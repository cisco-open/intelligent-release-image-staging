# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""ImageService: the Images screen's application logic. Wraps catalog.CatalogStore
(listing) and publish.publish (torrent/seed/catalog) with a streamed, size-capped,
atomic upload and an in-memory background publish-job tracker. All side effects
(publish fn, tracker-url fn, clock) are injected so the logic is unit-testable
off-box. Stdlib only."""
import os
import re
import secrets
import tempfile
import threading
import time

import catalog as catalog_mod
import publish as publish_mod
from gui_onboard import _fmt_dur

# Catalog filenames are interpolated into IOS commands on the device (the copy
# applet), so the whole pipeline whitelists this charset. Match it here at the
# upload boundary too.
_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_IMAGE_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB hard cap on an uploaded image
_JOB_TTL = 3600  # seconds a terminal (done/error) job is retained before eviction


class ImageService:
    def __init__(self, state_dir, images_dir,
                 tracker_url_fn=publish_mod.default_tracker_url,
                 publish_fn=publish_mod.publish, now_fn=time.time,
                 seeder_remove_fn=publish_mod.remove_torrent_rpc,
                 audit_fn=None):
        self.state_dir = state_dir
        self.images_dir = images_dir
        self._tracker_url_fn = tracker_url_fn
        self._publish_fn = publish_fn
        self._now = now_fn
        self._seeder_remove = seeder_remove_fn
        self._audit = audit_fn
        self._jobs = {}
        self._lock = threading.Lock()
        os.makedirs(images_dir, exist_ok=True)

    def _store(self):
        return catalog_mod.CatalogStore(self.state_dir)

    def list_images(self):
        return self._store().list_images()

    def get_image(self, image_id):
        """Catalog entry for *image_id* (or None) — CatalogStore passthrough."""
        return self._store().get_image(image_id)

    def delete_image(self, image_id, live_device_ids=None):
        """Full delete of a published image. If any device is assigned it, returns
        the sorted list of those device ids and deletes NOTHING (caller -> 409).
        Otherwise removes the catalog entry, the image file, the .torrent, and
        best-effort stops the seeder, returning []. Raises KeyError if unknown.

        When *live_device_ids* is given, the assigned check is intersected with it,
        so a stale policy for a device that has since been removed from the fleet no
        longer blocks deletion (the caller passes the live fleet inventory, matching
        the Overview's live-fleet rollout view). Passing None checks every policy.

        Only GUI-uploaded images live under images_dir and have their file removed
        here; a CLI-published .bin (seeded in place from a read-only mount such as
        /opt/images) is intentionally left on disk -- the catalog entry, .torrent
        and seeding are still removed. The assigned check and the catalog removal
        are not one atomic transaction: a delete racing a concurrent assign of the
        same image can leave a device pointing at a removed image, but that is
        bounded by the stage-only invariant (the agent finds no image and never
        stages) and is acceptable under the single-admin model."""
        store = self._store()
        entry = store.get_image(image_id)
        if entry is None:
            raise KeyError(image_id)
        pol = store.list_policies()
        assigned = sorted(
            did for did, p in pol.items()
            if p.get("approved_image_id") == image_id
            and (live_device_ids is None or did in live_device_ids))
        if assigned:
            return assigned
        store.delete_image(image_id)
        fn = entry.get("filename")
        if fn:
            try:
                os.remove(self.image_path(fn))
            except OSError:
                pass
        try:
            os.remove(store.torrent_path(image_id))
        except OSError:
            pass
        try:
            self._seeder_remove(entry.get("info_hash_hex"))
        except Exception:   # seeder unreachable is non-fatal
            pass
        return []

    def valid_filename(self, name):
        return bool(name) and name not in (".", "..") \
            and _FILENAME_RE.match(name) is not None

    def image_path(self, filename):
        return os.path.join(self.images_dir, filename)

    def save_stream(self, filename, reader, max_bytes=_MAX_IMAGE_BYTES, expected=None):
        """Stream chunks from *reader* (a zero-arg callable returning bytes, b''
        at EOF) into images_dir under a unique temp file, enforcing *max_bytes*,
        then atomically rename to image_path(filename). Returns the final path.
        If *expected* is given, the stream must deliver exactly that many bytes
        (a short read means a truncated/aborted upload). Raises ValueError on a
        bad filename, oversize, or incomplete upload (leaving no final file)."""
        if not self.valid_filename(filename):
            raise ValueError("bad filename")
        os.makedirs(self.images_dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.images_dir, prefix=".upload-",
                                   suffix=".tmp")
        total = 0
        try:
            with os.fdopen(fd, "wb") as f:
                while True:
                    chunk = reader()
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("image too large")
                    f.write(chunk)
            if expected is not None and total != expected:
                raise ValueError(
                    "incomplete upload: got %d of %d bytes" % (total, expected))
            final = self.image_path(filename)
            os.replace(tmp, final)
            return final
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def start_publish(self, image_path):
        """Create a publish job and run publish() on a daemon thread. Returns the
        job id immediately; poll get_job() for progress. A missing tracker URL or
        any publish error transitions the job to state 'error' with a message.
        Jobs are in-memory and per-process: a server restart loses all job state,
        and an in-flight publish is abandoned (not resumed). Terminal jobs are
        evicted after _JOB_TTL."""
        job_id = secrets.token_hex(8)
        job = {
            "id": job_id,
            "filename": os.path.basename(image_path),
            "state": "publishing",
            "message": "",
            "image_id": None,
            "started_at": int(self._now()),
            "finished_at": None,
        }
        with self._lock:
            self._evict_old(self._now())
            self._jobs[job_id] = job

        def run():
            try:
                tracker_url = self._tracker_url_fn()
                if not tracker_url:
                    raise RuntimeError(
                        "cannot determine tracker URL (is IRIS_HOST_IP set?)")
                entry = self._publish_fn(image_path, self._store(), tracker_url)
                self._finish(job_id, "done", image_id=entry.get("id"))
            except Exception as exc:  # publish is best-effort; report, don't crash
                self._finish(job_id, "error", message=str(exc))

        threading.Thread(target=run, daemon=True).start()
        return job_id

    def _finish(self, job_id, state, image_id=None, message=""):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job["state"] = state
            job["image_id"] = image_id
            job["message"] = message
            job["finished_at"] = int(self._now())
            filename = job["filename"]
            duration = job["finished_at"] - job["started_at"]
        # Publish runs async: without this emission a failed publish would
        # leave NO audit trace after the upload event. Best-effort, outside
        # the lock.
        if self._audit is not None:
            try:
                self._audit(event="image_publish_finished", category="image",
                           action="publish", actor="system", target=filename,
                           result="ok" if state == "done" else "fail",
                           detail=("published id %s in %s"
                                   % (image_id, _fmt_dur(duration)))
                                  if state == "done" else
                                  ("publish failed after %s: %s"
                                   % (_fmt_dur(duration), (message or "?")[:120])))
            except Exception:
                pass

    def get_job(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def _evict_old(self, now):
        """Drop terminal (done/error) jobs finished more than _JOB_TTL ago.
        Caller must hold self._lock."""
        cutoff = int(now) - _JOB_TTL
        stale = [jid for jid, v in self._jobs.items()
                 if v["state"] in ("done", "error")
                 and v.get("finished_at") is not None
                 and v["finished_at"] <= cutoff]
        for jid in stale:
            del self._jobs[jid]

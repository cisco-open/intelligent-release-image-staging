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
# Where an image may already be sitting when the operator asks to import it:
# the uploads volume (orphaned whenever the catalog in iris-state is reset while
# the payload in iris-images survives) and the read-only IRIS_IMAGE_ROOT bind,
# which exists so operators can stage images on the host. Publishing is in
# place, so the read-only root stays read-only.
_IMPORT_ROOT_ENV = "IMAGES_ROOT"
_DEFAULT_IMPORT_ROOT = "/opt/images"


class ImageService:
    def __init__(self, state_dir, images_dir,
                 tracker_url_fn=publish_mod.default_tracker_url,
                 publish_fn=publish_mod.publish, now_fn=time.time,
                 seeder_remove_fn=publish_mod.remove_torrent_rpc,
                 audit_fn=None, import_root=None):
        self.state_dir = state_dir
        self.images_dir = images_dir
        self.import_root = import_root if import_root is not None else \
            os.environ.get(_IMPORT_ROOT_ENV, _DEFAULT_IMPORT_ROOT)
        self._tracker_url_fn = tracker_url_fn
        self._publish_fn = publish_fn
        self._now = now_fn
        self._seeder_remove = seeder_remove_fn
        self._audit = audit_fn
        self._jobs = {}
        # image_ids with an async publish still running: the catalog entry does
        # not exist until the job finishes, so this is the only thing that makes
        # a concurrent import of the same image visible to discovery.
        self._publishing = set()
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

        Only images that actually live under images_dir have their file removed
        here; one published in place (seeded from a read-only mount such as
        /opt/images, by import or by iris-publish) is intentionally left on disk
        -- the catalog entry, .torrent and seeding are still removed. Which case
        an entry is in comes from its recorded source_dir, NOT from its filename:
        the uploads volume and the import root can hold the same basename, and
        inferring location from the name would delete the wrong file. Entries
        published before source_dir was recorded keep the legacy behaviour of
        removing images_dir/<filename>. The assigned check and the catalog removal
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
        if fn and self._file_is_ours(entry):
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

    def _file_is_ours(self, entry):
        """True when *entry*'s image file lives in the uploads volume, so
        deleting the entry should unlink it. An entry with a source_dir pointing
        anywhere else was published in place and its file belongs to the
        operator. A legacy entry with no source_dir predates that bookkeeping,
        so it keeps the original assume-it-is-ours behaviour."""
        src = entry.get("source_dir")
        if not src:
            return True
        return os.path.realpath(src) == os.path.realpath(self.images_dir)

    def valid_filename(self, name):
        return bool(name) and name not in (".", "..") \
            and _FILENAME_RE.match(name) is not None

    def _scan_roots(self):
        """Every on-disk file that structurally looks like an importable image,
        before identity filtering. A file qualifies if it is a .bin whose
        basename passes the same charset gate as an upload (catalog filenames
        reach IOS commands on the device), is not a sidecar/temp/dotfile, and
        whose resolved path is still inside the root it was found under -- so a
        symlink cannot pull a file from outside the mount into the set."""
        found = []
        # The two roots may be the SAME directory (the Kubernetes configmap
        # points IRIS_IMAGES_DIR and IMAGES_ROOT at /data/images), or the import
        # root may sit INSIDE the volume. Either way a second walk re-yields the
        # same files, every file collides with itself, and the ambiguity rule
        # would refuse the whole set. Walk each distinct tree once.
        seen_paths = set()
        walked = []
        for label, root in (("volume", self.images_dir),
                            ("import", self.import_root)):
            if not root or not os.path.isdir(root):
                continue
            root_real = os.path.realpath(root)
            if any(root_real == done or root_real.startswith(done + os.sep)
                   for done in walked):
                continue
            walked.append(root_real)
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                for name in filenames:
                    if not name.endswith(".bin") or name.startswith("."):
                        continue
                    if not self.valid_filename(name):
                        continue
                    path = os.path.join(dirpath, name)
                    real = os.path.realpath(path)
                    if real != root_real and not real.startswith(root_real + os.sep):
                        continue
                    if real in seen_paths:   # reached twice via nested roots
                        continue
                    seen_paths.add(real)
                    try:
                        stat = os.stat(path)
                    except OSError:   # vanished or unreadable — not importable
                        continue
                    found.append({"path": path, "filename": name,
                                  "size": stat.st_size, "root": label,
                                  "mtime": int(stat.st_mtime),
                                  "image_id": publish_mod.derive_id(name),
                                  "readable": os.access(path, os.R_OK)})
        found.sort(key=lambda c: (c["filename"], c["path"]))
        return found

    def _partition_candidates(self):
        """Split the scan into (importable, skipped-with-reason).

        Two things make a structurally-valid file unsafe to import, and both are
        about IDENTITY rather than the file itself:

        * Already published. The catalog is keyed on publish.derive_id(), which
          strips ".SPA.bin" OR ".bin", so foo.bin and foo.SPA.bin are ONE entry.
          Matching on basename alone would miss that and let an import overwrite
          a live entry's hashes and info_hash while every device policy still
          names the same approved_image_id -- the devices would then stage a
          different release than the operator approved. An in-flight publish
          counts as published: the entry only appears when the async job ends.
        * Ambiguous. reseed_input resolves a catalogued torrent back to a
          directory by BASENAME across both roots, first root wins, and the
          seeder runs with bt-seed-unverified. So if one basename (or one
          derived id) exists in more than one place, a restart can re-seed the
          wrong bytes under the right piece hashes. Refuse rather than guess."""
        found = self._scan_roots()
        taken = {entry.get("id") for entry in self.list_images()}
        taken |= {entry.get("filename") for entry in self.list_images()}
        with self._lock:
            in_flight = set(self._publishing)
        names = {}
        ids = {}
        for cand in found:
            names.setdefault(cand["filename"], []).append(cand)
            ids.setdefault(cand["image_id"], []).append(cand)
        importable, skipped = [], []
        for cand in found:
            if cand["image_id"] in taken or cand["filename"] in taken \
                    or cand["image_id"] in in_flight:
                reason = "already published"
            elif len(names[cand["filename"]]) > 1 or len(ids[cand["image_id"]]) > 1:
                reason = "ambiguous name in more than one location"
            elif not cand["readable"]:
                # Listing a file only needs its directory, so an unreadable image
                # would otherwise pass discovery and fail deep inside publish with
                # a bare PermissionError. Root-owned 0600 images left in a volume
                # by a pre-non-root container land here.
                reason = "not readable by the server"
            else:
                importable.append(cand)
                continue
            skipped.append(dict(cand, reason=reason))
        return importable, skipped

    def list_importable(self):
        """Image files on disk that are safe to publish into the catalog, across
        the uploads volume and the read-only import root. Pure read -- nothing is
        published or moved. Each entry is {path, filename, size, root
        ("volume"|"import"), mtime, image_id}, sorted by filename."""
        return self._partition_candidates()[0]

    def list_skipped(self):
        """On-disk images deliberately NOT offered for import, each with a
        reason. Surfaced in the Console so a file the operator expects to see
        does not just silently fail to appear."""
        return self._partition_candidates()[1]

    def is_importable_path(self, path):
        """True iff *path* is exactly one of the currently importable
        candidates. The import route authorizes on this identity check rather
        than a prefix test, so a traversal that merely starts inside a root
        ('<root>/../outside/secret.bin') is not importable."""
        return any(c["path"] == path for c in self.list_importable())

    def derived_id(self, path):
        """The catalog id publish() would assign to *path* — exposed so callers
        can reason about identity without importing the publish module."""
        return publish_mod.derive_id(path)

    def publish_in_flight(self, image_id):
        """True while an async publish for *image_id* has not finished. The
        catalog entry does not exist yet during that window, so this is what
        stops a second concurrent import of the same image."""
        with self._lock:
            return image_id in self._publishing

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
        pending_id = publish_mod.derive_id(job["filename"])
        with self._lock:
            self._evict_old(self._now())
            self._jobs[job_id] = job
            self._publishing.add(pending_id)

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
            finally:
                with self._lock:
                    self._publishing.discard(pending_id)

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

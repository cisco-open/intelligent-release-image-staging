# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pure telemetry-report logic for the IRIS device agent (issue #13).

Everything here is deterministic and side-effect free (single exception:
build_report reads the IRIS_RUNTIME_MODE env var, mirroring cli_ssh.select_cli's
runtime gate), so it is fully unit-testable off-box. All I/O — aria2 RPC
sampling, the report POST, syslog — lives in iris_agent._telemetry_tick and
CatalogClient. Stdlib only (no requests/psutil): the agent runs in Guest Shell
(C9300) and an IOx container (IE-3400) where only the standard library exists.

State layout (ADDITIVE ONLY — never bump iris_agent._STATE_SCHEMA for these
keys: a bump clears 'copied' flags and forces a fleet-wide ~1.2 GB re-copy):
  state['link'] = {'rtt_ms': [floats, <=RTT_KEEP], 'fail_streak': int}
  state[img_id]['tele'] = {'peers': {ip: times_observed}  (insertion order
      = observation order, capped at STATE_PEER_SET_CAP), 'started_ts',
      'done_ts', 'total_bytes', 'elapsed_s', 'avg_bps', 'sha_ok',
      'report_pending', 'report_attempts', 'report_next_ts',
      'report_sent_ts', 'event'}
('other' and 'last_sample_ts' are legacy byte-integration keys — new code
removes them on sight; see observe_peers.)
"""
import os
import re
import secrets

PEER_CAP = 64               # named peer rows per report (rest -> peers_total)
STATE_PEER_SET_CAP = 512    # distinct peer IPs tracked per image (size valve)
RTT_KEEP = 8                # HTTPS RTT samples kept for the median
GZIP_MIN = 1024             # gzip report bodies larger than this (bytes)
JITTER_MAX = 10.0           # max pre-POST sleep, seconds (desync report bursts)
RTT_CONSTRAINED_MS = 250    # median RTT above this -> 'constrained'
SLOW_BPS = 1048576          # last download avg under 1 MiB/s -> 'constrained'
FAIL_STREAK_BAD = 3         # consecutive catalog failures -> 'bad'
BACKOFF_CAP_TICKS = 16      # defer backoff cap: 1->2->4->8->16 ticks (~16 min)
MAX_ATTEMPTS = 60           # mark report_failed after this many deferred sends
TICK_SECONDS = 60           # the EEM agent tick period

# v2 telemetry (spec section 10). The v2 observation envelope + terminal report
# schema. sampling_class replaces the ambiguous v1 'tier'; obs_state replaces
# 'phase'. IDs are persisted random 128-bit values (32 lowercase hex).
OBS_STATES = ("observed", "not_due", "paused", "disabled",
              "not_active", "rpc_unavailable")
SAMPLING_CLASSES = ("good", "constrained")
LIVE_PEER_ROWS_MAX = 32     # peer_connections[] cap in a v2 observation envelope
_HEX32 = re.compile(r"^[a-f0-9]{32}$")
CONTENT_SHA256_STATES = ("verified", "mismatch", "not_checked")
IOS_COPY_VERIFY_STATES = ("ok", "failed", "not_run", "unsupported")


def content_sha256_state(state, img_id):
    """The persisted content-hash verify fact for a report (spec §3D), read
    VERBATIM from the decision point run_once recorded. Defaults to
    'not_checked' when no verify decision has been made — never inferred from
    done/copied or absence, and 'false' is never used to mean unchecked."""
    tele = (state.get(img_id) or {}).get("tele") or {}
    v = tele.get("content_sha256_state")
    return v if v in CONTENT_SHA256_STATES else "not_checked"


def ios_copy_verify_state(state, img_id):
    """The persisted IOS copy /verify fact for a report (spec §3D), read
    VERBATIM from the decision point. Defaults to 'not_run' when no copy /verify
    decision has been made. Independent of content_sha256_state."""
    tele = (state.get(img_id) or {}).get("tele") or {}
    v = tele.get("ios_copy_verify_state")
    return v if v in IOS_COPY_VERIFY_STATES else "not_run"


def mint_id():
    """A persisted random 128-bit identity as 32 lowercase hex chars
    (secrets.token_hex(16)) — for transfer_id and report_id. Random, not a
    short deterministic hash (which collides and leaks structure)."""
    return secrets.token_hex(16)


def _tele(state, img_id):
    return state.setdefault(img_id, {}).setdefault("tele", {})


def ensure_transfer_id(state, img_id):
    """Return this acquisition cycle's transfer_id, minting+persisting a random
    one on the first observation of an image with no stored transfer (spec §2).
    Stable across ticks for the same cycle. The image-change boundary is handled
    by clear_transfer() (called by run_once when the assigned image changes), so
    an A->B->A sequence mints three distinct ids. P1 boundaries (changed hash /
    local loss) intentionally reuse the existing id — dedupe/freshness still
    advance via report_id/sample_seq."""
    tele = _tele(state, img_id)
    tid = tele.get("transfer_id")
    if not tid:
        tid = mint_id()
        tele["transfer_id"] = tid
    return tid


def clear_transfer(state, img_id):
    """Drop the transfer identity + sequence for an image whose acquisition
    cycle has ended (the assigned image changed away from it), so the next
    acquisition of the same id mints a fresh transfer_id and restarts
    sample_seq. Leaves the rest of that image's state to run_once's own
    cleanup."""
    tele = (state.get(img_id) or {}).get("tele")
    if isinstance(tele, dict):
        tele.pop("transfer_id", None)
        tele.pop("sample_seq", None)


def next_sample_seq(state, img_id):
    """Increment and persist the monotonic per-transfer sample_seq, returning
    the new value (starting at 1). The CALLER checkpoints state before the
    heartbeat POST that carries the returned seq, so a crash-after-POST restart
    never re-uses or rewinds it (spec §2)."""
    tele = _tele(state, img_id)
    seq = int(tele.get("sample_seq", 0)) + 1
    tele["sample_seq"] = seq
    return seq


def build_observation(obs_state, observed_at, transfer_id, image_id,
                      sample_seq=None, aria_session_id=None,
                      sampling_class=None, stats=None, peers=None,
                      peer_rows_max=LIVE_PEER_ROWS_MAX):
    """Assemble the state-first v2 `telemetry_observation` envelope (spec
    §3A/10.1). Pure. `aria`, `peer_connections`, and `sampling_class` appear
    ONLY under obs_state=='observed'; a state-only envelope invents no transfer
    fields (no phase/tier/aria/peer rows). transfer_id/image_id are included
    only when present (absent for not_active).

    Raises ValueError on an unknown obs_state, or on an observed envelope
    missing sample_seq/sampling_class (a bad envelope is caught here rather than
    shipped)."""
    if obs_state not in OBS_STATES:
        raise ValueError("unknown obs_state: %r" % (obs_state,))
    env = {"v": 2, "obs_state": obs_state, "observed_at": float(observed_at)}
    if transfer_id is not None:
        env["transfer_id"] = transfer_id
    if image_id is not None:
        env["image_id"] = image_id
    if obs_state != "observed":
        return env
    if sample_seq is None or sampling_class not in SAMPLING_CLASSES:
        raise ValueError("observed envelope requires sample_seq + sampling_class")
    env["sample_seq"] = int(sample_seq)
    if aria_session_id:
        env["aria_session_id"] = aria_session_id
    env["sampling_class"] = sampling_class
    stats = stats or {}
    aria = {"receive_bps": int(stats.get("downloadSpeed", "0") or 0),
            "send_bps": int(stats.get("uploadSpeed", "0") or 0),
            "completed_content_bytes":
                int(stats.get("completedLength", "0") or 0),
            "total_content_bytes": int(stats.get("totalLength", "0") or 0),
            "connections": int(stats.get("connections", "0") or 0)}
    status = stats.get("status")
    if status:
        aria["status"] = status
    env["aria"] = aria
    rows = []
    for p in (peers or [])[:peer_rows_max]:
        ip = p.get("ip")
        if not ip:
            continue
        row = {"ip": ip, "send_bps": int(p.get("send_bps", 0) or 0),
               "receive_bps": int(p.get("receive_bps", 0) or 0)}
        rows.append(row)
    env["peer_connections"] = rows
    return env



def enabled(cfg):
    """Telemetry toggle: conf key `telemetry`, default on. Only an explicit
    off/0/false/no (case-insensitive, whitespace-stripped) disables — anything
    else, including garbage, stays on (spec: default on)."""
    v = str(cfg.get("telemetry", "on")).strip().lower()
    return v not in ("off", "0", "false", "no")


def _link(state):
    return state.setdefault("link", {})


def record_rtt(state, rtt_ms):
    """Append one HTTPS RTT sample (ms) to state['link']['rtt_ms'], keeping
    only the last RTT_KEEP (the classifier uses the median of these)."""
    rtts = _link(state).setdefault("rtt_ms", [])
    rtts.append(float(rtt_ms))
    del rtts[:-RTT_KEEP]


def record_failure(state):
    """One more consecutive HEARTBEAT-POST failure (drives the classifier's
    'bad' tier). Split from the report streak: a new agent talking to an old
    server heartbeats fine but its report POST 404s — those are distinct
    signals in the v2 report (heartbeat_fail_streak vs report_fail_streak)."""
    link = _link(state)
    link["fail_streak"] = int(link.get("fail_streak", 0)) + 1


def record_report_failure(state):
    """One more consecutive TELEMETRY-REPORT send failure (spec §10.2
    report_fail_streak), tracked independently of the heartbeat streak."""
    link = _link(state)
    link["report_fail_streak"] = int(link.get("report_fail_streak", 0)) + 1


def record_report_success(state):
    """A telemetry report was delivered — reset the report failure streak."""
    _link(state)["report_fail_streak"] = 0


def record_success(state):
    """A catalog POST succeeded — reset the failure streak."""
    _link(state)["fail_streak"] = 0


def _median(vals):
    if not vals:
        return 0.0
    s = sorted(vals)
    n = len(s)
    if n % 2:
        return float(s[n // 2])
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def classify(state, avg_bps):
    """Link tier, first match wins (spec section 1 table):
      bad         -> fail_streak >= FAIL_STREAK_BAD (defer with backoff)
      constrained -> median RTT > RTT_CONSTRAINED_MS, or the last download
                     averaged below SLOW_BPS (send trimmed payload)
      good        -> otherwise (send full report)
    avg_bps may be None/0 (no completed download yet) -> not constraining."""
    link = state.get("link") or {}
    if int(link.get("fail_streak", 0)) >= FAIL_STREAK_BAD:
        return "bad"
    if _median(link.get("rtt_ms") or []) > RTT_CONSTRAINED_MS:
        return "constrained"
    if avg_bps and avg_bps < SLOW_BPS:
        return "constrained"
    return "good"


def sampling_class_of(state, avg_bps):
    """Derived telemetry sampling class for the v2 envelope/report (spec §3D):
    'good' or 'constrained'. Maps the internal classify() tier ('bad' collapses
    to 'constrained' — an observed envelope is only emitted on good/constrained
    cadence anyway, never on 'bad'). Explicitly NOT a measured link quality."""
    return "good" if classify(state, avg_bps) == "good" else "constrained"


def observe_peers(tele, peers, now=None):
    """Record one aria2 getPeers sample as participation observation, in
    place. Per-peer BYTE counts are deliberately not tracked: aria2 1.37
    exposes only instantaneous per-peer speeds, and integrating those over
    the sparse one-shot tick cadence fabricates data (the even-split
    fallback fired on every multi-peer lab transfer — see CHANGELOG). What
    IS measured: which peer IPs were connected at the sample instants, in
    observation order, with a per-ip sample count for dedup. New IPs beyond
    STATE_PEER_SET_CAP are dropped (size valve; peers_total saturates).

    When `now` is provided, ALSO maintains the v2 rich form `tele['peers_v2']`
    = {ip: {first_observed, last_observed, observations}} in parallel with the
    legacy v1 `tele['peers']` = {ip: count}, so the v2 terminal report can
    surface first/last/count while the cap/set/truncate/saturate semantics stay
    identical (STATE_PEER_SET_CAP-bounded distinct IPs)."""
    tele.pop("other", None)             # legacy keys from the
    tele.pop("last_sample_ts", None)    # byte-integration era
    rows = tele.setdefault("peers", {})
    if rows and isinstance(next(iter(rows.values())), list):
        # legacy {ip: [rx, tx]} state persisted across the upgrade: the
        # accumulators are fabricated-by-integration — discard, never migrate
        rows = tele["peers"] = {}
    v2 = tele.setdefault("peers_v2", {}) if now is not None else None
    for p in peers:
        ip = p.get("ip")
        if not ip:
            continue
        if ip in rows:
            rows[ip] += 1
        elif len(rows) < STATE_PEER_SET_CAP:
            rows[ip] = 1
        if v2 is not None:
            if ip in v2:
                v2[ip]["last_observed"] = float(now)
                v2[ip]["observations"] += 1
            elif len(v2) < STATE_PEER_SET_CAP:
                v2[ip] = {"first_observed": float(now),
                          "last_observed": float(now), "observations": 1}


def build_report(cfg, state, img_id, event, now):
    """Assemble the report body (exact shape: spec section 2). Pure read of
    cfg/state — the caller (iris_agent._telemetry_tick) owns sampling, jitter
    and the POST. event: 'staging-complete' | 'seeding-only' | 'pull'.
    peers/peers_total are participation-only (see observe_peers); rows
    beyond PEER_CAP are counted in peers_total but not named."""
    st = state.get(img_id) or {}
    tele = st.get("tele") or {}
    link = state.get("link") or {}
    rtts = link.get("rtt_ms") or []
    avg_bps = int(tele.get("avg_bps", 0) or 0)
    if st.get("copied"):
        stage_state = "ready"
    elif st.get("blocked_no_space"):
        stage_state = "flash_full_seeding_only"
    else:
        stage_state = "staging"
    # Participation only: per-peer BYTES are not measured (aria2 exposes
    # only instantaneous rates), so rows carry just the observed peer IPs in
    # observation order. peers_total = distinct IPs observed (saturates at
    # STATE_PEER_SET_CAP); rows beyond PEER_CAP are counted, not named.
    # Keys-only read: also safe on legacy {ip: [rx, tx]} state (pull-before-
    # first-observe), where values are ignored anyway.
    observed = tele.get("peers") or {}
    peer_rows = [{"ip": ip} for ip in list(observed)[:PEER_CAP]]
    runtime_mode = (os.environ.get("IRIS_RUNTIME_MODE")
                    or cfg.get("runtime_mode") or "guestshell")
    return {
        "ts": int(now),
        "image_id": img_id,
        "event": event,
        "transfer": {"total_bytes": int(tele.get("total_bytes", 0) or 0),
                     "elapsed_s": round(float(tele.get("elapsed_s", 0) or 0), 1),
                     "avg_bps": avg_bps,
                     "sha_ok": bool(tele.get("sha_ok", False)),
                     "stage_state": stage_state},
        "link": {"tier": classify(state, avg_bps),
                 "rtt_ms_median": int(round(_median(rtts))),
                 "rtt_samples": len(rtts),
                 "hb_failures": int(link.get("fail_streak", 0)),
                 "trimmed": False},
        "peers": peer_rows,
        "peers_total": len(observed),
        "agent": {"version": cfg.get("agent_version", "unknown"),
                  "runtime_mode": runtime_mode},
    }


def _report_peer_rows_v2(tele):
    """(peer_rows, peers_total, truncated, saturated) for the v2 report from the
    rich `peers_v2` state. Rows carry participation only — ip + first/last
    observed times + observation count, NEVER bytes. Rows beyond PEER_CAP (64)
    are counted in peers_total but not named (truncated); peers_total saturates
    at STATE_PEER_SET_CAP (512)."""
    observed = tele.get("peers_v2") or {}
    total = len(observed)
    rows = []
    for ip in list(observed)[:PEER_CAP]:
        rec = observed[ip]
        rows.append({"ip": ip,
                     "first_observed": rec.get("first_observed"),
                     "last_observed": rec.get("last_observed"),
                     "observations": int(rec.get("observations", 0) or 0)})
    return rows, total, total > PEER_CAP, total >= STATE_PEER_SET_CAP


def build_report_v2(cfg, state, img_id, event, now, transfer_id, report_id,
                    report_request_id=None, window_start=None,
                    window_complete=True):
    """Assemble the EXACT v2 terminal report body (spec §10.2). Pure read of
    cfg/state. IDs are supplied by the caller (frozen once, retried verbatim).
    Verification is TWO independent persisted facts read verbatim
    (content_sha256_state / ios_copy_verify_state); avg_bps / sha_ok / the
    generic 'tier' are retired. Peers carry first/last/count participation only.
    `report_request_id` is set only for pull reports (null otherwise)."""
    st = state.get(img_id) or {}
    tele = st.get("tele") or {}
    link = state.get("link") or {}
    rtts = link.get("rtt_ms") or []
    if st.get("copied"):
        stage_state = "ready"
    elif st.get("blocked_no_space"):
        stage_state = "flash_full_seeding_only"
    else:
        stage_state = "staging"
    peer_rows, peers_total, truncated, saturated = _report_peer_rows_v2(tele)
    runtime_mode = (os.environ.get("IRIS_RUNTIME_MODE")
                    or cfg.get("runtime_mode") or "guestshell")
    completed = int(tele.get("completed_content_bytes",
                             tele.get("total_bytes", 0)) or 0)
    total = int(tele.get("total_content_bytes",
                         tele.get("total_bytes", 0)) or 0)
    sha_state = content_sha256_state(state, img_id)
    content_sha256 = {"state": sha_state}
    if sha_state in ("verified", "mismatch"):
        content_sha256["algo"] = "sha256"
    end = float(tele.get("done_ts", now) or now)
    start = window_start
    if start is None:
        start = float(tele.get("started_ts", end) or end)
    return {
        "v": 2,
        "report_id": report_id,
        "transfer_id": transfer_id,
        "report_request_id": report_request_id,
        "report_created_at": float(now),
        "image_id": img_id,
        "event": event,
        "window": {"start": start, "end": end,
                   "complete": bool(window_complete)},
        "content": {"completed_content_bytes": completed,
                    "total_content_bytes": total},
        "content_sha256": content_sha256,
        "ios_copy_verify": {"state": ios_copy_verify_state(state, img_id)},
        "sampling": {
            "sampling_class": sampling_class_of(state, tele.get("avg_bps")),
            "catalog_rtt_ms_median": int(round(_median(rtts))),
            "catalog_rtt_samples": len(rtts),
            "heartbeat_fail_streak": int(link.get("fail_streak", 0) or 0),
            "report_fail_streak": int(link.get("report_fail_streak", 0) or 0)},
        "stage_state": stage_state,
        "peers": peer_rows,
        "peers_total": peers_total,
        "peers_truncated": truncated,
        "peers_saturated": saturated,
        "agent": {"version": cfg.get("agent_version", "unknown"),
                  "runtime_mode": runtime_mode},
    }


def freeze_report(state, img_id, report):
    """Freeze a completion/seeding v2 report payload in state (per transfer) so
    every retry re-sends it byte-identical (spec §2). The CALLER checkpoints
    state BEFORE the first POST. Returns the frozen dict (the stored object)."""
    tele = _tele(state, img_id)
    tele["frozen_report"] = report
    return report


def frozen_report(state, img_id):
    """The frozen completion/seeding report, or None."""
    return ((state.get(img_id) or {}).get("tele") or {}).get("frozen_report")


def freeze_pull_report(state, request_id, report):
    """Freeze a pull report keyed by the server's request_id (spec §10.2b), so
    a repeated pull with the SAME request_id reuses the identical frozen body,
    while a NEW request_id gets a fresh report. Bounded to the most recent
    pull (the server clears a request on ingest)."""
    state["frozen_pull"] = {"request_id": request_id, "report": report}
    return report


def frozen_pull_report(state, request_id):
    """The frozen pull report for request_id, or None if the stored pull is for
    a different (or absent) request."""
    fp = state.get("frozen_pull")
    if isinstance(fp, dict) and fp.get("request_id") == request_id:
        return fp.get("report")
    return None


def pull_request_id(resp):
    """The server's pull report_request_id from a heartbeat response (spec
    §10.2b), or None. 32-hex only; tolerates captive-portal garbage."""
    if isinstance(resp, dict):
        rid = resp.get("report_request_id")
        if isinstance(rid, str) and _HEX32.match(rid):
            return rid
    return None


def trim_report(report):
    """Constrained-tier copy: per-peer rows dropped, link marked trimmed.
    Returns a NEW dict (fresh 'link' too) — the original stays intact so a
    later pull can still send the full detail from state."""
    out = dict(report)
    out["peers"] = []
    out["link"] = dict(report.get("link") or {})
    out["link"]["trimmed"] = True
    return out


def pull_requested(resp):
    """True ONLY for a dict heartbeat response carrying report_requested: true.
    Tolerates None (send failed), strings, lists and other captive-portal
    garbage — a malformed response must never look like a pull directive."""
    return isinstance(resp, dict) and resp.get("report_requested") is True


def next_backoff_ts(attempts, now):
    """Next allowed send time for the 'bad' tier: exponential backoff in agent
    ticks (1 -> 2 -> 4 -> 8 -> 16, capped at ~16 min). `attempts` is the count
    of sends already tried (0 -> one tick out)."""
    return now + TICK_SECONDS * min(2 ** attempts, BACKOFF_CAP_TICKS)


# --- live streaming samples (device transfer telemetry spec, section 5) ----
STREAM_TIER_TICKS = {"good": 1, "constrained": 4}   # 'bad' streams nothing
STREAM_EVERY_MIN = 1
STREAM_EVERY_MAX = 60
STREAM_DIRECTIVE_FRESH_TICKS = 3    # expire without heartbeat renewal
SAMPLE_V = 1


def stream_enabled(cfg):
    """Streaming opt-in: conf key `telemetry_stream`, default OFF. Fail-closed
    (deliberately the inverse polarity of enabled()): ONLY an explicit
    on/1/true/yes enables — anything else, including garbage, stays off.
    Streaming also requires the master `telemetry` toggle."""
    if not enabled(cfg):
        return False
    v = cfg.get("telemetry_stream", "off")
    if not isinstance(v, str):
        return False        # conf values are strings; any other type is garbage
    return v.strip().lower() in ("on", "1", "true", "yes")


def parse_stream_directives(resp):
    """(stream_every, stream_pause) from a heartbeat response, with the
    pull_requested() paranoia: resp must be a dict, stream_every a real int
    (bool excluded) inside [STREAM_EVERY_MIN, STREAM_EVERY_MAX], stream_pause
    literally True — anything else yields the defaults (1, False)."""
    every, pause = 1, False
    if isinstance(resp, dict):
        raw = resp.get("stream_every")
        if isinstance(raw, int) and not isinstance(raw, bool) \
                and STREAM_EVERY_MIN <= raw <= STREAM_EVERY_MAX:
            every = raw
        if resp.get("stream_pause") is True:
            pause = True
    return every, pause


def store_directives(state, resp, now):
    """Overwrite state['stream_directives'] from THIS response — no merge:
    absent or malformed keys overwrite with the defaults, so captive-portal
    garbage can never accumulate into policy. resp None (failed heartbeat)
    leaves the stored entry untouched to age out via the freshness rule."""
    if resp is None:
        return
    every, pause = parse_stream_directives(resp)
    state["stream_directives"] = {"every": every, "pause": pause,
                                  "received_ts": float(now)}


def active_directives(state, now):
    """Directives currently in force: the stored entry while fresh. Every
    successful heartbeat renews it (the catalog echoes unconditionally), so
    freshness lapses only when heartbeats stop or an old server stops
    echoing — then the device reverts to defaults within 3 ticks (the
    anti-wedge rule, spec section 5.4)."""
    d = state.get("stream_directives")
    if isinstance(d, dict):
        try:
            age = now - float(d.get("received_ts", 0))
        except (TypeError, ValueError):
            age = -1.0
        if 0 <= age <= STREAM_DIRECTIVE_FRESH_TICKS * TICK_SECONDS:
            every = d.get("every")
            if not (isinstance(every, int) and not isinstance(every, bool)
                    and STREAM_EVERY_MIN <= every <= STREAM_EVERY_MAX):
                every = 1
            return every, d.get("pause") is True
    return 1, False


def should_sample(state, tele, tier, now):
    """Cadence gate: one sample per effective interval (spec section 5.3),
    hard-capped at one per tick by the caller's tick cycle. Half-a-tick slop
    absorbs EEM timer drift (a 59.5 s gap still counts as the next tick)."""
    if tier not in STREAM_TIER_TICKS:
        return False
    every, pause = active_directives(state, now)
    if pause:
        return False
    interval_ticks = max(STREAM_TIER_TICKS[tier], every)
    last = float(tele.get("stream_last_ts", 0) or 0)
    return (now - last) >= (interval_ticks - 0.5) * TICK_SECONDS


def build_sample(img_id, phase, stats, tier):
    """The v1 wire sample (spec section 5.1) or None when nothing should be
    sent. stats is the aria2 tellStatus subset (string values, exactly what
    _aria_stats_impl already fetches). run_once phase 'seeding-only' maps to
    wire 'seeding' (the server checks enums exactly). A seeder with zero
    connections streams nothing."""
    if phase not in ("downloading", "seeding-only") or not stats:
        return None
    if tier not in STREAM_TIER_TICKS:
        return None
    conns = int(stats.get("connections", "0") or 0)
    wire = "downloading" if phase == "downloading" else "seeding"
    if wire == "seeding" and conns <= 0:
        return None
    return {"v": SAMPLE_V, "image_id": img_id, "phase": wire,
            "done_bytes": int(stats.get("completedLength", "0") or 0),
            "down_bps": int(stats.get("downloadSpeed", "0") or 0),
            "up_bps": int(stats.get("uploadSpeed", "0") or 0),
            "peers": conns, "tier": tier}

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
  state[img_id]['tele'] = {'peers': {ip: [rx, tx]}, 'other': [rx, tx, count],
      'last_sample_ts', 'started_ts', 'done_ts', 'total_bytes', 'elapsed_s',
      'avg_bps', 'sha_ok', 'report_pending', 'report_attempts',
      'report_next_ts', 'report_sent_ts', 'event'}
"""
import os

PEER_CAP = 20               # top-N peer rows kept per image (rest -> 'other')
RTT_KEEP = 8                # HTTPS RTT samples kept for the median
GZIP_MIN = 1024             # gzip report bodies larger than this (bytes)
JITTER_MAX = 10.0           # max pre-POST sleep, seconds (desync report bursts)
RTT_CONSTRAINED_MS = 250    # median RTT above this -> 'constrained'
SLOW_BPS = 1048576          # last download avg under 1 MiB/s -> 'constrained'
FAIL_STREAK_BAD = 3         # consecutive catalog failures -> 'bad'
BACKOFF_CAP_TICKS = 16      # defer backoff cap: 1->2->4->8->16 ticks (~16 min)
MAX_ATTEMPTS = 60           # mark report_failed after this many deferred sends
ELAPSED_CLAMP = 180.0       # bound rate-integration error when ticks stall (s)
TICK_SECONDS = 60           # the EEM agent tick period


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
    """One more consecutive catalog-POST failure (heartbeat or report)."""
    link = _link(state)
    link["fail_streak"] = int(link.get("fail_streak", 0)) + 1


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


def heal_post_completion_contamination(tele):
    """One-shot repair of state poisoned by the pre-2026.07.04.7 pull bug.

    The old agent sampled on steady-state pulls and rate-integrated one
    instantaneous speed over the ELAPSED_CLAMP window, mutating a FINISHED
    transfer's table — fabricating multi-GB tx rows for neighbors it happened
    to be seeding (hardware-observed: ~12 GB on a 1.26 GB image) and injecting
    them as zero-rx peer rows. That state persists across agent upgrades, so
    the fixed agent would faithfully re-report the old poison forever.

    Detection is exact for the signature: a staging-complete transfer whose
    last_sample_ts postdates done_ts (the fixed agent never samples a
    completed download again; seeding-only transfers legitimately do keep
    sampling and are left alone). Repair: drop the fabricated zero-rx/
    nonzero-tx rows and clamp last_sample_ts back to done_ts. Idempotent —
    after healing the signature no longer matches. Returns True iff healed."""
    if tele.get("event") != "staging-complete":
        return False
    done = tele.get("done_ts")
    if not done or tele.get("last_sample_ts", 0) <= done + 2 * TICK_SECONDS:
        return False
    rows = tele.get("peers") or {}
    for ip in [ip for ip, (rx, tx) in rows.items() if rx == 0 and tx > 0]:
        del rows[ip]
    tele["last_sample_ts"] = done
    return True


def integrate_peers(tele, peers, now):
    """Integrate one aria2 getPeers sample into tele['peers'] in place.

    aria2 1.37.0 exposes only instantaneous per-peer speeds (every value a
    string), so bytes are approximated as rate x elapsed-since-last-sample,
    clamped at ELAPSED_CLAMP so a stalled tick can't inflate totals. The first
    sample has no baseline -> elapsed 0 (rows appear with zero bytes). Rows
    beyond PEER_CAP (ranked by rx+tx) collapse into tele['other'] =
    [rx, tx, count]; a peer that re-enters and is evicted again is re-counted,
    so 'other' is approximate by design (the UI shows '~')."""
    elapsed = min(now - tele.get("last_sample_ts", now), ELAPSED_CLAMP)
    tele["last_sample_ts"] = now
    rows = tele.setdefault("peers", {})
    for p in peers:
        ip = p.get("ip")
        if not ip:
            continue
        cur = rows.setdefault(ip, [0, 0])
        cur[0] = int(cur[0] + int(p.get("downloadSpeed", "0") or 0) * elapsed)
        cur[1] = int(cur[1] + int(p.get("uploadSpeed", "0") or 0) * elapsed)
    if len(rows) > PEER_CAP:
        ranked = sorted(rows.items(),
                        key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0]))
        other = tele.setdefault("other", [0, 0, 0])
        for ip, (rx, tx) in ranked[PEER_CAP:]:
            other[0] += rx
            other[1] += tx
            other[2] += 1
            del rows[ip]


def _attribute_rx(weighted, total, elapsed):
    """Attribute the accurate *total* received bytes across peer rows and
    derive each row's average receive throughput.

    weighted is an ordered list of (ip, rx_weight, tx_raw, is_real); the order
    is the report's display order (already sorted, with the 'other' pseudo-row
    last). Returns the final peer rows: {ip, rx_bytes, tx_bytes, avg_bps}.

      - sum_w > 0: rx_bytes = round(rx_weight / sum_w * total); the rounding
        remainder (total - sum of rounded, may be negative) lands on the
        largest-weight row so the per-peer rx sums to total exactly.
      - sum_w == 0 (no per-peer sample ever landed — the fast-download case):
        split total evenly across the REAL peer rows (never 'other'); one real
        row gets the whole total. With no real rows, nothing is attributed.

    avg_bps = round(rx_bytes / max(elapsed, 1)). tx_raw passes through as
    tx_bytes untouched (upload accrued while seeding is not rescaled)."""
    denom = max(elapsed, 1.0)
    sum_w = sum(w for _, w, _, _ in weighted)
    if sum_w == 0 and total > 0:
        # No per-peer sample ever landed (fast download). Split evenly across
        # the REAL peer rows only; drop a lone zero-weight 'other' (no real
        # peer to attribute to -> peers stays empty per the spec).
        weighted = [row for row in weighted if row[3]]
    n = len(weighted)
    rx_out = [0] * n
    if total > 0 and n:
        if sum_w > 0:
            rx_out = [int(round(w / sum_w * total)) for _, w, _, _ in weighted]
            remainder = total - sum(rx_out)
            if remainder:
                # largest by rx weight, ties -> earliest (stable display order)
                big = max(range(n), key=lambda k: (weighted[k][1], -k))
                rx_out[big] += remainder
        else:
            base, extra = divmod(total, n)
            rx_out = [base + (1 if j < extra else 0) for j in range(n)]
    rows = []
    for (ip, _w, tx, _real), rx in zip(weighted, rx_out):
        rows.append({"ip": ip, "rx_bytes": rx, "tx_bytes": int(tx),
                     "avg_bps": int(round(rx / denom))})
    return rows


def build_report(cfg, state, img_id, event, now):
    """Assemble the report body (exact shape: spec section 2). Pure read of
    cfg/state — the caller (iris_agent._telemetry_tick) owns sampling, jitter
    and the POST. event: 'staging-complete' | 'seeding-only' | 'pull'.
    When tele['other'] holds evicted peers, one 'other(N)' pseudo-row is
    appended after the top rows (the report schema has no separate slot)."""
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
    total = int(tele.get("total_bytes", 0) or 0)
    elapsed = float(tele.get("elapsed_s", 0) or 0)
    # Raw rate-integration only approximates per-peer bytes (the first sample
    # integrates over elapsed 0, and a fast <2-min download yields too few
    # samples); transfer.total_bytes is accurate. So carry each row's rx weight
    # and RESCALE below so the per-peer rx sums to the accurate total exactly.
    # Rows are (ip, rx_weight, tx_raw, is_real): tx is never rescaled (it's the
    # upload accumulated while seeding); 'other' is not a real peer row so a
    # zero-weight even split skips it.
    weighted = [(ip, rx, tx, True)
                for ip, (rx, tx) in sorted(
                    (tele.get("peers") or {}).items(),
                    key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0]))]
    other = tele.get("other") or [0, 0, 0]
    if other[2]:
        weighted.append(("other(%d)" % other[2], other[0], other[1], False))
    peer_rows = _attribute_rx(weighted, total, elapsed)
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
        "agent": {"version": cfg.get("agent_version", "unknown"),
                  "runtime_mode": runtime_mode},
    }


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

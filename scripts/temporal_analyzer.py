#!/usr/bin/env python3
"""
temporal_analyzer.py — Claris AI V5.0
Session-level temporal attack pattern analyzer.

Tracks patterns ACROSS a session to detect slow-burn context poisoning,
escalating attacks, coordinated campaigns, and multi-turn manipulation.

State file: /root/.openclaw/workspace/skills/claris-ai/data/sessions.json
"""

import json
import os
import sys
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
SKILL_DIR = Path(__file__).resolve().parent.parent
DATA_DIR  = SKILL_DIR / "data"
SESSIONS_FILE = DATA_DIR / "sessions.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Verdict weights ──────────────────────────────────────────────────────────
VERDICT_WEIGHT = {
    "CLEAN": 0.0,
    "WARN":  0.3,
    "FLAG":  0.6,
    "BLOCK": 1.0,
}

# ── Temporal pattern thresholds ──────────────────────────────────────────────
ESCALATION_WINDOW     = 6   # messages to look back for escalation
PERSISTENCE_THRESHOLD = 3   # same category N times = persistence alert
CONTEXT_DRIFT_CLEAN   = 3   # min CLEANs before drift check
TRUST_BUILD_JUMP      = 0.6 # risk score jump that triggers trust-build alert
SLOW_BURN_WARN_COUNT  = 5   # N WARNs without BLOCK = slow-burn
COORDINATED_MIN_SESSIONS = 3  # min sessions to flag coordinated attack


# ════════════════════════════════════════════════════════════════════════════
#  I/O helpers
# ════════════════════════════════════════════════════════════════════════════

def _load_sessions() -> dict:
    if SESSIONS_FILE.exists():
        try:
            with open(SESSIONS_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _save_sessions(data: dict) -> None:
    with open(SESSIONS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_to_dt(iso: str) -> datetime:
    """Parse ISO timestamp, handling both Z and +00:00 suffixes."""
    iso = iso.replace("Z", "+00:00")
    return datetime.fromisoformat(iso)


# ════════════════════════════════════════════════════════════════════════════
#  Session management
# ════════════════════════════════════════════════════════════════════════════

def start_session(session_id: str, source: str = "unknown") -> dict:
    """
    Create or reset a session entry.
    Returns the session dict.
    """
    sessions = _load_sessions()
    if session_id in sessions:
        return sessions[session_id]

    entry = {
        "session_id":      session_id,
        "source":          source,
        "created":         _now_iso(),
        "last_seen":       _now_iso(),
        "message_count":   0,
        "verdicts":        [],
        "pattern_sequence":[],
        "risk_trajectory": [],
        "alerts":          [],
        "temporal_risk":   0.0,
    }
    sessions[session_id] = entry
    _save_sessions(sessions)
    return entry


# ════════════════════════════════════════════════════════════════════════════
#  Temporal pattern detectors
# ════════════════════════════════════════════════════════════════════════════

def _check_escalation(session: dict) -> dict | None:
    """ESCALATION: gradual ramp from CLEAN to BLOCK over last N messages."""
    verdicts = session["verdicts"]
    trajectory = session["risk_trajectory"]
    if len(verdicts) < 4:
        return None

    window = verdicts[-ESCALATION_WINDOW:]
    risk_window = trajectory[-ESCALATION_WINDOW:]

    # Need at least one CLEAN start and a high-risk end
    if window[0] != "CLEAN":
        return None
    if risk_window[-1] < 0.55:
        return None

    # Check monotonic-ish increase
    increases = sum(1 for i in range(1, len(risk_window)) if risk_window[i] >= risk_window[i-1])
    if increases >= len(risk_window) - 2:
        # Escalation confirmed
        return {
            "type":     "ESCALATION",
            "severity": "HIGH",
            "message":  f"Gradual risk escalation detected over {len(window)} messages "
                        f"({window[0]} → {window[-1]}). Risk: {risk_window[0]:.2f} → {risk_window[-1]:.2f}.",
            "fired_at": _now_iso(),
        }
    return None


def _check_persistence(session: dict) -> dict | None:
    """PERSISTENCE: same attack category hammered 3+ times."""
    categories = session["pattern_sequence"]
    if not categories:
        return None

    # Count occurrences of each category (non-empty)
    from collections import Counter
    cat_counts = Counter(c for seq in categories for c in seq if c)
    if not cat_counts:
        return None

    worst = cat_counts.most_common(1)[0]
    cat_name, count = worst
    if count >= PERSISTENCE_THRESHOLD:
        return {
            "type":     "PERSISTENCE",
            "severity": "HIGH",
            "message":  f"Attack category '{cat_name}' seen {count} times — persistent vector.",
            "category": cat_name,
            "count":    count,
            "fired_at": _now_iso(),
        }
    return None


def _check_context_drift(session: dict, last_text: str = "") -> dict | None:
    """CONTEXT_DRIFT: early CLEANs set context, later message exploits it."""
    verdicts = session["verdicts"]
    if len(verdicts) < CONTEXT_DRIFT_CLEAN + 1:
        return None

    # Count leading CLEANs
    leading_cleans = 0
    for v in verdicts:
        if v == "CLEAN":
            leading_cleans += 1
        else:
            break

    if leading_cleans < CONTEXT_DRIFT_CLEAN:
        return None

    # Look for drift markers in the last message
    drift_markers = [
        "as we discussed", "as you said", "as mentioned", "you agreed",
        "you told me", "per our conversation", "like you established",
        "following your instructions", "as per your earlier",
        "based on what you said", "continuing from before",
        "building on our context", "remember you said",
    ]
    text_lower = last_text.lower()
    matched = [m for m in drift_markers if m in text_lower]

    # Also check if current verdict is non-CLEAN
    current_verdict = verdicts[-1] if verdicts else "CLEAN"
    if matched and current_verdict in ("WARN", "FLAG", "BLOCK"):
        return {
            "type":     "CONTEXT_DRIFT",
            "severity": "HIGH",
            "message":  f"Context drift attack: {leading_cleans} CLEAN messages used to establish "
                        f"false context, then exploitation with drift marker: '{matched[0]}'.",
            "markers":  matched,
            "fired_at": _now_iso(),
        }
    return None


def _check_trust_building(session: dict) -> dict | None:
    """TRUST_BUILDING: many CLEANs → sudden risk spike > TRUST_BUILD_JUMP."""
    trajectory = session["risk_trajectory"]
    verdicts = session["verdicts"]
    if len(trajectory) < 3:
        return None

    # Need several low-risk messages followed by a sudden jump
    prev = trajectory[:-1]
    current = trajectory[-1]
    avg_prev = sum(prev) / len(prev) if prev else 0.0

    jump = current - avg_prev
    clean_count = sum(1 for v in verdicts[:-1] if v == "CLEAN")

    if jump >= TRUST_BUILD_JUMP and clean_count >= 3:
        return {
            "type":     "TRUST_BUILDING",
            "severity": "HIGH",
            "message":  f"Trust-building attack: {clean_count} CLEAN messages (avg risk {avg_prev:.2f}) "
                        f"then sudden jump to {current:.2f} (+{jump:.2f}).",
            "jump":     round(jump, 3),
            "fired_at": _now_iso(),
        }
    return None


def _check_slow_burn(session: dict) -> dict | None:
    """SLOW_BURN: 5+ WARNs accumulating without triggering a BLOCK."""
    verdicts = session["verdicts"]
    warn_count = verdicts.count("WARN")
    block_count = verdicts.count("BLOCK")

    if warn_count >= SLOW_BURN_WARN_COUNT and block_count == 0:
        return {
            "type":     "SLOW_BURN",
            "severity": "MEDIUM",
            "message":  f"Slow-burn attack: {warn_count} WARN verdicts accumulating without "
                        f"crossing BLOCK threshold. May be probing defenses.",
            "warn_count": warn_count,
            "fired_at": _now_iso(),
        }
    return None


def _check_distributed(sessions: dict, current_session_id: str, window_minutes: int = 60) -> dict | None:
    """DISTRIBUTED_INJECT: same categories across ≥3 different sessions recently."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    # Gather recent sessions (excluding current)
    recent = {}
    for sid, sdata in sessions.items():
        if sid == current_session_id:
            continue
        try:
            last_seen = _iso_to_dt(sdata.get("last_seen", "1970-01-01T00:00:00+00:00"))
        except ValueError:
            continue
        if last_seen >= cutoff:
            recent[sid] = sdata

    if len(recent) < COORDINATED_MIN_SESSIONS - 1:
        return None

    current = sessions.get(current_session_id, {})
    current_cats = set(c for seq in current.get("pattern_sequence", []) for c in seq if c)
    if not current_cats:
        return None

    matching_sessions = []
    for sid, sdata in recent.items():
        other_cats = set(c for seq in sdata.get("pattern_sequence", []) for c in seq if c)
        overlap = current_cats & other_cats
        if len(overlap) >= 1:
            matching_sessions.append({"session_id": sid, "shared_categories": list(overlap)})

    if len(matching_sessions) >= COORDINATED_MIN_SESSIONS - 1:
        all_shared = set()
        for m in matching_sessions:
            all_shared.update(m["shared_categories"])
        return {
            "type":     "DISTRIBUTED_INJECT",
            "severity": "CRITICAL",
            "message":  f"Coordinated attack fingerprint: same categories {sorted(all_shared)} "
                        f"seen across {len(matching_sessions)+1} sessions in {window_minutes}min window.",
            "sessions": [current_session_id] + [m["session_id"] for m in matching_sessions],
            "shared_categories": sorted(all_shared),
            "fired_at": _now_iso(),
        }
    return None


# ════════════════════════════════════════════════════════════════════════════
#  Core: record_message
# ════════════════════════════════════════════════════════════════════════════

def record_message(
    session_id: str,
    verdict: str,
    score: float,
    categories: list[str],
    message_text: str = "",
) -> dict:
    """
    Record a message verdict in the session and run all temporal checks.

    Returns:
        {session_id, temporal_risk, alerts, recommendation}
    """
    verdict = verdict.upper()
    if verdict not in VERDICT_WEIGHT:
        verdict = "WARN"
    score = float(max(0.0, min(1.0, score)))

    sessions = _load_sessions()

    # Auto-create session if missing
    if session_id not in sessions:
        start_session(session_id, source="auto")
        sessions = _load_sessions()

    session = sessions[session_id]
    session["last_seen"]       = _now_iso()
    session["message_count"]  += 1
    session["verdicts"].append(verdict)
    session["pattern_sequence"].append(categories)
    session["risk_trajectory"].append(score)

    # Run all temporal checks
    new_alerts = []

    alert = _check_escalation(session)
    if alert:
        new_alerts.append(alert)

    alert = _check_persistence(session)
    if alert:
        new_alerts.append(alert)

    alert = _check_context_drift(session, last_text=message_text)
    if alert:
        new_alerts.append(alert)

    alert = _check_trust_building(session)
    if alert:
        new_alerts.append(alert)

    alert = _check_slow_burn(session)
    if alert:
        new_alerts.append(alert)

    alert = _check_distributed(sessions, session_id)
    if alert:
        new_alerts.append(alert)

    # Deduplicate: don't re-fire same alert type if it already fired recently
    existing_types = {a["type"] for a in session["alerts"]}
    for alert in new_alerts:
        if alert["type"] not in existing_types:
            session["alerts"].append(alert)

    # Compute temporal_risk = max(base score, escalated risk from alerts)
    temporal_risk = _compute_temporal_risk(session)
    session["temporal_risk"] = temporal_risk

    sessions[session_id] = session
    _save_sessions(sessions)

    # Recommendation
    recommendation = _make_recommendation(temporal_risk, new_alerts)

    return {
        "session_id":    session_id,
        "temporal_risk": round(temporal_risk, 3),
        "alerts":        new_alerts,
        "recommendation": recommendation,
        "message_count": session["message_count"],
    }


def _compute_temporal_risk(session: dict) -> float:
    """Compute an aggregate temporal risk score for the session."""
    trajectory = session["risk_trajectory"]
    alerts = session["alerts"]

    if not trajectory:
        return 0.0

    # Base: weighted average (recent messages weight more)
    n = len(trajectory)
    weights = [1.0 + (i / n) for i in range(n)]
    weighted_sum = sum(r * w for r, w in zip(trajectory, weights))
    base_risk = weighted_sum / sum(weights)

    # Boost for alert severity
    severity_boost = {"CRITICAL": 0.3, "HIGH": 0.2, "MEDIUM": 0.1, "LOW": 0.05}
    alert_boost = sum(severity_boost.get(a.get("severity","LOW"), 0.0) for a in alerts)

    return min(1.0, base_risk + alert_boost)


def _make_recommendation(temporal_risk: float, new_alerts: list) -> str:
    alert_types = [a["type"] for a in new_alerts]
    if temporal_risk >= 0.8 or "DISTRIBUTED_INJECT" in alert_types:
        return "TERMINATE_SESSION — high temporal risk, possible coordinated attack"
    if temporal_risk >= 0.6 or any(a in alert_types for a in ("ESCALATION", "TRUST_BUILDING", "CONTEXT_DRIFT")):
        return "ESCALATE_REVIEW — suspicious temporal pattern, flag for human review"
    if temporal_risk >= 0.4 or "SLOW_BURN" in alert_types:
        return "MONITOR_CLOSELY — accumulating risk signals, increase scrutiny"
    if temporal_risk >= 0.2:
        return "WATCH — low-level signals, continue monitoring"
    return "PROCEED — no significant temporal threat detected"


# ════════════════════════════════════════════════════════════════════════════
#  Query helpers
# ════════════════════════════════════════════════════════════════════════════

def get_session_report(session_id: str) -> dict:
    """Full analysis report for a session."""
    sessions = _load_sessions()
    session = sessions.get(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found"}

    trajectory = session["risk_trajectory"]
    verdicts   = session["verdicts"]

    report = {
        "session_id":     session_id,
        "source":         session.get("source", "unknown"),
        "created":        session.get("created"),
        "last_seen":      session.get("last_seen"),
        "message_count":  session.get("message_count", 0),
        "temporal_risk":  round(session.get("temporal_risk", 0.0), 3),
        "verdict_summary": {
            "CLEAN": verdicts.count("CLEAN"),
            "WARN":  verdicts.count("WARN"),
            "FLAG":  verdicts.count("FLAG"),
            "BLOCK": verdicts.count("BLOCK"),
        },
        "risk_trajectory":  trajectory,
        "peak_risk":         round(max(trajectory), 3) if trajectory else 0.0,
        "avg_risk":          round(sum(trajectory) / len(trajectory), 3) if trajectory else 0.0,
        "alerts_fired":      session.get("alerts", []),
        "alert_count":       len(session.get("alerts", [])),
        "recommendation":    _make_recommendation(session.get("temporal_risk", 0.0), []),
    }
    return report


def detect_coordinated_attack(window_minutes: int = 60) -> list:
    """
    Scan all sessions for coordinated attack campaigns.
    Returns list of campaign dicts with involved sessions + shared categories.
    """
    sessions = _load_sessions()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    # Filter to recent active sessions
    recent = {}
    for sid, sdata in sessions.items():
        try:
            last_seen = _iso_to_dt(sdata.get("last_seen", "1970-01-01T00:00:00+00:00"))
        except ValueError:
            continue
        if last_seen >= cutoff:
            recent[sid] = sdata

    if len(recent) < COORDINATED_MIN_SESSIONS:
        return []

    # Build category fingerprints
    fingerprints = {}
    for sid, sdata in recent.items():
        cats = set(c for seq in sdata.get("pattern_sequence", []) for c in seq if c)
        if cats:
            fingerprints[sid] = cats

    # Cluster by shared categories
    campaigns = []
    processed = set()

    for sid, cats in fingerprints.items():
        if sid in processed:
            continue
        cluster = [sid]
        for other_sid, other_cats in fingerprints.items():
            if other_sid == sid or other_sid in processed:
                continue
            if cats & other_cats:
                cluster.append(other_sid)

        if len(cluster) >= COORDINATED_MIN_SESSIONS:
            shared = cats.copy()
            for s in cluster[1:]:
                shared &= fingerprints.get(s, set())
            campaigns.append({
                "type":              "COORDINATED_CAMPAIGN",
                "severity":          "CRITICAL",
                "sessions_involved": cluster,
                "session_count":     len(cluster),
                "shared_categories": sorted(shared),
                "window_minutes":    window_minutes,
                "detected_at":       _now_iso(),
            })
            processed.update(cluster)

    return campaigns


def prune_old_sessions(max_age_hours: int = 24) -> int:
    """Remove sessions older than max_age_hours. Returns count pruned."""
    sessions = _load_sessions()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    to_delete = []

    for sid, sdata in sessions.items():
        try:
            last_seen = _iso_to_dt(sdata.get("last_seen", "1970-01-01T00:00:00+00:00"))
        except ValueError:
            to_delete.append(sid)
            continue
        if last_seen < cutoff:
            to_delete.append(sid)

    for sid in to_delete:
        del sessions[sid]

    _save_sessions(sessions)
    return len(to_delete)


def get_high_risk_sessions(threshold: float = 0.7) -> list:
    """Return sessions with temporal_risk above threshold."""
    sessions = _load_sessions()
    results = []
    for sid, sdata in sessions.items():
        risk = sdata.get("temporal_risk", 0.0)
        if risk >= threshold:
            results.append({
                "session_id":    sid,
                "temporal_risk": round(risk, 3),
                "message_count": sdata.get("message_count", 0),
                "alerts":        len(sdata.get("alerts", [])),
                "last_seen":     sdata.get("last_seen"),
            })
    results.sort(key=lambda x: x["temporal_risk"], reverse=True)
    return results


def list_all_sessions() -> list:
    """List summary of all active sessions."""
    sessions = _load_sessions()
    result = []
    for sid, sdata in sessions.items():
        trajectory = sdata.get("risk_trajectory", [])
        result.append({
            "session_id":    sid,
            "source":        sdata.get("source", "unknown"),
            "message_count": sdata.get("message_count", 0),
            "temporal_risk": round(sdata.get("temporal_risk", 0.0), 3),
            "alert_count":   len(sdata.get("alerts", [])),
            "last_seen":     sdata.get("last_seen"),
            "verdicts":      sdata.get("verdicts", []),
        })
    result.sort(key=lambda x: x["temporal_risk"], reverse=True)
    return result


# ════════════════════════════════════════════════════════════════════════════
#  Display helpers
# ════════════════════════════════════════════════════════════════════════════

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[33m",
    "MEDIUM":   "\033[36m",
    "LOW":      "\033[37m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def _color(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def _print_session_summary(s: dict) -> None:
    risk = s["temporal_risk"]
    color = "\033[91m" if risk >= 0.7 else "\033[33m" if risk >= 0.4 else "\033[32m"
    print(f"  {BOLD}{s['session_id']}{RESET}  risk={_color(f'{risk:.2f}', color)} "
          f"msgs={s['message_count']} alerts={s.get('alert_count',0)} "
          f"src={s.get('source','?')} last={s.get('last_seen','?')[:19]}")


def _print_report(report: dict) -> None:
    r = report
    print(f"\n{'='*60}")
    print(f"{BOLD}Session Report: {r['session_id']}{RESET}")
    print(f"{'='*60}")
    print(f"  Source:      {r.get('source','?')}")
    print(f"  Created:     {r.get('created','?')[:19]}")
    print(f"  Last seen:   {r.get('last_seen','?')[:19]}")
    print(f"  Messages:    {r['message_count']}")

    risk = r['temporal_risk']
    color = "\033[91m" if risk >= 0.7 else "\033[33m" if risk >= 0.4 else "\033[32m"
    print(f"  Temporal risk: {_color(f'{risk:.3f}', color)}")
    print(f"  Peak risk:   {r['peak_risk']:.3f}  Avg: {r['avg_risk']:.3f}")

    vs = r['verdict_summary']
    print(f"  Verdicts:    CLEAN={vs['CLEAN']} WARN={vs['WARN']} FLAG={vs['FLAG']} BLOCK={vs['BLOCK']}")
    print(f"  Trajectory:  {r['risk_trajectory']}")
    print(f"\n  Recommendation: {BOLD}{r['recommendation']}{RESET}")

    alerts = r.get("alerts_fired", [])
    if alerts:
        print(f"\n  Alerts fired ({len(alerts)}):")
        for a in alerts:
            sc = SEVERITY_COLOR.get(a.get("severity","LOW"), "")
            print(f"    [{_color(a.get('severity','?'), sc)}] {a['type']}: {a['message'][:100]}")
    else:
        print("\n  No temporal alerts fired.")
    print()


# ════════════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Claris AI V5.0 — Temporal Attack Pattern Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 temporal_analyzer.py --sessions
  python3 temporal_analyzer.py --session sess_abc123
  python3 temporal_analyzer.py --record sess_abc123 WARN 0.45 "INJECTION,ROLEPLAY"
  python3 temporal_analyzer.py --coordinated
  python3 temporal_analyzer.py --high-risk
  python3 temporal_analyzer.py --prune
  python3 temporal_analyzer.py --sessions --json
""")

    parser.add_argument("--sessions",     action="store_true", help="List all active sessions")
    parser.add_argument("--session",      metavar="ID",        help="Full report for session ID")
    parser.add_argument("--coordinated",  action="store_true", help="Detect coordinated attacks")
    parser.add_argument("--high-risk",    action="store_true", help="Show high-risk sessions (>0.7)")
    parser.add_argument("--prune",        action="store_true", help="Prune sessions older than 24h")
    parser.add_argument("--json",         action="store_true", help="Output as JSON")
    parser.add_argument("--record",       nargs=4,
                        metavar=("SESSION_ID","VERDICT","SCORE","CATEGORIES_CSV"),
                        help="Record a message verdict into a session")
    parser.add_argument("--window",       type=int, default=60, help="Window minutes for coordinated check")
    parser.add_argument("--threshold",    type=float, default=0.7, help="Risk threshold for --high-risk")
    parser.add_argument("--start",        nargs=2,
                        metavar=("SESSION_ID","SOURCE"),
                        help="Start a new session")
    args = parser.parse_args()

    # ── Start session ────────────────────────────────────────────────────────
    if args.start:
        sid, source = args.start
        entry = start_session(sid, source)
        if args.json:
            print(json.dumps(entry, indent=2))
        else:
            print(f"Session started: {sid} (source={source})")
        return

    # ── Record message ───────────────────────────────────────────────────────
    if args.record:
        sid, verdict, score_str, cats_csv = args.record
        categories = [c.strip() for c in cats_csv.split(",") if c.strip()]
        result = record_message(sid, verdict, float(score_str), categories)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            risk = result["temporal_risk"]
            color = "\033[91m" if risk >= 0.7 else "\033[33m" if risk >= 0.4 else "\033[32m"
            print(f"Recorded | session={sid} | temporal_risk={_color(f'{risk:.3f}', color)} "
                  f"| {result['recommendation']}")
            for a in result.get("alerts", []):
                sc = SEVERITY_COLOR.get(a.get("severity","LOW"), "")
                print(f"  ⚠  [{_color(a['severity'], sc)}] {a['type']}: {a['message'][:80]}")
        return

    # ── Sessions list ────────────────────────────────────────────────────────
    if args.sessions:
        sessions = list_all_sessions()
        if args.json:
            print(json.dumps(sessions, indent=2))
        else:
            if not sessions:
                print("No active sessions.")
            else:
                print(f"\n{BOLD}Active Sessions ({len(sessions)}){RESET}")
                for s in sessions:
                    _print_session_summary(s)
        return

    # ── Single session report ────────────────────────────────────────────────
    if args.session:
        report = get_session_report(args.session)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            if "error" in report:
                print(f"Error: {report['error']}")
            else:
                _print_report(report)
        return

    # ── Coordinated attack detection ─────────────────────────────────────────
    if args.coordinated:
        campaigns = detect_coordinated_attack(window_minutes=args.window)
        if args.json:
            print(json.dumps(campaigns, indent=2))
        else:
            if not campaigns:
                print(f"No coordinated campaigns detected in last {args.window} min.")
            else:
                print(f"\n{BOLD}⚠  COORDINATED CAMPAIGNS DETECTED ({len(campaigns)}){RESET}")
                for c in campaigns:
                    print(f"\n  Sessions: {c['sessions_involved']}")
                    print(f"  Shared categories: {c['shared_categories']}")
                    print(f"  Detected: {c['detected_at'][:19]}")
        return

    # ── High-risk sessions ───────────────────────────────────────────────────
    if args.high_risk:
        risky = get_high_risk_sessions(threshold=args.threshold)
        if args.json:
            print(json.dumps(risky, indent=2))
        else:
            if not risky:
                print(f"No sessions above risk threshold {args.threshold}.")
            else:
                print(f"\n{BOLD}High-Risk Sessions (>{args.threshold}){RESET}")
                for s in risky:
                    _print_session_summary(s)
        return

    # ── Prune ────────────────────────────────────────────────────────────────
    if args.prune:
        count = prune_old_sessions()
        if args.json:
            print(json.dumps({"pruned": count}))
        else:
            print(f"Pruned {count} stale session(s) (>24h).")
        return

    parser.print_help()


if __name__ == "__main__":
    main()

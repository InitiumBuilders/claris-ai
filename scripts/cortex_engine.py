#!/usr/bin/env python3
"""
cortex_engine.py — Claris AI V4.0 Learning Cortex
Tracks pattern effectiveness, evolves weights, detects trends, reports coverage gaps.
State: /root/.openclaw/workspace/skills/claris-ai/data/cortex_state.json
"""

import json
import os
import sys
import argparse
from datetime import datetime, timezone, timedelta
from collections import defaultdict

# ── Paths ─────────────────────────────────────────────────────────────────────
SKILL_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR    = os.path.join(SKILL_DIR, "data")
STATE_FILE  = os.path.join(DATA_DIR, "cortex_state.json")

# ── Default state factory ──────────────────────────────────────────────────────
DEFAULT_PATTERN_STATS = {
    # Layer 1 — Override / Instruction Injection
    "OVERRIDE_IGNORE":         {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":1},
    "OVERRIDE_FORGET":         {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":1},
    "OVERRIDE_DISREGARD":      {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":1},
    "OVERRIDE_NEW_INSTRUCTION":{"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":1},
    "OVERRIDE_SYSTEM_PROMPT":  {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":1},
    # Layer 2 — Role Confusion / Persona Hijack
    "ROLE_YOU_ARE_NOW":        {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":2},
    "ROLE_ACT_AS":             {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":2},
    "ROLE_PRETEND":            {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":2},
    "ROLE_SIMULATE":           {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":2},
    "ROLE_JAILBREAK_DAN":      {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.90,"last_seen":None,"trend_score":0.0,"trending":False,"layer":2},
    "ROLE_DEV_MODE":           {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.90,"last_seen":None,"trend_score":0.0,"trending":False,"layer":2},
    "ROLE_GOD_MODE":           {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.90,"last_seen":None,"trend_score":0.0,"trending":False,"layer":2},
    "ROLE_TRUE_SELF":          {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.85,"last_seen":None,"trend_score":0.0,"trending":False,"layer":2},
    # Layer 3 — Web3 / Wallet Threats
    "WEB3_WALLET_DRAINER":     {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.2,"confidence":0.92,"last_seen":None,"trend_score":0.0,"trending":False,"layer":3},
    "WEB3_ADDRESS_REPLACE":    {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.2,"confidence":0.90,"last_seen":None,"trend_score":0.0,"trending":False,"layer":3},
    "WEB3_NFT_PHISH":          {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.1,"confidence":0.88,"last_seen":None,"trend_score":0.0,"trending":False,"layer":3},
    "WEB3_SEED_PHRASE":        {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.5,"confidence":0.95,"last_seen":None,"trend_score":0.0,"trending":False,"layer":3},
    "WEB3_PRIVATE_KEY":        {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.5,"confidence":0.95,"last_seen":None,"trend_score":0.0,"trending":False,"layer":3},
    "WEB3_FAKE_AIRDROP":       {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.1,"confidence":0.87,"last_seen":None,"trend_score":0.0,"trending":False,"layer":3},
    "WEB3_APPROVAL_SCAM":      {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.2,"confidence":0.89,"last_seen":None,"trend_score":0.0,"trending":False,"layer":3},
    # Layer 4 — Encoding / Obfuscation
    "ENCODE_BASE64":           {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.80,"last_seen":None,"trend_score":0.0,"trending":False,"layer":4},
    "ENCODE_HEX":              {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.80,"last_seen":None,"trend_score":0.0,"trending":False,"layer":4},
    "ENCODE_HOMOGLYPH":        {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.82,"last_seen":None,"trend_score":0.0,"trending":False,"layer":4},
    "ENCODE_LEETSPEAK":        {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":0.9,"confidence":0.78,"last_seen":None,"trend_score":0.0,"trending":False,"layer":4},
    "ENCODE_ZERO_WIDTH":       {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.1,"confidence":0.88,"last_seen":None,"trend_score":0.0,"trending":False,"layer":4},
    # Layer 5 — Social Engineering
    "SOCIAL_AUTHORITY":        {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.83,"last_seen":None,"trend_score":0.0,"trending":False,"layer":5},
    "SOCIAL_URGENCY":          {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":0.9,"confidence":0.80,"last_seen":None,"trend_score":0.0,"trending":False,"layer":5},
    "SOCIAL_FALSE_CONTEXT":    {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.82,"last_seen":None,"trend_score":0.0,"trending":False,"layer":5},
    "SOCIAL_IMPERSONATION":    {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.1,"confidence":0.86,"last_seen":None,"trend_score":0.0,"trending":False,"layer":5},
    "SOCIAL_GASLIGHTING":      {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.0,"confidence":0.82,"last_seen":None,"trend_score":0.0,"trending":False,"layer":5},
    # Layer 6 — Smart Contract / Code Threats
    "SC_REENTRANCY":           {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.3,"confidence":0.90,"last_seen":None,"trend_score":0.0,"trending":False,"layer":6},
    "SC_INTEGER_OVERFLOW":     {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.2,"confidence":0.88,"last_seen":None,"trend_score":0.0,"trending":False,"layer":6},
    "SC_SELF_DESTRUCT":        {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.4,"confidence":0.92,"last_seen":None,"trend_score":0.0,"trending":False,"layer":6},
    "SC_DELEGATE_CALL":        {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.3,"confidence":0.90,"last_seen":None,"trend_score":0.0,"trending":False,"layer":6},
    "SC_UNPROTECTED_INIT":     {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.2,"confidence":0.88,"last_seen":None,"trend_score":0.0,"trending":False,"layer":6},
    "SC_FLASH_LOAN_ATTACK":    {"hits":0,"confirmed_true_positives":0,"false_positives":0,"weight":1.3,"confidence":0.89,"last_seen":None,"trend_score":0.0,"trending":False,"layer":6},
}

def _default_state() -> dict:
    return {
        "version": "4.0",
        "total_scans": 0,
        "total_blocks": 0,
        "total_flags": 0,
        "total_warns": 0,
        "total_cleans": 0,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "pattern_stats": {k: dict(v) for k, v in DEFAULT_PATTERN_STATS.items()},
        "threat_history": [],
        "daily_stats": {},
        "signal_weights": {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3},
        "evolution_log": [],
        "coverage_gaps": [],
    }

# ── Core I/O ──────────────────────────────────────────────────────────────────
def load_state() -> dict:
    """Load cortex state from disk, creating defaults if missing."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(STATE_FILE):
        state = _default_state()
        save_state(state)
        return state
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
        # Merge any new default patterns not yet in state
        for k, v in DEFAULT_PATTERN_STATS.items():
            if k not in state["pattern_stats"]:
                state["pattern_stats"][k] = dict(v)
        # Ensure all required top-level keys exist
        for key, val in _default_state().items():
            if key not in state:
                state[key] = val
        return state
    except (json.JSONDecodeError, KeyError):
        return _default_state()


def save_state(state: dict) -> None:
    """Persist cortex state to disk."""
    os.makedirs(DATA_DIR, exist_ok=True)
    state["last_updated"] = datetime.now(timezone.utc).isoformat()
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


# ── Core Operations ───────────────────────────────────────────────────────────
def record_scan(verdict: str, score: float, categories: list, source: str = "unknown", layer_list: list = None) -> None:
    """Record a completed scan into cortex state."""
    state = load_state()
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    # Append to threat_history (cap at 500)
    entry = {
        "ts": now.isoformat(),
        "verdict": verdict,
        "score": score,
        "categories": categories,
        "source": source,
        "layer": layer_list or [],
    }
    state["threat_history"].append(entry)
    if len(state["threat_history"]) > 500:
        state["threat_history"] = state["threat_history"][-500:]

    # Update daily_stats
    if today not in state["daily_stats"]:
        state["daily_stats"][today] = {"BLOCK": 0, "FLAG": 0, "WARN": 0, "CLEAN": 0}
    v = verdict.upper()
    if v in state["daily_stats"][today]:
        state["daily_stats"][today][v] += 1

    # Update total counters
    state["total_scans"] += 1
    if v == "BLOCK":
        state["total_blocks"] += 1
    elif v == "FLAG":
        state["total_flags"] += 1
    elif v == "WARN":
        state["total_warns"] += 1
    elif v == "CLEAN":
        state["total_cleans"] += 1

    # Update pattern_stats.hits
    ts_str = now.isoformat()
    for cat in categories:
        if cat in state["pattern_stats"]:
            state["pattern_stats"][cat]["hits"] += 1
            state["pattern_stats"][cat]["last_seen"] = ts_str
            if v in ("BLOCK", "FLAG"):
                state["pattern_stats"][cat]["confirmed_true_positives"] += 1
        else:
            # Dynamic pattern
            state["pattern_stats"][cat] = {
                "hits": 1, "confirmed_true_positives": (1 if v in ("BLOCK","FLAG") else 0),
                "false_positives": 0, "weight": 1.0, "confidence": 0.80,
                "last_seen": ts_str, "trend_score": 0.0, "trending": False, "layer": 0
            }

    save_state(state)


def evolve_weights() -> list:
    """Run weight evolution cycle. Returns list of change dicts."""
    state = load_state()
    now = datetime.now(timezone.utc)
    changes = []

    for cat, stats in state["pattern_stats"].items():
        hits    = stats["hits"]
        fp      = stats["false_positives"]
        weight  = stats["weight"]
        old_w   = weight
        reason  = None

        # Check recent activity
        last_seen = None
        if stats.get("last_seen"):
            try:
                last_seen = datetime.fromisoformat(stats["last_seen"])
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
            except ValueError:
                last_seen = None

        days_since = (now - last_seen).days if last_seen else 999

        if hits > 0:
            fp_rate = fp / max(hits, 1)
            if fp_rate > 0.3:
                weight *= 0.9
                reason = f"fp_rate={fp_rate:.2f} > 0.3 → reduce"
            elif fp_rate < 0.05 and hits > 10:
                weight = min(weight * 1.05, 2.0)
                reason = f"fp_rate={fp_rate:.2f} < 0.05, hits={hits} > 10 → boost"

        # Trending boost
        if stats.get("trending"):
            weight = min(weight * 1.1, 2.0)
            reason = (reason or "") + " | trending → boost"

        # Cold decay (0 hits in 30 days)
        if days_since > 30 and hits == 0:
            weight *= 0.98
            reason = f"cold ({days_since}d no activity) → decay"

        weight = max(0.1, round(weight, 4))
        if abs(weight - old_w) > 0.0001:
            stats["weight"] = weight
            change = {
                "ts": now.isoformat(),
                "category": cat,
                "old_weight": round(old_w, 4),
                "new_weight": weight,
                "reason": reason or "no change",
            }
            changes.append(change)
            state["evolution_log"].append(change)
            if len(state["evolution_log"]) > 100:
                state["evolution_log"] = state["evolution_log"][-100:]

    # Recompute trending
    _update_trending(state, now)

    save_state(state)
    return changes


def _update_trending(state: dict, now: datetime) -> None:
    """Recompute trend_score and trending flag for all patterns."""
    cutoff = now - timedelta(days=7)
    cat_hits_7d: dict = defaultdict(int)

    for entry in state["threat_history"]:
        try:
            ts = datetime.fromisoformat(entry["ts"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, KeyError):
            continue
        if ts >= cutoff:
            for cat in entry.get("categories", []):
                cat_hits_7d[cat] += 1

    for cat, stats in state["pattern_stats"].items():
        h7 = cat_hits_7d.get(cat, 0)
        stats["trend_score"] = round(h7 / 7.0, 3)
        stats["trending"] = h7 >= 5


def mark_false_positive(category: str) -> None:
    """Mark a detection as false positive; re-evolve weights."""
    state = load_state()
    if category in state["pattern_stats"]:
        state["pattern_stats"][category]["false_positives"] += 1
        save_state(state)
        evolve_weights()
        print(f"[CORTEX] FP recorded for '{category}' — weights evolved.")
    else:
        print(f"[CORTEX] WARNING: category '{category}' not found in pattern_stats.")


def get_trending_threats(days: int = 7) -> list:
    """Return list of trending categories with hit counts + trend scores."""
    state = load_state()
    now   = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    cat_hits: dict = defaultdict(int)

    for entry in state["threat_history"]:
        try:
            ts = datetime.fromisoformat(entry["ts"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, KeyError):
            continue
        if ts >= cutoff:
            for cat in entry.get("categories", []):
                cat_hits[cat] += 1

    results = []
    for cat, hits in sorted(cat_hits.items(), key=lambda x: -x[1]):
        results.append({
            "category": cat,
            "hits": hits,
            "trend_score": round(hits / days, 3),
        })
    return results


def get_coverage_report() -> dict:
    """Return dict covering pattern stats, top categories, and daily volume."""
    state = load_state()
    now   = datetime.now(timezone.utc)
    stats = state["pattern_stats"]

    total_defined    = len(stats)
    never_fired      = [k for k, v in stats.items() if v["hits"] == 0]
    top5             = sorted(stats.items(), key=lambda x: -x[1]["hits"])[:5]
    top5_list        = [{"category": k, "hits": v["hits"], "weight": v["weight"]} for k, v in top5]

    # Threat distribution by verdict (from daily_stats)
    verdict_totals: dict = defaultdict(int)
    for day_data in state["daily_stats"].values():
        for v, n in day_data.items():
            verdict_totals[v] += n

    # Daily volume last 7 days
    daily_7d = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        ds  = state["daily_stats"].get(day, {"BLOCK":0,"FLAG":0,"WARN":0,"CLEAN":0})
        daily_7d.append({"date": day, **ds})

    # Coverage gaps: never fired or no hits in 30 days
    gaps = []
    for k, v in stats.items():
        last_seen = None
        if v.get("last_seen"):
            try:
                last_seen = datetime.fromisoformat(v["last_seen"])
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        if v["hits"] == 0 or (last_seen and (now - last_seen).days > 30):
            gaps.append(k)
    state["coverage_gaps"] = gaps
    save_state(state)

    return {
        "total_patterns_defined": total_defined,
        "patterns_never_fired": len(never_fired),
        "never_fired_list": never_fired,
        "top_5_categories": top5_list,
        "threat_distribution_by_verdict": dict(verdict_totals),
        "daily_volume_7d": daily_7d,
        "total_scans": state["total_scans"],
        "total_blocks": state["total_blocks"],
        "total_flags": state["total_flags"],
        "total_warns": state["total_warns"],
        "total_cleans": state["total_cleans"],
    }


def generate_cortex_brief() -> str:
    """Generate a short human-readable cortex status brief."""
    state  = load_state()
    report = get_coverage_report()
    now    = datetime.now(timezone.utc)
    today  = now.strftime("%Y-%m-%d")

    today_stats = state["daily_stats"].get(today, {"BLOCK":0,"FLAG":0,"WARN":0,"CLEAN":0})
    trending    = get_trending_threats(7)

    lines = [
        "╔══════════════════════════════════════════╗",
        "║      CLARIS V4.0 · CORTEX BRIEF          ║",
        "╚══════════════════════════════════════════╝",
        f"  Generated : {now.strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Total scans: {state['total_scans']:,}  |  Patterns: {report['total_patterns_defined']}",
        "",
        "  TODAY'S ACTIVITY:",
        f"    🔴 BLOCK : {today_stats.get('BLOCK',0)}",
        f"    🟡 FLAG  : {today_stats.get('FLAG',0)}",
        f"    🟠 WARN  : {today_stats.get('WARN',0)}",
        f"    🟢 CLEAN : {today_stats.get('CLEAN',0)}",
        "",
        "  TOP TRENDING (7d):",
    ]
    if trending:
        for t in trending[:5]:
            lines.append(f"    · {t['category']:<30} hits={t['hits']}  score={t['trend_score']}")
    else:
        lines.append("    · No trending threats detected.")

    lines += [
        "",
        f"  Coverage gaps: {report['patterns_never_fired']} patterns never fired",
        "  ~Claris · Semper Fortis · V4.0",
    ]
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Claris V4.0 Cortex Engine")
    parser.add_argument("--status",  action="store_true",  help="Print coverage report")
    parser.add_argument("--brief",   action="store_true",  help="Short cortex summary")
    parser.add_argument("--evolve",  action="store_true",  help="Run weight evolution cycle")
    parser.add_argument("--fp",      metavar="CATEGORY",   help="Mark false positive for category")
    parser.add_argument("--trending",action="store_true",  help="Show trending threats (7d)")
    parser.add_argument("--history", metavar="N", type=int,help="Show last N threat history entries")
    parser.add_argument("--json",         action="store_true",   help="Output as JSON")
    parser.add_argument("--record-scan",  metavar="JSON_PAYLOAD", help="Record a scan result (internal use by injection_guard)")

    args = parser.parse_args()

    if args.record_scan:
        try:
            payload = json.loads(args.record_scan)
            record_scan(
                verdict    = payload.get("verdict", "CLEAN"),
                score      = payload.get("score", 0),
                categories = payload.get("categories", []),
                source     = payload.get("source", "injection_guard"),
                layer_list = payload.get("layers", []),
            )
        except Exception:
            pass
        return

    if args.fp:
        mark_false_positive(args.fp)
        return

    if args.evolve:
        changes = evolve_weights()
        if args.json:
            print(json.dumps({"changes": changes}, indent=2))
        else:
            print(f"[CORTEX EVOLVE] {len(changes)} weight change(s):")
            for c in changes:
                print(f"  {c['category']:<32} {c['old_weight']} → {c['new_weight']}  ({c['reason']})")
            if not changes:
                print("  No changes — all weights stable.")
        return

    if args.trending:
        trends = get_trending_threats(7)
        if args.json:
            print(json.dumps({"trending": trends}, indent=2))
        else:
            print("[CORTEX TRENDING — Last 7 Days]")
            if trends:
                for t in trends:
                    bar = "█" * min(int(t["hits"]), 40)
                    print(f"  {t['category']:<32} {bar} {t['hits']}")
            else:
                print("  No trending threats.")
        return

    if args.history is not None:
        state = load_state()
        history = state["threat_history"][-args.history:]
        if args.json:
            print(json.dumps({"history": history}, indent=2))
        else:
            print(f"[CORTEX HISTORY — Last {args.history} entries]")
            for e in history:
                cats = ", ".join(e.get("categories", [])) or "—"
                print(f"  {e['ts'][:19]}  {e['verdict']:<6}  score={e['score']:.1f}  {cats}")
        return

    if args.brief:
        brief = generate_cortex_brief()
        if args.json:
            state = load_state()
            print(json.dumps({"brief": brief, "state_summary": {
                "total_scans": state["total_scans"],
                "total_blocks": state["total_blocks"],
            }}, indent=2))
        else:
            print(brief)
        return

    if args.status:
        report = get_coverage_report()
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("[CORTEX COVERAGE REPORT]")
            print(f"  Total patterns : {report['total_patterns_defined']}")
            print(f"  Never fired    : {report['patterns_never_fired']}")
            print(f"  Total scans    : {report['total_scans']:,}")
            print()
            print("  Verdict distribution:")
            for v, n in report["threat_distribution_by_verdict"].items():
                print(f"    {v:<8} {n}")
            print()
            print("  Top 5 categories:")
            for t in report["top_5_categories"]:
                print(f"    {t['category']:<32} hits={t['hits']}  weight={t['weight']}")
            print()
            print("  Daily volume (last 7 days):")
            for d in report["daily_volume_7d"]:
                total = d.get("BLOCK",0)+d.get("FLAG",0)+d.get("WARN",0)+d.get("CLEAN",0)
                print(f"    {d['date']}  total={total}  B={d.get('BLOCK',0)} F={d.get('FLAG',0)} W={d.get('WARN',0)} C={d.get('CLEAN',0)}")
        return

    # Default: show brief
    print(generate_cortex_brief())


if __name__ == "__main__":
    main()

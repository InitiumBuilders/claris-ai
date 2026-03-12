#!/usr/bin/env python3
"""
posture_engine.py — Claris AI V7.0 Posture Intelligence Engine
──────────────────────────────────────────────────────────────
Holistic security posture assessment across the 6 Core Words.
Not a single scan. Not a single tool. The whole organism — assessed.

"Posture is the system-level view of security.
 Not reacting to individual threats but building
 an organism that's resilient by design."
                           — Claris V6.0

Usage:
  python3 posture_engine.py --report
  python3 posture_engine.py --score --trust 0.8 --adversarial 0.6 --surface 0.7
  python3 posture_engine.py --history
  python3 posture_engine.py --delta
  python3 posture_engine.py --recommend
"""

import json
import os
import sys
import argparse
import time
from datetime import datetime, timezone
from typing import Optional

# ── Paths ────────────────────────────────────────────────────────────────────
_SELF_DIR    = os.path.dirname(os.path.abspath(__file__))
_SKILL_DIR   = os.path.dirname(_SELF_DIR)
_DATA_DIR    = os.path.join(_SKILL_DIR, "data")
_POSTURE_LOG = os.path.join(_DATA_DIR, "posture_log.jsonl")
_POSTURE_STATE = os.path.join(_DATA_DIR, "posture_state.json")

os.makedirs(_DATA_DIR, exist_ok=True)

# ── Posture Dimensions (the 6 Core Words) ────────────────────────────────────
DIMENSIONS = {
    "TRUST": {
        "weight": 0.25,
        "icon": "🟢",
        "description": "Identity, access control, zero-trust implementation",
        "indicators": {
            "mfa_enforced": {"label": "MFA enforced everywhere", "weight": 0.30},
            "least_privilege": {"label": "Least privilege principle applied", "weight": 0.25},
            "access_reviews": {"label": "Regular access reviews conducted", "weight": 0.20},
            "zero_trust_arch": {"label": "Zero Trust architecture in place", "weight": 0.15},
            "vendor_audit": {"label": "Third-party vendor access audited", "weight": 0.10},
        }
    },
    "ADVERSARIAL": {
        "weight": 0.20,
        "icon": "🔴",
        "description": "Red team capability, threat modeling, attacker perspective",
        "indicators": {
            "pentest_regular": {"label": "Regular penetration testing", "weight": 0.30},
            "threat_intel": {"label": "Active threat intelligence consumption", "weight": 0.25},
            "red_team": {"label": "Red team exercises conducted", "weight": 0.20},
            "tabletop": {"label": "Tabletop exercises run", "weight": 0.15},
            "bug_bounty": {"label": "Bug bounty or responsible disclosure", "weight": 0.10},
        }
    },
    "SURFACE": {
        "weight": 0.20,
        "icon": "🟡",
        "description": "Attack surface mapping, asset inventory, exposure reduction",
        "indicators": {
            "asset_inventory": {"label": "Up-to-date asset inventory", "weight": 0.30},
            "ext_scan": {"label": "External attack surface continuously scanned", "weight": 0.25},
            "shadow_it": {"label": "Shadow IT monitored", "weight": 0.20},
            "decommission": {"label": "Unused assets regularly decommissioned", "weight": 0.15},
            "supply_chain": {"label": "Supply chain exposure mapped", "weight": 0.10},
        }
    },
    "ENTROPY": {
        "weight": 0.15,
        "icon": "🔵",
        "description": "Cryptographic hygiene, patch management, configuration drift",
        "indicators": {
            "crypto_hygiene": {"label": "Cryptographically secure randomness used", "weight": 0.30},
            "key_rotation": {"label": "Encryption keys rotated on schedule", "weight": 0.25},
            "patch_mgmt": {"label": "Patch management with enforced SLAs", "weight": 0.25},
            "config_drift": {"label": "Configuration drift monitored", "weight": 0.20},
        }
    },
    "LATERAL": {
        "weight": 0.10,
        "icon": "🟠",
        "description": "Network segmentation, east-west monitoring, containment",
        "indicators": {
            "segmentation": {"label": "Network segmentation implemented", "weight": 0.35},
            "east_west": {"label": "Internal (east-west) traffic monitored", "weight": 0.30},
            "priv_isolation": {"label": "Privileged accounts isolated", "weight": 0.20},
            "cred_protection": {"label": "Credential theft detection active", "weight": 0.15},
        }
    },
    "POSTURE": {
        "weight": 0.10,
        "icon": "🟣",
        "description": "Security culture, policies, awareness, continuous improvement",
        "indicators": {
            "policy": {"label": "Documented security policy reviewed annually", "weight": 0.25},
            "awareness": {"label": "Security awareness training for all staff", "weight": 0.25},
            "ir_plan": {"label": "Tested incident response plan exists", "weight": 0.25},
            "metrics": {"label": "Security metrics tracked and reported", "weight": 0.15},
            "improvement": {"label": "Continuous improvement cycle active", "weight": 0.10},
        }
    },
}

# ── Posture Rating ────────────────────────────────────────────────────────────
POSTURE_RATINGS = [
    (0.90, "A+", "Cyber Patriot",    "🟢", "Exemplary. Few organizations reach this level."),
    (0.80, "A",  "Strong Defender",  "🟢", "Well-defended. Minor gaps remain."),
    (0.70, "B",  "Active Defender",  "🟡", "Good foundation. Targeted improvements needed."),
    (0.60, "C",  "Developing",       "🟡", "Basic controls present. Significant work ahead."),
    (0.40, "D",  "Exposed",          "🟠", "Material risk. Priority remediation required."),
    (0.00, "F",  "Critical Risk",    "🔴", "Immediate action required. High breach probability."),
]

def get_rating(score: float) -> tuple:
    for threshold, grade, label, color, desc in POSTURE_RATINGS:
        if score >= threshold:
            return grade, label, color, desc
    return "F", "Critical Risk", "🔴", "Immediate action required."


# ── Posture Engine ────────────────────────────────────────────────────────────
class PostureEngine:

    def __init__(self):
        self.state = self._load_state()

    def _load_state(self) -> dict:
        if os.path.exists(_POSTURE_STATE):
            with open(_POSTURE_STATE) as f:
                return json.load(f)
        return {"snapshots": [], "current": None}

    def _save_state(self):
        with open(_POSTURE_STATE, "w") as f:
            json.dump(self.state, f, indent=2)

    def _log(self, entry: dict):
        with open(_POSTURE_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def score(self, dimension_scores: dict) -> dict:
        """
        Calculate full posture score.
        dimension_scores: {TRUST: 0.0-1.0, ADVERSARIAL: 0.0-1.0, ...}
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        weighted = {}
        overall_weighted = 0.0
        total_weight = 0.0

        for dim, raw_score in dimension_scores.items():
            if dim in DIMENSIONS:
                weight = DIMENSIONS[dim]["weight"]
                weighted[dim] = round(raw_score * weight, 4)
                overall_weighted += raw_score * weight
                total_weight += weight

        # Normalize (in case not all dims provided)
        if total_weight > 0:
            overall = round(overall_weighted / total_weight, 3)
        else:
            overall = 0.0

        grade, label, color, desc = get_rating(overall)

        snapshot = {
            "timestamp": timestamp,
            "dimension_scores": dimension_scores,
            "weighted_scores": weighted,
            "overall": overall,
            "grade": grade,
            "label": label,
            "color": color,
            "description": desc,
        }

        self.state["current"] = snapshot
        self.state["snapshots"].append({
            "timestamp": timestamp,
            "overall": overall,
            "grade": grade,
        })
        self._save_state()
        self._log(snapshot)

        return snapshot

    def recommend(self, dimension_scores: dict) -> list:
        """Generate prioritized recommendations based on dimension gaps."""
        recs = []
        sorted_dims = sorted(
            dimension_scores.items(),
            key=lambda x: x[1]
        )

        for dim, score in sorted_dims:
            if dim not in DIMENSIONS:
                continue
            info = DIMENSIONS[dim]
            if score < 0.8:
                priority = "CRITICAL" if score < 0.3 else ("HIGH" if score < 0.5 else "MEDIUM")
                gap = 1.0 - score
                recs.append({
                    "dimension": dim,
                    "current_score": score,
                    "gap": round(gap, 2),
                    "priority": priority,
                    "icon": info["icon"],
                    "action": f"Improve {dim} posture: {info['description']}",
                    "quick_wins": [
                        ind["label"]
                        for ind_key, ind in list(info["indicators"].items())[:2]
                    ],
                })

        return sorted(recs, key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["priority"], 4)
        ))

    def delta(self) -> Optional[dict]:
        """Compare current vs previous snapshot."""
        snaps = self.state.get("snapshots", [])
        if len(snaps) < 2:
            return None
        prev = snaps[-2]
        curr = snaps[-1]
        change = round(curr["overall"] - prev["overall"], 3)
        return {
            "previous": prev,
            "current": curr,
            "change": change,
            "direction": "▲ IMPROVED" if change > 0 else ("▼ DECLINED" if change < 0 else "━ STABLE"),
            "magnitude": "significant" if abs(change) > 0.1 else "minor",
        }

    def history(self, limit: int = 10) -> list:
        """Return recent posture history."""
        snaps = self.state.get("snapshots", [])
        return snaps[-limit:]

    def report(self, dimension_scores: dict) -> str:
        """Generate a full posture report as formatted text."""
        result = self.score(dimension_scores)
        recs = self.recommend(dimension_scores)
        delta = self.delta()

        lines = []
        lines.append("╔══════════════════════════════════════════════════════════════════╗")
        lines.append("║  CLARIS AI — POSTURE INTELLIGENCE REPORT                         ║")
        lines.append(f"║  Generated: {result['timestamp'][:19]} UTC                        ║")
        lines.append("╚══════════════════════════════════════════════════════════════════╝")
        lines.append("")
        lines.append(f"  {result['color']} OVERALL POSTURE:  {result['overall']:.1%}  |  Grade: {result['grade']}  |  {result['label']}")
        lines.append(f"  ◎ Assessment: {result['description']}")
        lines.append("")

        if delta:
            lines.append(f"  {delta['direction']}  (prev: {delta['previous']['overall']:.1%} → now: {delta['current']['overall']:.1%})")
            lines.append("")

        lines.append("  ─── DIMENSION BREAKDOWN ─────────────────────────────────────────")
        for dim, score in result["dimension_scores"].items():
            if dim in DIMENSIONS:
                info = DIMENSIONS[dim]
                grade, _, color, _ = get_rating(score)
                bar_len = int(score * 30)
                bar = "█" * bar_len + "░" * (30 - bar_len)
                lines.append(f"  {info['icon']} {dim:<15} [{bar}] {score:.0%}  ({grade})")
        lines.append("")

        if recs:
            lines.append("  ─── TOP RECOMMENDATIONS ──────────────────────────────────────────")
            for i, rec in enumerate(recs[:4], 1):
                lines.append(f"  [{rec['priority']}] {rec['icon']} {rec['dimension']}: {rec['action']}")
                for win in rec["quick_wins"]:
                    lines.append(f"         → {win}")
            lines.append("")

        strengths = [d for d, s in dimension_scores.items() if s >= 0.8]
        if strengths:
            lines.append(f"  🟢 STRENGTHS: {', '.join(strengths)}")

        critical = [d for d, s in dimension_scores.items() if s < 0.3]
        if critical:
            lines.append(f"  🔴 CRITICAL GAPS: {', '.join(critical)}")

        lines.append("")
        lines.append("  ~Claris · Semper Fortis · V7.0 Posture Intelligence Engine")
        lines.append("")

        return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Claris AI — Posture Intelligence Engine V7.0"
    )
    parser.add_argument("--report",      action="store_true", help="Generate full posture report (interactive)")
    parser.add_argument("--score",       action="store_true", help="Score with provided values")
    parser.add_argument("--history",     action="store_true", help="Show posture history")
    parser.add_argument("--delta",       action="store_true", help="Show change vs last assessment")
    parser.add_argument("--recommend",   action="store_true", help="Show recommendations only")
    parser.add_argument("--json",        action="store_true", help="Output as JSON")
    parser.add_argument("--learn",       action="store_true", help="Educational mode: explain each Core Word dimension")

    # Dimension score flags
    for dim in DIMENSIONS:
        parser.add_argument(f"--{dim.lower()}", type=float, default=None,
                          help=f"{dim} score (0.0-1.0)")

    args = parser.parse_args()

    if getattr(args, 'learn', False):
        print("\n🎓 POSTURE ENGINE V7.0 — LEARNING MODE")
        print("══════════════════════════════════════")
        print("The 6 Core Words are the pillars of holistic security posture.")
        print("Each dimension represents a critical security capability area.\n")
        dim_education = {
            "TRUST": ("Identity & Access", "Can you trust who is accessing your systems?", [
                "Enable MFA on all accounts immediately",
                "Audit which accounts have admin access — revoke what's unneeded",
                "Implement Zero Trust: verify every request, even internal ones"
            ]),
            "ADVERSARIAL": ("Attacker Mindset", "Do you know how attackers think about your systems?", [
                "Schedule a penetration test — find your weaknesses before attackers do",
                "Run threat modeling sessions on your most critical systems",
                "Subscribe to threat intelligence feeds relevant to your industry"
            ]),
            "SURFACE": ("Attack Surface", "How much of you is exposed to the internet?", [
                "Run an asset inventory — list every internet-facing service",
                "Decommission or firewall services you no longer actively use",
                "Use Shodan or similar to see your external exposure"
            ]),
            "ENTROPY": ("Cryptographic Hygiene", "Is your randomness truly random? Are you patching?", [
                "Enable auto-updates for OS and critical dependencies",
                "Audit your certificate expiration dates",
                "Ensure password hashing uses bcrypt/argon2 with high cost factors"
            ]),
            "LATERAL": ("Lateral Movement Defense", "If an attacker gets in, can they move freely?", [
                "Segment your network — production should not touch development",
                "Implement least privilege — each service only accesses what it needs",
                "Deploy EDR/XDR on endpoints to detect lateral movement"
            ]),
            "POSTURE": ("Continuous Security", "Is security a program or a one-time project?", [
                "Schedule monthly security reviews — posture decays without attention",
                "Build a security dashboard to track key metrics over time",
                "Train your team on security awareness quarterly"
            ]),
        }
        for dim, (name, question, actions) in dim_education.items():
            info = DIMENSIONS.get(dim, {})
            print(f"  {info.get('icon','•')} {dim} — {name}")
            print(f"     Core question: {question}")
            print(f"     Top 3 improvement actions:")
            for action in actions:
                print(f"       ✦ {action}")
            print()

    engine = PostureEngine()

    # Collect dimension scores from flags
    provided = {}
    for dim in DIMENSIONS:
        val = getattr(args, dim.lower(), None)
        if val is not None:
            provided[dim] = max(0.0, min(1.0, val))

    if args.score and provided:
        result = engine.score(provided)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n  {result['color']} {result['overall']:.1%}  |  {result['grade']} — {result['label']}\n")
            print(f"  {result['description']}\n")

    elif args.report:
        if not provided:
            print("\n📊 INTERACTIVE POSTURE ASSESSMENT\n")
            print("   Rate each dimension 0.0 (none) to 1.0 (excellent):\n")
            for dim, info in DIMENSIONS.items():
                while True:
                    try:
                        val = float(input(f"  {info['icon']} {dim} — {info['description']}: "))
                        provided[dim] = max(0.0, min(1.0, val))
                        break
                    except ValueError:
                        print("     Enter a number between 0.0 and 1.0")
        print(engine.report(provided))

    elif args.history:
        hist = engine.history()
        if args.json:
            print(json.dumps(hist, indent=2))
        else:
            print("\n📈 POSTURE HISTORY\n")
            for snap in hist:
                grade, _, color, _ = get_rating(snap["overall"])
                print(f"  {color} {snap['timestamp'][:10]}  {snap['overall']:.1%}  ({grade})")
            print()

    elif args.delta:
        d = engine.delta()
        if d:
            if args.json:
                print(json.dumps(d, indent=2))
            else:
                print(f"\n  {d['direction']}: {d['previous']['overall']:.1%} → {d['current']['overall']:.1%}  ({d['magnitude']} change)\n")
        else:
            print("\n  Not enough history for delta comparison.\n")

    elif args.recommend and provided:
        recs = engine.recommend(provided)
        if args.json:
            print(json.dumps(recs, indent=2))
        else:
            print("\n📋 TOP RECOMMENDATIONS\n")
            for rec in recs[:5]:
                print(f"  [{rec['priority']}] {rec['icon']} {rec['dimension']}: {rec['action']}")
    else:
        parser.print_help()
        print("""
Examples:
  python3 posture_engine.py --report
  python3 posture_engine.py --score --trust 0.8 --adversarial 0.5 --surface 0.7 \\
                            --entropy 0.6 --lateral 0.4 --posture 0.9
  python3 posture_engine.py --history
  python3 posture_engine.py --delta
""")


if __name__ == "__main__":
    main()

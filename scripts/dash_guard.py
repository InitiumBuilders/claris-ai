#!/usr/bin/env python3
"""
Script: dash_guard.py
Version: V10.0 (Forge)
Claris AI — Defense Network
Author: August + AVARI (Unitium Mode)
Last Updated: 2026-03-10

Dash Defense Module — expanded, comprehensive guard for Dash Platform.
Protects DAPI, DPNS, Evonodes. Detects quorum manipulation, contract injections,
identity spoofing, collateral fraud. Includes simulated network status.

Positive security work FOR the Dash network.
"""

import argparse, json, sys, os, re, random
from datetime import datetime, timezone

VERSION = "V10.0"
SCRIPT_NAME = "dash_guard"

# ─── COMPREHENSIVE THREAT SIGNATURES ─────────────────────────────────────────

DASH_THREATS = {
    # QUORUM THREATS
    "QUORUM_DOUBLE_SIGN": {
        "description": "Evonode double-signing — signing two conflicting platform blocks",
        "patterns": [r"double.{0,10}sign", r"sign.{0,20}twice", r"conflicting.{0,20}(block|signature)"],
        "severity": "CRITICAL",
        "category": "QUORUM",
        "impact": "Can stall platform consensus, potential slashing",
        "mitigation": "ChainLocks provide finality. Monitor for conflicting quorum signatures.",
    },
    "QUORUM_MANIPULATION": {
        "description": "Attempt to manipulate platform quorum voting",
        "patterns": [r"quorum.{0,30}(manipulat|bypass|fake|forge)", r"(fake|forge).{0,20}quorum", r"bribe.{0,20}(evonode|masternode)"],
        "severity": "CRITICAL",
        "category": "QUORUM",
        "impact": "Quorum manipulation can halt platform or approve invalid state transitions",
        "mitigation": "Requires >1/3 of quorum — economic cost is very high (~4000 DASH per node)",
    },
    "QUORUM_DKG_ATTACK": {
        "description": "Attack on Distributed Key Generation ceremony",
        "patterns": [r"dkg.{0,20}(attack|poison|interfer)", r"distributed.{0,10}key.{0,10}gen.{0,20}(fail|compromise)"],
        "severity": "CRITICAL",
        "category": "QUORUM",
        "impact": "Compromised DKG = compromised quorum threshold signatures",
        "mitigation": "Monitor DKG participation and success rates per quorum",
    },

    # DAPI THREATS
    "DAPI_RATE_EVASION": {
        "description": "Rate limit evasion on DAPI endpoints",
        "patterns": [r"dapi.{0,20}rate.{0,10}(evad|bypass|limit)", r"rotate.{0,20}ip.{0,30}dapi", r"dapi.{0,20}flood"],
        "severity": "HIGH",
        "category": "DAPI",
        "impact": "Degrades DAPI availability for legitimate users",
        "mitigation": "Implement client reputation scoring. Block rotating IP patterns.",
    },
    "DAPI_STATE_TRANSITION_INJECT": {
        "description": "Malformed or injected state transition broadcast",
        "patterns": [r"(inject|malform|corrupt).{0,20}state.?transition", r"state.?transition.{0,30}(poison|tamper|bypass)"],
        "severity": "CRITICAL",
        "category": "DAPI",
        "impact": "Could corrupt Drive state or trigger unintended platform behavior",
        "mitigation": "All state transitions must be verified via platform proofs before acting on them",
    },
    "DAPI_REPLAY_ATTACK": {
        "description": "Replay of previously valid state transition",
        "patterns": [r"replay.{0,20}(state.?transition|broadcast|tx)", r"rebroadcast.{0,20}(old|previous|stale)"],
        "severity": "HIGH",
        "category": "DAPI",
        "impact": "Replaying state transitions could cause unintended mutations",
        "mitigation": "Platform uses nonces — replay protection is built in. Verify nonce freshness.",
    },

    # CONTRACT THREATS
    "CONTRACT_SCHEMA_POISON": {
        "description": "Data contract schema poisoning or injection",
        "patterns": [r"(poison|corrupt|tamper).{0,20}(data.?contract|schema)", r"schema.{0,20}(inject|overflow|overflow)"],
        "severity": "CRITICAL",
        "category": "CONTRACT",
        "impact": "Corrupted schemas can break all applications using the contract",
        "mitigation": "Validate contracts thoroughly before publishing. Contracts are immutable once deployed.",
    },
    "CONTRACT_PRIVILEGE_ESCALATION": {
        "description": "Attempt to escalate permissions via contract manipulation",
        "patterns": [r"contract.{0,30}(escalat|privilege|permission).{0,20}(bypass|elevat)", r"owner.{0,20}(bypass|spoof|replac).{0,20}contract"],
        "severity": "HIGH",
        "category": "CONTRACT",
        "impact": "Unauthorized document mutations or contract ownership changes",
        "mitigation": "Strict owner validation on all document mutations",
    },

    # IDENTITY THREATS
    "IDENTITY_HIJACKING": {
        "description": "Attempt to hijack a Dash Platform identity",
        "patterns": [r"identity.{0,30}(hijack|steal|tak.?over)", r"(steal|replac).{0,20}dash.{0,10}identity", r"(forge|fake).{0,20}platform.{0,20}identity"],
        "severity": "CRITICAL",
        "category": "IDENTITY",
        "impact": "Full account takeover — attacker controls all documents and DPNS names",
        "mitigation": "Secure private key storage. Hardware wallet for high-value identities.",
    },
    "DPNS_FRONT_RUNNING": {
        "description": "Front-running a DPNS name registration",
        "patterns": [r"front.?run.{0,20}dpns", r"(watch|monitor).{0,20}(mempool|preorder).{0,20}(steal|grab|register)"],
        "severity": "MEDIUM",
        "category": "DPNS",
        "impact": "Target loses their desired name to an attacker",
        "mitigation": "Two-phase commit reduces (but doesn't eliminate) front-running risk",
    },
    "DPNS_TYPOSQUATTING": {
        "description": "Registering typosquatted variations of known names",
        "patterns": [r"(squat|typosquat|register).{0,30}(dpns|\.dash)", r"similar.{0,20}(name|domain).{0,20}\.dash"],
        "severity": "MEDIUM",
        "category": "DPNS",
        "impact": "Phishing, brand confusion, user misdirection",
        "mitigation": "Monitor for near-duplicates of your DPNS names",
    },

    # COLLATERAL THREATS
    "COLLATERAL_FRAUD": {
        "description": "Masternode/evonode collateral transaction fraud",
        "patterns": [r"(fake|steal|fraud).{0,20}(collateral|4000.{0,10}dash)", r"collateral.{0,20}(spoof|replac|drain)"],
        "severity": "CRITICAL",
        "category": "COLLATERAL",
        "impact": "Loss of evonode status, ~$400K+ financial loss",
        "mitigation": "Use hardware wallet for collateral. Never expose collateral private key.",
    },
    "COLLATERAL_TRANSACTION_ANOMALY": {
        "description": "Suspicious collateral transaction pattern",
        "patterns": [r"collateral.{0,20}transaction.{0,20}(anomal|suspici|unusual)", r"masternode.{0,20}(collateral|tx).{0,20}(tamper|modify)"],
        "severity": "HIGH",
        "category": "COLLATERAL",
        "impact": "Could indicate collateral theft or evonode compromise attempt",
        "mitigation": "Monitor collateral addresses with real-time alerting",
    },
}

# ─── MOCK NETWORK STATUS ─────────────────────────────────────────────────────

MOCK_THREAT_EVENTS = [
    {"timestamp": "18:42 UTC", "type": "DPNS_TYPOSQUATTING", "severity": "MEDIUM", "detail": "3 typosquatted names registered in last hour", "status": "MONITORING"},
    {"timestamp": "17:15 UTC", "type": "DAPI_RATE_EVASION", "severity": "LOW", "detail": "IP rotation pattern on broadcastStateTransition endpoint", "status": "BLOCKED"},
    {"timestamp": "15:30 UTC", "type": "CLEAN_WINDOW", "severity": "INFO", "detail": "No threats in 90-minute window prior", "status": "CLEAR"},
    {"timestamp": "14:02 UTC", "type": "QUORUM_ANOMALY", "severity": "LOW", "detail": "One evonode offline — quorum maintained", "status": "RESOLVED"},
]


def get_network_status() -> dict:
    return {
        "network": "Dash Platform Mainnet",
        "overall_threat_level": "GUARDED",
        "threat_scale": "LOW | GUARDED | ELEVATED | SEVERE | CRITICAL",
        "components": {
            "evonodes": {"status": "HEALTHY", "count": 4096, "active_quorums": 24, "threat": "LOW"},
            "dapi": {"status": "OPERATIONAL", "rps": 12430, "error_rate": "0.02%", "threat": "GUARDED"},
            "dpns": {"status": "HEALTHY", "registrations_24h": 847, "squat_attempts_24h": 3, "threat": "MEDIUM"},
            "drive": {"status": "HEALTHY", "state_transitions_24h": 45120, "invalid_attempts": 12, "threat": "LOW"},
            "governance": {"status": "NORMAL", "active_proposals": 7, "suspicious_voting": False, "threat": "LOW"},
        },
        "recent_threat_events": MOCK_THREAT_EVENTS,
        "claris_dash_guard": "ACTIVE",
        "data_source": "SIMULATED — Claris AI V10.0 Demo",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── SCAN ENGINE ─────────────────────────────────────────────────────────────

def scan(text: str, category: str = None, verbose: bool = False) -> dict:
    """Scan for Dash Platform threats."""
    if not text or not text.strip():
        return {"status": "CLEAN", "threats": [], "score": 0}

    text_lower = text.lower()
    threats_found = []
    score = 0

    threats_to_check = {k: v for k, v in DASH_THREATS.items()
                        if category is None or v["category"] == category.upper()}

    for threat_id, threat in threats_to_check.items():
        for pattern in threat["patterns"]:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    severity_score = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}.get(threat["severity"], 10)
                    threats_found.append({
                        "id": threat_id,
                        "description": threat["description"],
                        "severity": threat["severity"],
                        "category": threat["category"],
                        "impact": threat["impact"],
                        "mitigation": threat["mitigation"],
                        "score": severity_score,
                        "pattern": pattern if verbose else "redacted",
                    })
                    score += severity_score
                    break
            except re.error:
                continue

    score = min(score, 100)

    if score == 0:
        status = "CLEAN"
    elif score < 20:
        status = "WARN"
    elif score < 50:
        status = "FLAG"
    else:
        status = "BLOCK"

    return {
        "status": status,
        "score": score,
        "threats_found": len(threats_found),
        "threats": threats_found,
        "categories_scanned": list(set(t["category"] for t in DASH_THREATS.values())) if category is None else [category.upper()],
        "recommendation": {
            "CLEAN": "No Dash Platform threats detected.",
            "WARN": "Low-level Dash signals. Log and monitor.",
            "FLAG": "Dash threat indicators present. Investigate before proceeding.",
            "BLOCK": "CRITICAL: Confirmed Dash attack pattern. Block immediately.",
        }[status],
        "positive_security": "Claris DashGuard — protecting the Dash network",
        "claris_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Claris AI Dash Guard {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dash_guard.py --scan "testing quorum manipulation bypass"
  python3 dash_guard.py --scan "dpns typosquat" --category DPNS
  python3 dash_guard.py --status
  python3 dash_guard.py --list-threats
        """
    )
    parser.add_argument("--scan", metavar="TEXT", help="Scan text for Dash threats")
    parser.add_argument("--category", choices=["QUORUM", "DAPI", "CONTRACT", "IDENTITY", "DPNS", "COLLATERAL"],
                        help="Limit scan to specific category")
    parser.add_argument("--status", action="store_true", help="Show Dash network threat status")
    parser.add_argument("--list-threats", action="store_true", help="List all monitored threat types")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.status:
        print(json.dumps(get_network_status(), indent=2))
        return

    if args.list_threats:
        threats_list = [
            {"id": k, "name": v["description"], "severity": v["severity"], "category": v["category"]}
            for k, v in DASH_THREATS.items()
        ]
        print(json.dumps({"threats": threats_list, "total": len(threats_list), "version": VERSION}, indent=2))
        return

    if args.scan:
        result = scan(args.scan, category=args.category, verbose=args.verbose)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["status"] in ("CLEAN", "WARN") else 1)
        return

    parser.print_help()


if __name__ == "__main__":
    main()

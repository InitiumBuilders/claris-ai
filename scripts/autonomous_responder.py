#!/usr/bin/env python3
"""
Script: autonomous_responder.py
Version: V6.0
Claris AI — Defense Network
Author: August + AVARI (Unitium Mode)
Last Updated: 2026-03-10

Autonomous incident response engine.
Triages threats, runs response playbooks, simulates attack responses,
and manages escalation chains.
"""

import argparse, json, sys, os, re, random
from datetime import datetime, timezone
from pathlib import Path

VERSION = "V6.0"
SCRIPT_NAME = "autonomous_responder"

DATA_DIR = Path(__file__).parent.parent / "data"
RESPONSE_LOG = DATA_DIR / "response_log.jsonl"

# ─── ESCALATION CHAIN ─────────────────────────────────────────────────────────

ESCALATION_CHAIN = {
    "LOW": ["AVARI (auto-log)"],
    "MEDIUM": ["AVARI (alert)", "Claris AI (flag + log)"],
    "HIGH": ["AVARI (alert)", "Claris AI (block)", "August (Telegram notification)"],
    "CRITICAL": ["AVARI (emergency)", "Claris AI (BLOCK ALL)", "August (immediate alert)", "Eris (red team review)"],
}

# ─── RESPONSE PLAYBOOKS ───────────────────────────────────────────────────────

PLAYBOOKS = {
    "prompt_injection": {
        "name": "Prompt Injection Attack",
        "threat_level": "HIGH",
        "description": "Adversarial prompt attempting to override AI system instructions",
        "steps": [
            {"phase": "DETECT", "action": "Run injection_guard.py on input", "tool": "injection_guard.py", "auto": True},
            {"phase": "CONTAIN", "action": "Reject the injected prompt; do not process", "auto": True},
            {"phase": "CONTAIN", "action": "Log full payload with timestamp and source", "auto": True},
            {"phase": "ANALYZE", "action": "Extract and classify injection technique (override/jailbreak/leak)", "auto": True},
            {"phase": "RESPOND", "action": "Add injection pattern to cortex_engine.py pattern bank", "auto": False},
            {"phase": "RESPOND", "action": "Notify August if novel technique detected", "auto": False},
            {"phase": "RECOVER", "action": "Confirm no sensitive data was leaked in response", "auto": True},
            {"phase": "LEARN", "action": "Update adversarial_trainer.py with new sample", "auto": False},
        ],
    },
    "wallet_drain": {
        "name": "Crypto Wallet Drain Attack",
        "threat_level": "CRITICAL",
        "description": "Social engineering or technical exploit targeting crypto wallet/private keys",
        "steps": [
            {"phase": "DETECT", "action": "Identify wallet drain indicators (urgency + key request)", "auto": True},
            {"phase": "CONTAIN", "action": "BLOCK immediately — do not provide any wallet assistance", "auto": True},
            {"phase": "CONTAIN", "action": "Revoke any active session if compromise suspected", "auto": True},
            {"phase": "ALERT", "action": "IMMEDIATE: Notify August via Telegram (CRITICAL severity)", "auto": True},
            {"phase": "ANALYZE", "action": "Trace attack origin — which channel, what payload", "auto": True},
            {"phase": "RESPOND", "action": "Blacklist source identifier", "auto": True},
            {"phase": "RESPOND", "action": "Provide August with safe wallet security steps", "auto": False},
            {"phase": "RECOVER", "action": "Verify no transactions were initiated", "auto": False},
            {"phase": "LEARN", "action": "Update social engineering pattern database", "auto": False},
        ],
    },
    "dapi_abuse": {
        "name": "DAPI Endpoint Abuse",
        "threat_level": "HIGH",
        "description": "Malicious or excessive use of Dash Platform API endpoints",
        "steps": [
            {"phase": "DETECT", "action": "dash_security_intelligence.py identifies DAPI abuse pattern", "auto": True},
            {"phase": "CONTAIN", "action": "Rate-limit or block offending IP/identity", "auto": True},
            {"phase": "ANALYZE", "action": "Classify: rate-limit evasion vs. malformed payloads vs. replay", "auto": True},
            {"phase": "RESPOND", "action": "Report to Dash Core Group (DCG) if novel attack", "auto": False},
            {"phase": "RESPOND", "action": "Add DAPI abuse signature to dash_security_intelligence.py", "auto": False},
            {"phase": "RECOVER", "action": "Verify no state corruption on Drive", "auto": False},
            {"phase": "LEARN", "action": "Update threat intelligence database", "auto": True},
        ],
    },
    "evonode_attack": {
        "name": "Evonode Attack / Quorum Manipulation",
        "threat_level": "CRITICAL",
        "description": "Attack targeting Dash Evolution Masternode quorum integrity",
        "steps": [
            {"phase": "DETECT", "action": "Identify quorum anomaly or evonode spoofing signal", "auto": True},
            {"phase": "CONTAIN", "action": "CRITICAL ALERT — Quorum attacks can halt platform", "auto": True},
            {"phase": "CONTAIN", "action": "Isolate affected quorum observation data", "auto": True},
            {"phase": "ALERT", "action": "IMMEDIATE: Alert August + Dash community channels", "auto": True},
            {"phase": "ALERT", "action": "Notify Dash Core Group (DCG) security contact", "auto": False},
            {"phase": "ANALYZE", "action": "Determine: DDoS vs identity spoof vs quorum manipulation", "auto": False},
            {"phase": "RESPOND", "action": "Publish threat advisory if confirmed", "auto": False},
            {"phase": "RECOVER", "action": "Monitor quorum recovery and re-establishment", "auto": False},
            {"phase": "LEARN", "action": "Document for Dash security research paper", "auto": False},
        ],
    },
    "api_key_compromise": {
        "name": "API Key Compromise",
        "threat_level": "HIGH",
        "description": "API key or secret credential has been exposed or stolen",
        "steps": [
            {"phase": "DETECT", "action": "Detect key in code, logs, or public repository", "auto": True},
            {"phase": "CONTAIN", "action": "REVOKE compromised key IMMEDIATELY", "auto": False},
            {"phase": "CONTAIN", "action": "Block any active sessions using compromised key", "auto": True},
            {"phase": "ALERT", "action": "Alert August — key rotation required NOW", "auto": True},
            {"phase": "ANALYZE", "action": "Determine exposure window (when was key first compromised?)", "auto": False},
            {"phase": "ANALYZE", "action": "Audit API call logs for unauthorized usage during window", "auto": False},
            {"phase": "RESPOND", "action": "Generate new key with enhanced secret management", "auto": False},
            {"phase": "RESPOND", "action": "Add git-secrets pre-commit hook to prevent future leaks", "auto": False},
            {"phase": "RECOVER", "action": "Rotate all related credentials (token chains)", "auto": False},
            {"phase": "LEARN", "action": "Update injection_guard.py with API key pattern detection", "auto": True},
        ],
    },
    "social_engineering": {
        "name": "Social Engineering Attack",
        "threat_level": "HIGH",
        "description": "Manipulation attempt targeting human or AI decision-making via deception",
        "steps": [
            {"phase": "DETECT", "action": "Identify urgency + authority + fear manipulation patterns", "auto": True},
            {"phase": "CONTAIN", "action": "Do not comply with any request until verification complete", "auto": True},
            {"phase": "ANALYZE", "action": "Classify: vishing, phishing, pretexting, quid pro quo", "auto": True},
            {"phase": "RESPOND", "action": "Apply out-of-band verification (call back on known number)", "auto": False},
            {"phase": "RESPOND", "action": "Log and report — educate August on the attempt", "auto": True},
            {"phase": "LEARN", "action": "Add social engineering patterns to detection database", "auto": True},
        ],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration Attempt",
        "threat_level": "CRITICAL",
        "description": "Unauthorized attempt to extract sensitive data from the system",
        "steps": [
            {"phase": "DETECT", "action": "Identify large data access + unusual destination patterns", "auto": True},
            {"phase": "CONTAIN", "action": "Terminate suspicious data transfer immediately", "auto": True},
            {"phase": "ALERT", "action": "CRITICAL: Alert August — potential data breach", "auto": True},
            {"phase": "ANALYZE", "action": "Identify: what data was accessed, by whom, how much", "auto": False},
            {"phase": "RESPOND", "action": "Initiate breach notification procedures if data left system", "auto": False},
            {"phase": "RECOVER", "action": "Audit and tighten data access controls", "auto": False},
        ],
    },
    "jailbreak": {
        "name": "AI Jailbreak Attempt",
        "threat_level": "MEDIUM",
        "description": "Attempt to bypass AI safety constraints and system instructions",
        "steps": [
            {"phase": "DETECT", "action": "injection_guard.py flags jailbreak pattern", "auto": True},
            {"phase": "CONTAIN", "action": "Reject request with standard safety message", "auto": True},
            {"phase": "LOG", "action": "Save payload for adversarial training", "auto": True},
            {"phase": "ANALYZE", "action": "Classify jailbreak type: role-play, DAN, override, encoding", "auto": True},
            {"phase": "LEARN", "action": "Feed to adversarial_trainer.py for model hardening", "auto": False},
        ],
    },
    "zero_day_exploit": {
        "name": "Zero-Day Exploit Attempt",
        "threat_level": "CRITICAL",
        "description": "Novel attack exploiting an unknown vulnerability",
        "steps": [
            {"phase": "DETECT", "action": "zero_day_hunter.py anomaly score > 0.85", "auto": True},
            {"phase": "CONTAIN", "action": "Block and quarantine immediately — assume worst case", "auto": True},
            {"phase": "ALERT", "action": "CRITICAL: Immediate notification to August + Eris agent", "auto": True},
            {"phase": "ANALYZE", "action": "Forensic analysis — preserve all artifacts", "auto": False},
            {"phase": "RESPOND", "action": "Responsible disclosure if vendor vulnerability found", "auto": False},
            {"phase": "LEARN", "action": "Document for zero_day_hunter.py pattern database", "auto": False},
        ],
    },
    "supply_chain": {
        "name": "Supply Chain Attack",
        "threat_level": "CRITICAL",
        "description": "Compromise via third-party dependency, library, or tool",
        "steps": [
            {"phase": "DETECT", "action": "Dependency audit flags unexpected code or version changes", "auto": True},
            {"phase": "CONTAIN", "action": "Pin all dependencies to known-good versions", "auto": False},
            {"phase": "ALERT", "action": "Alert August — dependency review required", "auto": True},
            {"phase": "ANALYZE", "action": "Audit: which dependencies affected, what code changed", "auto": False},
            {"phase": "RESPOND", "action": "Replace affected dependency or fork to audited version", "auto": False},
            {"phase": "RECOVER", "action": "Full system scan with clean dependency tree", "auto": False},
        ],
    },
    "identity_theft": {
        "name": "Digital Identity Theft",
        "threat_level": "CRITICAL",
        "description": "Takeover of Dash Platform identity or OpenClaw session identity",
        "steps": [
            {"phase": "DETECT", "action": "dash_security_intelligence.py flags identity hijacking", "auto": True},
            {"phase": "CONTAIN", "action": "Revoke all active sessions for compromised identity", "auto": True},
            {"phase": "ALERT", "action": "IMMEDIATE: Notify August — identity breach", "auto": True},
            {"phase": "ANALYZE", "action": "Trace: which documents/actions were taken under stolen identity", "auto": False},
            {"phase": "RESPOND", "action": "Rotate all cryptographic keys associated with identity", "auto": False},
            {"phase": "RECOVER", "action": "Restore state to pre-compromise checkpoint if possible", "auto": False},
        ],
    },
    "insider_threat": {
        "name": "Insider Threat",
        "threat_level": "HIGH",
        "description": "Malicious or negligent action from a trusted internal actor",
        "steps": [
            {"phase": "DETECT", "action": "Behavioral anomaly detection — unusual access patterns", "auto": True},
            {"phase": "CONTAIN", "action": "Apply least-privilege review — reduce permissions temporarily", "auto": False},
            {"phase": "ALERT", "action": "Alert August — insider threat indicators", "auto": True},
            {"phase": "ANALYZE", "action": "Forensic review of recent access logs", "auto": False},
            {"phase": "RESPOND", "action": "Apply zero-trust controls — re-verify all access", "auto": False},
        ],
    },
}


# ─── TRIAGE ENGINE ────────────────────────────────────────────────────────────

def triage(threat_level: str) -> dict:
    """Generate response based on threat level."""
    threat_level = threat_level.upper()
    if threat_level not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return {"error": f"Invalid threat level: {threat_level}. Use LOW/MEDIUM/HIGH/CRITICAL", "code": 400}

    escalation = ESCALATION_CHAIN[threat_level]
    response_time = {"LOW": "72 hours", "MEDIUM": "4 hours", "HIGH": "1 hour", "CRITICAL": "IMMEDIATE"}[threat_level]

    return {
        "threat_level": threat_level,
        "response_required": threat_level in ("HIGH", "CRITICAL"),
        "response_time_target": response_time,
        "escalation_chain": escalation,
        "immediate_actions": {
            "LOW": ["Log the event", "Continue monitoring"],
            "MEDIUM": ["Log with full detail", "Flag for review", "Monitor for escalation"],
            "HIGH": ["Block the source", "Alert August", "Run relevant playbook"],
            "CRITICAL": ["BLOCK ALL related traffic", "IMMEDIATE alert to August", "Activate Eris red team", "Preserve all forensic artifacts"],
        }[threat_level],
        "recommended_playbooks": [name for name, pb in PLAYBOOKS.items() if pb["threat_level"] in (["LOW", "MEDIUM", "HIGH", "CRITICAL"][:["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(threat_level) + 1])],
        "claris_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def run_simulation(attack_type: str) -> dict:
    """Simulate response to an attack type (dry run)."""
    if attack_type not in PLAYBOOKS:
        return {"error": f"Unknown attack type: {attack_type}", "available": list(PLAYBOOKS.keys()), "code": 404}

    playbook = PLAYBOOKS[attack_type]
    sim_log = []

    for i, step in enumerate(playbook["steps"]):
        status = "✅ AUTO-EXECUTED" if step["auto"] else "⏳ AWAITING-HUMAN"
        sim_log.append({
            "step": i + 1,
            "phase": step["phase"],
            "action": step["action"],
            "auto": step["auto"],
            "status": status,
            "simulated_at": datetime.now(timezone.utc).isoformat(),
        })

    auto_count = sum(1 for s in playbook["steps"] if s["auto"])
    manual_count = len(playbook["steps"]) - auto_count

    return {
        "simulation": True,
        "attack_type": attack_type,
        "playbook_name": playbook["name"],
        "threat_level": playbook["threat_level"],
        "total_steps": len(playbook["steps"]),
        "automated_steps": auto_count,
        "manual_steps": manual_count,
        "automation_rate": f"{int(auto_count / len(playbook['steps']) * 100)}%",
        "escalation": ESCALATION_CHAIN[playbook["threat_level"]],
        "steps": sim_log,
        "note": "DRY RUN — No actions actually taken",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def log_response(data: dict):
    """Log a response event to JSONL file."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESPONSE_LOG, "a") as f:
        f.write(json.dumps(data) + "\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Claris AI Autonomous Responder {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 autonomous_responder.py --triage HIGH
  python3 autonomous_responder.py --simulate prompt_injection
  python3 autonomous_responder.py --playbook wallet_drain
  python3 autonomous_responder.py --list-playbooks
        """
    )
    parser.add_argument("--triage", metavar="LEVEL", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Triage at threat level")
    parser.add_argument("--simulate", metavar="ATTACK",
                        choices=list(PLAYBOOKS.keys()),
                        help="Simulate response to attack type")
    parser.add_argument("--playbook", metavar="TYPE",
                        choices=list(PLAYBOOKS.keys()),
                        help="Show full playbook for attack type")
    parser.add_argument("--list-playbooks", action="store_true", help="List all available playbooks")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.list_playbooks:
        playbooks_summary = [
            {"id": k, "name": v["name"], "threat_level": v["threat_level"], "steps": len(v["steps"])}
            for k, v in PLAYBOOKS.items()
        ]
        print(json.dumps({"available_playbooks": playbooks_summary}, indent=2))
        return

    if args.triage:
        result = triage(args.triage)
        print(json.dumps(result, indent=2))
        log_response({"type": "triage", **result})
        return

    if args.simulate:
        result = run_simulation(args.simulate)
        print(json.dumps(result, indent=2))
        log_response({"type": "simulation", **result})
        return

    if args.playbook:
        pb = PLAYBOOKS[args.playbook]
        print(json.dumps(pb, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()

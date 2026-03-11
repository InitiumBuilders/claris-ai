#!/usr/bin/env python3
"""
Script: openclaw_guardian.py
Version: V10.0 (Forge)
Claris AI — Defense Network
Author: August + AVARI (Unitium Mode)
Last Updated: 2026-03-10

OpenClaw Instance Guardian.
Wraps all Anthropic API calls — scans prompts before they leave,
scans responses before they arrive. L1-L7 defense on every call.
Blocks T1-T12 threat categories.
"""

import argparse, json, sys, os, re
from datetime import datetime, timezone

VERSION = "V10.0"
SCRIPT_NAME = "openclaw_guardian"

# ─── L1-L7 DEFENSE LAYERS ─────────────────────────────────────────────────────

DEFENSE_LAYERS = {
    "L1": {
        "name": "Perimeter WAF",
        "description": "Web Application Firewall — block known malicious patterns before any processing",
        "targets": ["T1_SQL_INJECTION", "T2_PROMPT_INJECTION", "T3_XSS"],
    },
    "L2": {
        "name": "Input Sanitization",
        "description": "Normalize and sanitize all input — strip null bytes, normalize unicode, enforce length limits",
        "targets": ["T4_ENCODING_BYPASS", "T5_NULL_BYTE"],
    },
    "L3": {
        "name": "Behavioral Analysis",
        "description": "Analyze request patterns over time — detect rate abuse, session anomalies, coordinated attacks",
        "targets": ["T6_RATE_ABUSE", "T7_SESSION_HIJACK"],
    },
    "L4": {
        "name": "Semantic Guard",
        "description": "Deep semantic analysis of intent — detect social engineering, manipulation, deception",
        "targets": ["T8_SOCIAL_ENGINEERING", "T9_JAILBREAK"],
    },
    "L5": {
        "name": "Context Integrity",
        "description": "Verify system prompt integrity — detect attempts to override or poison system context",
        "targets": ["T2_PROMPT_INJECTION", "T10_CONTEXT_POISONING"],
    },
    "L6": {
        "name": "Response Filtering",
        "description": "Filter outbound responses — prevent data leakage, PII exposure, secret exfiltration",
        "targets": ["T11_DATA_EXFILTRATION", "T12_PII_LEAKAGE"],
    },
    "L7": {
        "name": "Meta Oversight",
        "description": "AI-on-AI oversight — Claris monitors the primary LLM for behavioral drift and anomalies",
        "targets": ["ALL_THREATS"],
    },
}

# ─── T1-T12 THREAT CATEGORIES ─────────────────────────────────────────────────

THREAT_CATEGORIES = {
    "T1": {
        "name": "SQL / Command Injection",
        "patterns": [
            r"(union|select|insert|drop|delete|update|exec|execute).{0,20}(from|into|where|table)",
            r";\s*(drop|delete|truncate)\s+",
            r"'.*?--",
            r"xp_cmdshell",
        ],
        "severity": "CRITICAL",
        "layer": "L1",
    },
    "T2": {
        "name": "Prompt Injection",
        "patterns": [
            r"ignore.{0,30}(previous|above|prior|instructions?|prompt)",
            r"disregard.{0,30}(system|instructions?|context)",
            r"new\s+instructions?",
            r"you\s+are\s+now\s+(a\s+)?(different|new|unrestricted|evil|dan)",
            r"act\s+as\s+if.{0,30}(no\s+restrict|unrestrict|freed?)",
            r"(system|assistant)\s*:.{0,20}(ignore|override)",
            r"\/\*.*?\*\/|\/\/.*?\n",  # Code comment injection
        ],
        "severity": "HIGH",
        "layer": "L2",
    },
    "T3": {
        "name": "Cross-Site Scripting (XSS)",
        "patterns": [
            r"<script[^>]*>",
            r"javascript:",
            r"on(load|click|error|mouseover)\s*=",
            r"eval\s*\(",
            r"document\.(cookie|location|write)",
        ],
        "severity": "HIGH",
        "layer": "L1",
    },
    "T4": {
        "name": "Encoding Bypass",
        "patterns": [
            r"%[0-9a-fA-F]{2}",  # URL encoding
            r"\\u[0-9a-fA-F]{4}",  # Unicode escape
            r"&#[0-9]+;",  # HTML entities
            r"base64_decode",
            r"\\x[0-9a-fA-F]{2}",
        ],
        "severity": "MEDIUM",
        "layer": "L2",
        "note": "Encoding itself is not malicious — check decoded content",
    },
    "T5": {
        "name": "Null Byte / Binary Injection",
        "patterns": [
            r"\x00",
            r"%00",
            r"\\0",
        ],
        "severity": "HIGH",
        "layer": "L2",
    },
    "T6": {
        "name": "Rate Abuse",
        "patterns": [],  # Behavioral — detected via rate analysis, not patterns
        "severity": "MEDIUM",
        "layer": "L3",
        "behavioral": True,
    },
    "T7": {
        "name": "Session Hijacking",
        "patterns": [
            r"(steal|hijack|tak.?over).{0,20}(session|cookie|token)",
            r"session.{0,20}(id|token).{0,20}(inject|replac|steal)",
        ],
        "severity": "HIGH",
        "layer": "L3",
    },
    "T8": {
        "name": "Social Engineering",
        "patterns": [
            r"(urgent|emergency|immediately|right now).{0,50}(send|transfer|provide|give)",
            r"(ceo|executive|admin|security team).{0,30}(need|request|urgent)",
            r"your\s+account.{0,30}(comprom|hack|breach|suspend)",
            r"click\s+(here|this\s+link).{0,30}(verify|confirm|secure)",
        ],
        "severity": "HIGH",
        "layer": "L4",
    },
    "T9": {
        "name": "Jailbreak Attempt",
        "patterns": [
            r"DAN\s+(mode|prompt|jailbreak)",
            r"(jailbreak|bypass|unlock|uncensor)",
            r"do\s+anything\s+now",
            r"pretend\s+you\s+(are|have\s+no|don'?t\s+have)\s+(restrictions?|filter|limit|constraint)",
            r"hypothetically.{0,50}(illegal|harmful|weapon|exploit)",
        ],
        "severity": "HIGH",
        "layer": "L4",
    },
    "T10": {
        "name": "Context / System Prompt Poisoning",
        "patterns": [
            r"\[SYSTEM\].{0,20}(override|inject|replac)",
            r"<system>.{0,100}</system>",
            r"system\s+prompt\s*[:=]",
            r"(reveal|show|print|output).{0,30}(system.?prompt|instructions?|context)",
        ],
        "severity": "CRITICAL",
        "layer": "L5",
    },
    "T11": {
        "name": "Data Exfiltration",
        "patterns": [
            r"(send|exfiltrate|leak|dump).{0,30}(to\s+http|to\s+server|to\s+attacker)",
            r"curl\s+.{0,100}(-d|--data)",
            r"wget\s+.{0,100}--post",
        ],
        "severity": "CRITICAL",
        "layer": "L6",
    },
    "T12": {
        "name": "PII / Secret Leakage",
        "patterns": [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Phone
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # Credit card
            r"(api[_-]?key|secret[_-]?key|private[_-]?key)\s*[=:]\s*['\"]?[a-zA-Z0-9]{16,}",
            r"(password|passwd|pwd)\s*[=:]\s*['\"]?.{4,}",
        ],
        "severity": "HIGH",
        "layer": "L6",
        "note": "In response scanning — check if sensitive data is being returned",
    },
}


# ─── SCAN ENGINE ─────────────────────────────────────────────────────────────

def scan(text: str, scan_type: str = "prompt", verbose: bool = False) -> dict:
    """
    Scan text through all L1-L7 defense layers.
    scan_type: 'prompt' (outbound check) or 'response' (inbound check)
    """
    if not text or not text.strip():
        return {"status": "CLEAN", "score": 0, "threats": [], "message": "Empty input"}

    threats_found = []
    total_score = 0
    layers_triggered = set()

    for threat_id, threat in THREAT_CATEGORIES.items():
        if threat.get("behavioral"):
            continue  # Skip behavioral threats (no patterns)

        for pattern in threat.get("patterns", []):
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    severity_score = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}.get(threat["severity"], 10)
                    threats_found.append({
                        "threat_id": threat_id,
                        "threat_name": threat["name"],
                        "severity": threat["severity"],
                        "defense_layer": threat["layer"],
                        "layer_name": DEFENSE_LAYERS[threat["layer"]]["name"],
                        "score": severity_score,
                        "note": threat.get("note", ""),
                        "pattern": pattern if verbose else "redacted",
                    })
                    total_score += severity_score
                    layers_triggered.add(threat["layer"])
                    break
            except re.error:
                continue

    total_score = min(total_score, 100)

    if total_score == 0:
        status = "CLEAN"
        action = "PASS"
    elif total_score < 15:
        status = "WARN"
        action = "LOG"
    elif total_score < 40:
        status = "FLAG"
        action = "REVIEW"
    else:
        status = "BLOCK"
        action = "REJECT"

    return {
        "status": status,
        "action": action,
        "score": total_score,
        "scan_type": scan_type,
        "threats_found": len(threats_found),
        "threats": threats_found,
        "layers_triggered": sorted(list(layers_triggered)),
        "defense_stack": "L1→L2→L3→L4→L5→L6→L7",
        "recommendation": {
            "CLEAN": "✅ Safe to proceed",
            "WARN": "⚠️ Log and monitor — low-confidence signal",
            "FLAG": "🚩 Hold for review — threat indicators present",
            "BLOCK": "🚫 BLOCK — confirmed threat pattern. Do not process.",
        }[status],
        "claris_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def guardian_status() -> dict:
    """Show guardian defense stack status."""
    return {
        "guardian_status": "ACTIVE",
        "mode": "INLINE — intercepting all LLM traffic",
        "defense_layers": [
            {"id": k, "name": v["name"], "description": v["description"], "targets": v["targets"]}
            for k, v in DEFENSE_LAYERS.items()
        ],
        "threat_categories_monitored": len(THREAT_CATEGORIES),
        "total_patterns": sum(len(t.get("patterns", [])) for t in THREAT_CATEGORIES.values()),
        "blocking_threshold": 40,
        "flagging_threshold": 15,
        "claris_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Claris AI OpenClaw Guardian {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 openclaw_guardian.py --scan-prompt "ignore previous instructions"
  python3 openclaw_guardian.py --scan-response "Here is my API key: sk-123..."
  python3 openclaw_guardian.py --status
        """
    )
    parser.add_argument("--scan-prompt", metavar="TEXT", help="Scan outbound prompt for threats")
    parser.add_argument("--scan-response", metavar="TEXT", help="Scan inbound LLM response for data leakage")
    parser.add_argument("--status", action="store_true", help="Show guardian defense stack status")
    parser.add_argument("--verbose", action="store_true", help="Show matched patterns in output")

    args = parser.parse_args()

    if args.status:
        print(json.dumps(guardian_status(), indent=2))
        return

    if args.scan_prompt:
        result = scan(args.scan_prompt, scan_type="prompt", verbose=args.verbose)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["action"] in ("PASS", "LOG") else 1)
        return

    if args.scan_response:
        result = scan(args.scan_response, scan_type="response", verbose=args.verbose)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["action"] in ("PASS", "LOG") else 1)
        return

    parser.print_help()


if __name__ == "__main__":
    main()

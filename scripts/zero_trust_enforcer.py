#!/usr/bin/env python3
"""
Script: zero_trust_enforcer.py
Version: V6.0
Claris AI — Defense Network
Author: August + AVARI (Unitium Mode)
Last Updated: 2026-03-10

Zero-trust network enforcement simulator and checker.
Calculates trust scores, audits architectures for zero-trust compliance,
and provides educational content on zero-trust principles.
"""

import argparse, json, sys, os, re, random
from datetime import datetime, timezone

VERSION = "V6.0"
SCRIPT_NAME = "zero_trust_enforcer"

# ─── ZERO-TRUST PRINCIPLES ────────────────────────────────────────────────────

ZT_PRINCIPLES = {
    "never_trust_always_verify": {
        "name": "Never Trust, Always Verify",
        "description": "Every access request must be authenticated and authorized, regardless of network location.",
        "keywords": ["authenticate", "verify", "mfa", "certificate", "identity", "authz", "authn"],
        "antipatterns": ["implicit trust", "trusted network", "internal only", "no auth inside"],
    },
    "least_privilege": {
        "name": "Least Privilege Access",
        "description": "Users and systems receive only the minimum access required for their function.",
        "keywords": ["minimal", "least privilege", "need to know", "scoped", "rbac", "abac"],
        "antipatterns": ["admin by default", "wildcard permissions", "root access", "full access"],
    },
    "assume_breach": {
        "name": "Assume Breach",
        "description": "Design systems assuming adversaries are already inside. Minimize blast radius.",
        "keywords": ["segment", "isolate", "blast radius", "lateral movement", "contain", "micro-segment"],
        "antipatterns": ["flat network", "fully trusted internal", "no segmentation", "open internal"],
    },
    "verify_explicitly": {
        "name": "Verify Explicitly",
        "description": "Use all available data points: identity, location, device health, service, workload, data classification.",
        "keywords": ["device health", "posture", "context-aware", "signal", "conditional access"],
        "antipatterns": ["username only", "ip-based trust", "cookie only", "single factor"],
    },
    "continuous_monitoring": {
        "name": "Continuous Monitoring",
        "description": "Log everything, detect anomalies in real-time, and continuously re-evaluate trust.",
        "keywords": ["logging", "siem", "monitoring", "alert", "anomaly", "behavioral"],
        "antipatterns": ["periodic audit only", "no logging", "no monitoring", "trust once"],
    },
}

# ─── TRUST SCORE CALCULATOR ───────────────────────────────────────────────────

def calculate_trust_score(request: dict) -> dict:
    """
    Calculate 0-100 trust score for a request.
    
    Request fields:
    - source_ip: str
    - user_agent: str
    - time_of_day: int (0-23)
    - request_rate: float (requests per second)
    - has_mfa: bool
    - device_managed: bool
    - geo_anomaly: bool (is this an unusual location?)
    - previous_violations: int
    - data_sensitivity: str (LOW|MEDIUM|HIGH|CRITICAL)
    """
    score = 50  # Start neutral
    factors = []

    # IP reputation (simulated)
    ip = request.get("source_ip", "")
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        # Internal — but zero-trust still requires verification
        score += 5
        factors.append({"factor": "internal_ip", "delta": +5, "note": "Internal IP — still requires verification"})
    elif ip == "" or ip == "unknown":
        score -= 20
        factors.append({"factor": "unknown_ip", "delta": -20, "note": "Unknown source IP — HIGH RISK"})
    else:
        factors.append({"factor": "external_ip", "delta": 0, "note": "External IP — standard verification required"})

    # MFA status
    if request.get("has_mfa"):
        score += 20
        factors.append({"factor": "mfa_verified", "delta": +20, "note": "MFA verified — strong identity signal"})
    else:
        score -= 30
        factors.append({"factor": "no_mfa", "delta": -30, "note": "No MFA — significant trust reduction"})

    # Device management
    if request.get("device_managed"):
        score += 15
        factors.append({"factor": "managed_device", "delta": +15, "note": "Corporate-managed device with posture check"})
    else:
        score -= 10
        factors.append({"factor": "unmanaged_device", "delta": -10, "note": "Unmanaged device — unknown security posture"})

    # Geographic anomaly
    if request.get("geo_anomaly"):
        score -= 25
        factors.append({"factor": "geo_anomaly", "delta": -25, "note": "Unusual location — possible account takeover"})

    # Time of day
    hour = request.get("time_of_day", 12)
    if 2 <= hour <= 5:
        score -= 10
        factors.append({"factor": "unusual_hour", "delta": -10, "note": "Unusual access time (02:00-05:00)"})

    # Request rate
    rate = request.get("request_rate", 1.0)
    if rate > 100:
        score -= 30
        factors.append({"factor": "high_rate", "delta": -30, "note": f"Suspicious request rate: {rate} rps"})
    elif rate > 20:
        score -= 10
        factors.append({"factor": "elevated_rate", "delta": -10, "note": f"Elevated request rate: {rate} rps"})

    # Previous violations
    violations = request.get("previous_violations", 0)
    if violations > 0:
        delta = min(violations * 10, 40)
        score -= delta
        factors.append({"factor": "violations_history", "delta": -delta, "note": f"{violations} previous security violations"})

    # Data sensitivity modifier
    sensitivity = request.get("data_sensitivity", "LOW")
    sensitivity_map = {"LOW": 0, "MEDIUM": -5, "HIGH": -15, "CRITICAL": -25}
    delta = sensitivity_map.get(sensitivity, 0)
    if delta:
        score += delta
        factors.append({"factor": "data_sensitivity", "delta": delta, "note": f"Accessing {sensitivity} sensitivity data"})

    # User agent check
    ua = request.get("user_agent", "")
    suspicious_ua = ["curl", "python-requests", "wget", "scanner", "bot", "exploit"]
    if any(s in ua.lower() for s in suspicious_ua):
        score -= 15
        factors.append({"factor": "suspicious_ua", "delta": -15, "note": f"Suspicious user agent: {ua}"})

    score = max(0, min(100, score))

    if score >= 80:
        decision = "ALLOW"
        risk = "LOW"
    elif score >= 60:
        decision = "ALLOW_WITH_MFA"
        risk = "MEDIUM"
    elif score >= 40:
        decision = "STEP_UP_AUTH"
        risk = "HIGH"
    else:
        decision = "DENY"
        risk = "CRITICAL"

    return {
        "trust_score": score,
        "risk_level": risk,
        "decision": decision,
        "factors": factors,
        "recommendation": {
            "ALLOW": "Trust score sufficient. Grant access with standard logging.",
            "ALLOW_WITH_MFA": "Acceptable score but require MFA step-up before granting access.",
            "STEP_UP_AUTH": "Low trust score. Require additional verification (device cert + MFA + manager approval).",
            "DENY": "Trust score too low. Deny access. Alert security team. Consider account lockout.",
        }[decision],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── ARCHITECTURE AUDITOR ─────────────────────────────────────────────────────

def audit_architecture(description: str) -> dict:
    """Check an architecture description for zero-trust compliance."""
    desc_lower = description.lower()
    results = []
    overall_score = 0

    for principle_id, principle in ZT_PRINCIPLES.items():
        keywords_found = [kw for kw in principle["keywords"] if kw in desc_lower]
        antipatterns_found = [ap for ap in principle["antipatterns"] if ap in desc_lower]

        if antipatterns_found:
            status = "FAIL"
            score = 0
        elif len(keywords_found) >= 2:
            status = "PASS"
            score = 20
        elif len(keywords_found) == 1:
            status = "PARTIAL"
            score = 10
        else:
            status = "MISSING"
            score = 0

        overall_score += score
        results.append({
            "principle": principle["name"],
            "status": status,
            "score": score,
            "max_score": 20,
            "keywords_found": keywords_found,
            "antipatterns_found": antipatterns_found,
            "recommendation": principle["description"] if status != "PASS" else "✓ Compliant",
        })

    grade = "A" if overall_score >= 90 else "B" if overall_score >= 70 else "C" if overall_score >= 50 else "D" if overall_score >= 30 else "F"

    return {
        "overall_score": overall_score,
        "max_score": 100,
        "grade": grade,
        "zero_trust_compliant": overall_score >= 70,
        "principle_results": results,
        "critical_gaps": [r["principle"] for r in results if r["status"] in ("FAIL", "MISSING")],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── EDUCATIONAL CONTENT ──────────────────────────────────────────────────────

LEARN_CONTENT = {
    "zero-trust": """
🔐 ZERO TRUST — Never Trust, Always Verify
===========================================

Zero Trust is a security model that eliminates the concept of a "trusted network."
In the old model: inside the firewall = trusted. That's dead.

ZERO TRUST CORE PRINCIPLES:
1. Never trust implicitly based on network location
2. Always verify identity — every request, every time
3. Assume breach — design for when (not if) the attacker is inside
4. Least privilege — give the minimum access needed
5. Continuous monitoring — log everything, detect anomalies always

REAL WORLD EXAMPLE:
OLD WAY: VPN into corporate network → access everything
ZERO TRUST: VPN + MFA + device health check + conditional access policy → access only what you need

WHY IT MATTERS FOR CLARIS/DASH:
• Dash Platform already embodies ZT via DAPI (no implicit trust, cryptographic proofs)
• OpenClaw sessions should enforce ZT: verify agent identity per call
• Federation nodes require ZT: never trust a node's patterns without Byzantine verification

IMPLEMENTING ZERO TRUST:
1. Identity: Strong auth (MFA, certs, FIDO2)
2. Device: Managed device posture checks
3. Network: Micro-segmentation, encrypt everything
4. Application: App-layer auth, not just network
5. Data: Classify data, control access by classification
6. Logging: Full visibility, behavioral analytics

ZERO TRUST DOES NOT MEAN:
• Zero trust in people (it's about technical enforcement, not culture)
• No networks (you still have networks, just don't trust them implicitly)
• Maximum friction (good ZT is nearly invisible to legitimate users)
""",
    "microsegmentation": """
🔬 MICRO-SEGMENTATION
=======================
Micro-segmentation divides networks into small zones with granular access controls.

Instead of one flat network where everything talks to everything,
micro-segmentation creates boundaries between workloads — even in the same datacenter.

WHY IT MATTERS:
• Limits lateral movement after a breach
• Attacker can't pivot from your web server to your database
• Each segment has its own access policy

EXAMPLES:
• Kubernetes network policies — pods can only talk to specified services
• AWS Security Groups — per-instance firewall rules
• VLAN segmentation — separate development/staging/production

CLARIS AI PERSPECTIVE:
• Claris scripts should be isolated from each other
• Injection guard should run in a sandboxed process
• Federation mesh nodes are a natural micro-segment
""",
    "trust-score": """
📊 TRUST SCORES — Dynamic Access Decisions
===========================================
Trust scores make access decisions dynamic, not binary.

Instead of "allowed" or "denied," you compute a contextual trust score
based on multiple signals, then decide based on score thresholds.

SIGNALS THAT AFFECT TRUST:
• Identity strength (MFA, certificate, biometric)
• Device health (patched, managed, posture check passed)
• Location (known location vs. anomaly)
• Time of day (unusual hours = lower trust)
• Behavior (request rate, typical patterns)
• Data sensitivity (higher-risk data requires higher trust)

THRESHOLDS (example):
• 80-100: ALLOW — standard access
• 60-79: ALLOW with step-up MFA
• 40-59: ALLOW with manager approval + MFA
• 0-39: DENY — alert security team

ADAPTIVE TRUST:
Trust scores should decrease during a session if behavior becomes suspicious,
even if the session started with a high score.
""",
}


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Claris AI Zero Trust Enforcer {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 zero_trust_enforcer.py --check-request '{"has_mfa": true, "device_managed": true, "request_rate": 2}'
  python3 zero_trust_enforcer.py --audit-arch "System uses VPN with no internal auth"
  python3 zero_trust_enforcer.py --learn zero-trust
        """
    )
    parser.add_argument("--check-request", metavar="JSON", help="Calculate trust score for a request (JSON)")
    parser.add_argument("--audit-arch", metavar="DESCRIPTION", help="Audit an architecture description for ZT compliance")
    parser.add_argument("--learn", metavar="TOPIC",
                        choices=list(LEARN_CONTENT.keys()),
                        help=f"Learn about zero-trust. Topics: {', '.join(LEARN_CONTENT.keys())}")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.learn:
        print(LEARN_CONTENT[args.learn])
        return

    if args.check_request:
        try:
            request = json.loads(args.check_request)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"Invalid JSON: {e}", "code": 400}))
            sys.exit(2)
        result = calculate_trust_score(request)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["decision"] in ("ALLOW", "ALLOW_WITH_MFA") else 1)
        return

    if args.audit_arch:
        result = audit_architecture(args.audit_arch)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["zero_trust_compliant"] else 1)
        return

    parser.print_help()


if __name__ == "__main__":
    main()

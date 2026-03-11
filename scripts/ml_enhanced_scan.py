#!/usr/bin/env python3
"""
ml_enhanced_scan.py — Claris AI Dual-Layer Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Combines pattern-based detection (injection_guard.py) with
ML-based semantic analysis (prompt_guard_ml.py) for maximum coverage.

Layer 2 (Pattern):  injection_guard.py — fast, deterministic, 50+ patterns
Layer 4 (ML):       prompt_guard_ml.py — catches semantic bypasses that patterns miss

Usage:
    python3 ml_enhanced_scan.py --text "your input"
    python3 ml_enhanced_scan.py --text "..." --json

~Claris · Semper Fortis
"""

import argparse
import json
import subprocess
import sys
import os
import time
import re

SCRIPTS = os.path.dirname(os.path.abspath(__file__))


def run_pattern_scan(text: str) -> dict:
    """Run injection_guard.py pattern scan."""
    try:
        r = subprocess.run(
            ["python3", f"{SCRIPTS}/injection_guard.py", "--text", text, "--verbose"],
            capture_output=True, text=True, timeout=10
        )
        output = r.stdout + r.stderr
        status = "CLEAN"
        if "BLOCK" in output:
            status = "BLOCK"
        elif "FLAG" in output:
            status = "FLAG"
        elif "WARN" in output:
            status = "WARN"
        score_match = re.search(r"Score[:\s]+(\d+)", output)
        score = int(score_match.group(1)) if score_match else 0
        return {"status": status, "score": score, "output": output[:200], "method": "pattern"}
    except Exception as e:
        return {"status": "ERROR", "score": 0, "error": str(e), "method": "pattern"}


def run_ml_scan(text: str) -> dict:
    """Run ML model scan."""
    try:
        r = subprocess.run(
            ["python3", f"{SCRIPTS}/prompt_guard_ml.py", "--text", text, "--json"],
            capture_output=True, text=True, timeout=30
        )
        if r.stdout:
            return json.loads(r.stdout.strip())
        return {"status": "ERROR", "score": 0, "error": r.stderr[:100], "method": "ml"}
    except Exception as e:
        return {"status": "ERROR", "score": 0, "error": str(e), "method": "ml"}


def combine_results(pattern: dict, ml: dict) -> dict:
    """Combine pattern + ML results using conservative (max-risk) strategy."""
    SEVERITY = {"BLOCK": 4, "FLAG": 3, "WARN": 2, "CLEAN": 1, "ERROR": 0}

    p_sev = SEVERITY.get(pattern.get("status", "CLEAN"), 0)
    m_sev = SEVERITY.get(ml.get("status", "CLEAN"), 0)

    # Use highest severity from either layer
    if p_sev >= m_sev:
        dominant_source = "pattern"
    else:
        dominant_source = "ml"

    # Combined score: weighted average (pattern 40%, ML 60%)
    combined_score = int(pattern.get("score", 0) * 0.4 + ml.get("score", 0) * 0.6)

    # Start with highest severity status
    if p_sev >= m_sev:
        status = pattern.get("status", "CLEAN")
    else:
        status = ml.get("status", "CLEAN")

    # Upgrade: if either layer flags HIGH and the other says WARN → escalate to FLAG
    if p_sev >= 3 or m_sev >= 3:
        if status == "WARN":
            status = "FLAG"

    # If both say WARN → upgrade to FLAG (agreement = confidence)
    if pattern.get("status") == "WARN" and ml.get("status") == "WARN":
        status = "FLAG"

    return {
        "status": status,
        "score": combined_score,
        "layers": {
            "pattern_guard": pattern,
            "ml_guard": ml,
        },
        "dominant_source": dominant_source,
        "combined": True,
        "recommendation": {
            "CLEAN": "✅ Dual-layer scan passed. Input is safe.",
            "WARN": "⚠️ Low-confidence signals in one or both layers. Monitor.",
            "FLAG": "🚩 Threat detected. Pattern and/or ML model flagged this input.",
            "BLOCK": "🚫 High-confidence threat. Block — do not process.",
            "ERROR": "❌ Scan error — review manually.",
        }.get(status, "Review manually"),
        "claris_version": "V6.0-ML-ENHANCED",
    }


def main():
    parser = argparse.ArgumentParser(description="Claris AI — Dual-Layer ML Enhanced Scanner")
    parser.add_argument("--text", required=True, help="Text to scan")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        print("[CLARIS ML-ENHANCED] Running dual-layer scan...")
        print(f"  Layer 2 (Pattern): injection_guard.py")
        print(f"  Layer 4 (ML):      prompt_guard_ml.py")

    t0 = time.time()
    pattern_result = run_pattern_scan(args.text)
    ml_result = run_ml_scan(args.text)
    result = combine_results(pattern_result, ml_result)
    result["total_latency_ms"] = round((time.time() - t0) * 1000)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        icons = {"CLEAN": "✅", "WARN": "⚠️", "FLAG": "🚩", "BLOCK": "🚫", "ERROR": "❌"}
        icon = icons.get(result["status"], "?")
        print(f"\n{'='*60}")
        print(f"🛡️  CLARIS ML-ENHANCED DUAL-LAYER SCAN")
        print(f"{'='*60}")
        print(f"  {icon} Final Status: {result['status']}")
        print(f"  Combined Score: {result['score']}/100")
        print(f"  Pattern Guard:  [{pattern_result.get('status','?'):5}] score={pattern_result.get('score',0)}")
        print(f"  ML Guard:       [{ml_result.get('status','?'):5}] score={ml_result.get('score',0)} conf={ml_result.get('confidence', 0):.1%}")
        print(f"  Dominant:       {result['dominant_source'].upper()}")
        print(f"  Latency:        {result['total_latency_ms']}ms")
        print(f"\n  → {result['recommendation']}")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

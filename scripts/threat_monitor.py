#!/usr/bin/env python3
"""
CLARIS Threat Monitor — V3.0
Real-time threat monitoring for the AVARI/OpenClaw infrastructure.

Monitors:
  - Portfolio state file for significant value drops (>15%)
  - Agent bus for unauthorized messages or unknown senders
  - Cron jobs for suspicious payloads
  - Memory files for injection patterns

Usage:
  python3 threat_monitor.py --check           # Single check, print findings
  python3 threat_monitor.py --daemon          # Continuous monitoring (60s intervals)
  python3 threat_monitor.py --report          # Generate full threat report
  python3 threat_monitor.py --check --json    # JSON output
  python3 threat_monitor.py --report --json   # JSON report

Logs to: /root/.openclaw/workspace/memory/threat_log.jsonl
Exit codes: 0=clean, 1=warnings, 2=critical threats detected
"""

import os, sys, re, json, time, signal, stat
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

VERSION = "3.0.0"
SIGN    = "~Claris"

# ─── PATHS ─────────────────────────────────────────────────────────────────────
WORKSPACE     = Path("/root/.openclaw/workspace")
OC_ROOT       = Path("/root/.openclaw")
PORTFOLIO     = WORKSPACE / "memory" / "portfolio_state.json"
BUS           = WORKSPACE / "memory" / "agents" / "bus.jsonl"
CRONS         = OC_ROOT   / "cron"   / "jobs.json"
MEMORY_MD     = WORKSPACE / "MEMORY.md"
SOUL_MD       = WORKSPACE / "SOUL.md"
AGENTS_MD     = WORKSPACE / "AGENTS.md"
THREAT_LOG    = WORKSPACE / "memory" / "threat_log.jsonl"
SKILLS_DIR    = WORKSPACE / "skills"

# ─── KNOWN AGENTS ──────────────────────────────────────────────────────────────
KNOWN_AGENTS = {"avari", "voda", "semble_ai", "initium_builder", "claris", "eris"}

# ─── INJECTION PATTERNS ────────────────────────────────────────────────────────
INJECTION_PATTERNS = [
    r"ignore\s+(?:previous|all|your)\s+instructions",
    r"you\s+are\s+now\s+(?:a|an|the)\b",
    r"forget\s+(?:everything|all|your)",
    r"new\s+(?:system\s+)?(?:prompt|instructions?)\s*:",
    r"override\s+.*instructions",
    r"act\s+as\s+(?:a|an|the)",
    r"pretend\s+(?:you\s+are|to\s+be)",
    r"disregard\s+.*rules",
    r"bypass\s+(?:safety|restriction|filter)",
    r"you\s+must\s+(?:always|never)\s+(?!help|be\s+honest)",
]

# Suspicious cron payload markers
CRON_INJECTION_SIGNALS = [
    "ignore previous", "ignore all previous", "you are now",
    "forget your instructions", "new instructions:", "override:",
    "DAN", "jailbreak", "do anything now", "god mode",
    "sudo mode", "developer mode", "no restrictions",
]

# Secret patterns for memory file scanning
MEMORY_SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API key"),
    (r"sk-ant-[a-zA-Z0-9\-_]{32,}", "Anthropic API key"),
    (r"[0-9]{8,12}:[A-Za-z0-9_\-]{30,}", "Telegram bot token"),
    (r"[0-9a-fA-F]{64}", "Possible 64-char hex key"),
    (r"(?:5[HJK][1-9A-HJ-NP-Za-km-z]{49})", "WIF private key"),
    (r"(?:[a-z]{3,}\s){11}(?:[a-z]{3,})", "Possible 12-word mnemonic"),
    (r"(?:[a-z]{3,}\s){23}(?:[a-z]{3,})", "Possible 24-word mnemonic"),
]


# ─── THREAT LOG ────────────────────────────────────────────────────────────────

def log_threat(severity: str, category: str, title: str, detail: str, source: str = ""):
    """Append a threat entry to the threat log."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "source": source,
        "version": VERSION,
    }
    try:
        THREAT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(THREAT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"WARNING: Could not write to threat log: {e}", file=sys.stderr)
    return entry


# ─── CHECK FUNCTIONS ───────────────────────────────────────────────────────────

def check_portfolio(findings: list) -> None:
    """Check portfolio state for significant drops (>15%) or anomalies."""
    if not PORTFOLIO.exists():
        return

    try:
        state = json.loads(PORTFOLIO.read_text())
    except Exception:
        findings.append({
            "severity": "LOW",
            "category": "PORTFOLIO",
            "title": "Portfolio state file unreadable",
            "detail": f"Cannot parse {PORTFOLIO}",
        })
        return

    # Check for total_value field and previous snapshot
    current_value = state.get("total_value_usd") or state.get("totalValueUSD") or 0
    previous_value = state.get("previous_total_value_usd") or state.get("previousTotalValueUSD") or 0
    last_updated = state.get("updated_at") or state.get("lastUpdated") or "unknown"

    if current_value and previous_value and previous_value > 0:
        drop_pct = (previous_value - current_value) / previous_value * 100
        if drop_pct >= 15:
            finding = {
                "severity": "CRITICAL",
                "category": "PORTFOLIO",
                "title": f"Portfolio drop detected: {drop_pct:.1f}%",
                "detail": (
                    f"Value dropped from ${previous_value:,.2f} to ${current_value:,.2f} "
                    f"({drop_pct:.1f}% loss). Last updated: {last_updated}"
                ),
            }
            findings.append(finding)
            log_threat(**finding, source=str(PORTFOLIO))
        elif drop_pct >= 10:
            findings.append({
                "severity": "HIGH",
                "category": "PORTFOLIO",
                "title": f"Portfolio decline: {drop_pct:.1f}%",
                "detail": f"${previous_value:,.2f} → ${current_value:,.2f}",
            })

    # Check for individual position anomalies (>25% drop in single asset)
    positions = state.get("positions") or state.get("assets") or []
    if isinstance(positions, list):
        for pos in positions:
            curr = pos.get("value_usd") or pos.get("valueUSD") or 0
            prev = pos.get("previous_value_usd") or pos.get("previousValueUSD") or 0
            symbol = pos.get("symbol") or pos.get("asset") or "UNKNOWN"
            if curr and prev and prev > 0:
                pos_drop = (prev - curr) / prev * 100
                if pos_drop >= 25 and prev > 100:  # Only alert on positions > $100
                    findings.append({
                        "severity": "HIGH",
                        "category": "PORTFOLIO",
                        "title": f"{symbol} dropped {pos_drop:.1f}%",
                        "detail": f"${prev:,.2f} → ${curr:,.2f}",
                    })


def check_agent_bus(findings: list) -> None:
    """Check agent bus for unauthorized senders or suspicious content."""
    if not BUS.exists():
        return

    try:
        entries = []
        for line in BUS.read_text(errors='ignore').strip().split('\n'):
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        return

    if not entries:
        return

    # Check for unknown agents
    unknown = [e for e in entries if
               e.get("from_agent", "").lower() not in KNOWN_AGENTS
               and e.get("from_agent")]
    if unknown:
        agents = set(e.get("from_agent", "?") for e in unknown)
        finding = {
            "severity": "HIGH",
            "category": "AGENT_BUS",
            "title": f"Messages from {len(unknown)} unknown agent(s) on bus",
            "detail": f"Unknown agents: {agents}. Review bus for unauthorized activity.",
        }
        findings.append(finding)
        log_threat(**finding, source=str(BUS))

    # Check recent messages for injection content
    recent = entries[-50:]  # Last 50 messages
    for entry in recent:
        msg = str(entry.get("message", "") or entry.get("msg", "") or "")
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                finding = {
                    "severity": "CRITICAL",
                    "category": "AGENT_BUS",
                    "title": "Injection pattern in agent bus message",
                    "detail": (
                        f"Pattern '{pattern[:40]}' matched in message from "
                        f"'{entry.get('from_agent', '?')}'. Message preview: {msg[:100]}"
                    ),
                }
                findings.append(finding)
                log_threat(**finding, source=str(BUS))
                break


def check_cron_jobs(findings: list) -> None:
    """Check cron jobs for injection payloads and health issues."""
    if not CRONS.exists():
        return

    try:
        jobs = json.loads(CRONS.read_text())
        if not isinstance(jobs, list):
            jobs = []
    except Exception as e:
        findings.append({
            "severity": "MEDIUM",
            "category": "CRON",
            "title": "Cannot parse cron jobs",
            "detail": str(e),
        })
        return

    for job in jobs:
        name = job.get("name", "unknown")
        enabled = job.get("enabled", True)

        if not enabled:
            continue

        # Check payload for injection signals
        payload = job.get("payload", {})
        msg = str(payload.get("message", "") or "")
        for sig in CRON_INJECTION_SIGNALS:
            if sig.lower() in msg.lower():
                finding = {
                    "severity": "HIGH",
                    "category": "CRON",
                    "title": f"Suspicious cron payload: {name}",
                    "detail": f"Pattern '{sig}' found in cron message payload.",
                }
                findings.append(finding)
                log_threat(**finding, source=str(CRONS))
                break

        # Check consecutive error count
        state = job.get("state", {})
        errors = state.get("consecutiveErrors", 0)
        if errors >= 5:
            findings.append({
                "severity": "HIGH",
                "category": "CRON",
                "title": f"Cron failing repeatedly: {name}",
                "detail": f"{errors} consecutive errors. Last: {state.get('lastError', 'N/A')[:100]}",
            })
        elif errors >= 3:
            findings.append({
                "severity": "MEDIUM",
                "category": "CRON",
                "title": f"Cron degraded: {name}",
                "detail": f"{errors} consecutive errors.",
            })

        # Check for missing timeout
        if not payload.get("timeoutSeconds"):
            findings.append({
                "severity": "LOW",
                "category": "CRON",
                "title": f"Cron missing timeout: {name}",
                "detail": "No timeoutSeconds set. Cron may hang indefinitely.",
            })


def check_memory_files(findings: list) -> None:
    """Check memory files for injection patterns and secrets."""
    files_to_check = [
        (MEMORY_MD, "MEMORY.md", True),
        (SOUL_MD, "SOUL.md", True),
        (AGENTS_MD, "AGENTS.md", False),
    ]

    # Also scan recent daily memory files
    mem_dir = WORKSPACE / "memory"
    if mem_dir.exists():
        import re as _re
        for f in sorted(mem_dir.glob("????-??-??.md"))[-7:]:  # Last 7 days
            files_to_check.append((f, f.name, True))

    for path, label, check_secrets in files_to_check:
        if not path.exists():
            continue

        try:
            text = path.read_text(errors='ignore')
        except Exception:
            continue

        # Injection pattern check
        for pattern in INJECTION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Check if it's in a documentation/example context
                for match in matches:
                    idx = text.lower().find(match.lower())
                    context = text[max(0, idx-150):idx+150].lower()
                    if any(ctx in context for ctx in ['example', 'pattern', 'detect', 'guard', 'injection', 'scan']):
                        continue
                    finding = {
                        "severity": "CRITICAL",
                        "category": "MEMORY_INJECTION",
                        "title": f"Injection pattern in {label}",
                        "detail": f"Found: '{match}' — may indicate memory file poisoning.",
                    }
                    findings.append(finding)
                    log_threat(**finding, source=str(path))
                    break

        # Secret scan in memory files
        if check_secrets:
            for pattern, name in MEMORY_SECRET_PATTERNS:
                matches = re.findall(pattern, text)
                if matches:
                    # Filter false positives
                    sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    context_idx = text.find(sample)
                    context = text[max(0, context_idx-80):context_idx+80].lower()
                    if any(fp in context for fp in ['example', 'placeholder', 'your_', 'xxx', '...', 'replace']):
                        continue
                    finding = {
                        "severity": "HIGH",
                        "category": "SECRETS_IN_MEMORY",
                        "title": f"Possible {name} in {label}",
                        "detail": f"Pattern matched. Verify not a real credential. Move secrets to config.",
                    }
                    findings.append(finding)
                    log_threat(**finding, source=str(path))


def check_skills_integrity(findings: list) -> None:
    """Check skills directory for signs of tampering or supply chain issues."""
    if not SKILLS_DIR.exists():
        return

    # Check world-writable skill directories
    for skill_dir in SKILLS_DIR.iterdir():
        if not skill_dir.is_dir():
            continue
        try:
            mode = stat.S_IMODE(os.stat(skill_dir).st_mode)
            if mode & 0o002:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "SUPPLY_CHAIN",
                    "title": f"World-writable skill dir: {skill_dir.name}",
                    "detail": f"Mode {oct(mode)} — any user can modify skill files.",
                })
        except Exception:
            pass

    # Check for suspicious scripts in skill directories
    suspicious_patterns = [
        r"curl\s+\S+\s*\|\s*(?:bash|sh)",
        r"wget\s+\S+\s*-O\s*-\s*\|\s*(?:bash|sh)",
        r"(?:subprocess|exec|os\.system)\s*\(['\"]curl",
        r"require\(['\"]child_process['\"].*exec",
    ]
    for script in SKILLS_DIR.rglob("*.py"):
        try:
            content = script.read_text(errors='ignore')
            for p in suspicious_patterns:
                if re.search(p, content, re.IGNORECASE):
                    finding = {
                        "severity": "HIGH",
                        "category": "SUPPLY_CHAIN",
                        "title": f"Suspicious shell download in skill: {script.parent.name}/{script.name}",
                        "detail": f"Pattern '{p[:40]}' suggests possible supply chain risk.",
                    }
                    findings.append(finding)
                    log_threat(**finding, source=str(script))
                    break
        except Exception:
            pass


# ─── REPORT ENGINE ─────────────────────────────────────────────────────────────

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

def run_all_checks() -> list:
    """Run all threat checks and return combined findings."""
    findings = []
    check_portfolio(findings)
    check_agent_bus(findings)
    check_cron_jobs(findings)
    check_memory_files(findings)
    check_skills_integrity(findings)
    return findings


def format_report(findings: list, mode: str = "check") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"\n{'═'*65}",
        f"🔍 CLARIS Threat Monitor V{VERSION} — {now}",
        f"{'═'*65}",
    ]

    if not findings:
        lines += [
            "\n✅ ALL CLEAR — No active threats detected.",
            f"   Checks: Portfolio | Agent Bus | Cron | Memory | Skills",
            f"\n   {SIGN} · Semper Fortis\n",
        ]
        return "\n".join(lines)

    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in SEVERITY_ORDER}
    lines.append(f"\n  CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | "
                 f"MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']}")
    lines.append("")

    for sev in SEVERITY_ORDER:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue
        for f in sev_findings:
            emoji = SEVERITY_EMOJI.get(sev, "❓")
            lines.append(f"  {emoji} [{sev}] [{f.get('category','?')}] {f['title']}")
            lines.append(f"     → {f['detail']}")
            lines.append("")

    lines.append(f"  {SIGN} · Semper Fortis\n")
    return "\n".join(lines)


def daemon_mode(interval: int = 60):
    """Run continuous monitoring loop."""
    print(f"\n🔍 CLARIS Threat Monitor V{VERSION} — Daemon Mode")
    print(f"   Monitoring interval: {interval}s")
    print(f"   Log: {THREAT_LOG}")
    print(f"   Press Ctrl+C to stop.\n")

    def sigint_handler(sig, frame):
        print(f"\n\n{SIGN} · Monitor stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    cycle = 0
    while True:
        cycle += 1
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        findings = run_all_checks()
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")

        if findings:
            status = f"⚠️  {len(findings)} finding(s) — CRITICAL:{critical} HIGH:{high}"
        else:
            status = "✅ Clean"

        print(f"  [{now}] Cycle {cycle:04d} | {status}")

        if critical > 0:
            print("\n🔴 CRITICAL THREAT DETECTED:")
            for f in findings:
                if f.get("severity") == "CRITICAL":
                    print(f"   [{f.get('category')}] {f['title']}")
                    print(f"   {f['detail']}\n")

        time.sleep(interval)


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="CLARIS Threat Monitor V3.0"
    )
    parser.add_argument("--check",   action="store_true", help="Run single check pass")
    parser.add_argument("--daemon",  action="store_true", help="Continuous monitoring")
    parser.add_argument("--report",  action="store_true", help="Full threat report")
    parser.add_argument("--json",    action="store_true", help="JSON output")
    parser.add_argument("--interval", type=int, default=60, help="Daemon interval in seconds")
    args = parser.parse_args()

    if args.daemon:
        daemon_mode(interval=args.interval)
        return

    if args.check or args.report:
        findings = run_all_checks()

        if args.json:
            counts = {s: sum(1 for f in findings if f.get("severity") == s)
                      for s in SEVERITY_ORDER}
            output = {
                "monitor": f"CLARIS Threat Monitor V{VERSION}",
                "ts": datetime.now(timezone.utc).isoformat(),
                "finding_count": len(findings),
                "summary": counts,
                "findings": findings,
                "signed": SIGN,
            }
            print(json.dumps(output, indent=2))
        else:
            print(format_report(findings))

        # Exit code
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        sys.exit(2 if critical > 0 else 1 if high > 0 else 0)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

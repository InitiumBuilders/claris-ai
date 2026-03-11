#!/usr/bin/env python3
"""
CLARIS Security Scanner — Active System Defense
Scans the AVARI system environment for vulnerabilities, misconfigurations,
exposed secrets, and anomalies. Runs on demand or as part of weekly security review.

Usage:
  python3 claris_scan.py --full          # Full system scan
  python3 claris_scan.py --code <path>   # Code review for a file or directory
  python3 claris_scan.py --secrets       # Scan for exposed credentials
  python3 claris_scan.py --ports         # Network exposure audit
  python3 claris_scan.py --quick         # Fast health check
"""
import os, re, json, subprocess, argparse, sys
from pathlib import Path
from datetime import datetime, timezone

WORKSPACE = Path("/root/.openclaw/workspace")
FINDINGS  = []

RISK_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def add_finding(severity: str, category: str, title: str, detail: str, path: str = ""):
    FINDINGS.append({
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "path": str(path),
        "ts": datetime.now(timezone.utc).isoformat(),
    })

# ─── SECRET PATTERNS ──────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    (r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',    "API_KEY"),
    (r'(?i)(secret[_\-]?key|secretkey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "SECRET_KEY"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',         "HARDCODED_PASSWORD"),
    (r'(?i)(private[_\-]?key)\s*[=:]\s*["\']?([A-Za-z0-9+/=]{32,})',       "PRIVATE_KEY"),
    (r'(?i)(bearer\s+)([A-Za-z0-9_\-\.]{30,})',                             "BEARER_TOKEN"),
    (r'sk-[A-Za-z0-9]{20,}',                                                 "OPENAI_KEY"),
    (r'(?i)AKIA[0-9A-Z]{16}',                                                "AWS_ACCESS_KEY"),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----',                              "PRIVATE_KEY_PEM"),
    (r'(?i)(mnemonic|seed\s+phrase)\s*[=:]\s*["\']?([a-z\s]{20,})',         "MNEMONIC_PHRASE"),
    (r'xprv[A-Za-z0-9]{100,}',                                               "XPRV_KEY"),
]

# ─── CODE VULNERABILITY PATTERNS ──────────────────────────────────────────────
CODE_VULNS = {
    "SQL_INJECTION": {
        "patterns": [r'execute\(["\'].*%s.*["\']', r'\.format\(.*query\b', r'f["\'].*SELECT.*\{'],
        "severity": "CRITICAL", "languages": [".py", ".js", ".ts"]
    },
    "COMMAND_INJECTION": {
        "patterns": [r'os\.system\(', r'subprocess.*shell=True', r'eval\(.*input', r'exec\(.*input'],
        "severity": "CRITICAL", "languages": [".py"]
    },
    "PATH_TRAVERSAL": {
        "patterns": [r'open\(.*\+.*\)', r'readFile\(.*\+', r'\.\.\/',],
        "severity": "HIGH", "languages": [".py", ".js", ".ts"]
    },
    "XSS": {
        "patterns": [r'innerHTML\s*=', r'document\.write\(', r'dangerouslySetInnerHTML'],
        "severity": "HIGH", "languages": [".js", ".ts", ".jsx", ".tsx"]
    },
    "HARDCODED_SECRET_INLINE": {
        "patterns": [p[0] for p in SECRET_PATTERNS[:6]],
        "severity": "CRITICAL", "languages": [".py", ".js", ".ts", ".env", ".json"]
    },
    "EVAL_USAGE": {
        "patterns": [r'\beval\s*\(', r'\bexec\s*\('],
        "severity": "HIGH", "languages": [".py", ".js", ".ts"]
    },
    "NOSQL_INJECTION": {
        "patterns": [r'\$where\s*:', r'\$regex\s*:', r'find\(\{.*req\.(body|query|params)'],
        "severity": "HIGH", "languages": [".js", ".ts"]
    },
    "SSRF_RISK": {
        "patterns": [r'requests\.get\(.*input', r'fetch\(.*req\.(body|query|params)', r'urllib.*open\(.*input'],
        "severity": "HIGH", "languages": [".py", ".js", ".ts"]
    },
    "INSECURE_RANDOMNESS": {
        "patterns": [r'\brandom\.(random|randint|choice)\b.*\b(token|secret|key|password)\b'],
        "severity": "MEDIUM", "languages": [".py"]
    },
    "DEBUG_LEFTOVERS": {
        "patterns": [r'\bconsole\.log\(.*password', r'\bprint\(.*password', r'\bprint\(.*secret', r'\bdebug\s*=\s*True\b'],
        "severity": "MEDIUM", "languages": [".py", ".js", ".ts"]
    },
}

SKIP_DIRS  = {".git", "node_modules", "__pycache__", ".next", "dist", "build", ".venv", "venv"}
SKIP_FILES = {".pyc", ".min.js", ".map", ".lock", ".woff", ".woff2", ".ttf", ".png", ".jpg", ".gif"}

def scan_file_for_secrets(filepath: Path):
    try:
        content = filepath.read_text(errors="ignore")
        for pattern, label in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                # Skip .env.example and test files
                if "example" in str(filepath).lower() or "test" in str(filepath).lower():
                    continue
                add_finding("CRITICAL", "EXPOSED_SECRET",
                             f"{label} found in {filepath.name}",
                             f"Pattern: {pattern[:40]} | Match preview: {match.group()[:30]}...",
                             filepath)
    except Exception:
        pass

def scan_file_for_vulns(filepath: Path):
    ext = filepath.suffix.lower()
    try:
        content = filepath.read_text(errors="ignore")
        lines   = content.splitlines()
        for vuln_name, config in CODE_VULNS.items():
            if config.get("languages") and ext not in config["languages"]:
                continue
            for pattern in config["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        add_finding(config["severity"], "CODE_VULNERABILITY",
                                     f"{vuln_name} in {filepath.name}:{i}",
                                     f"Line {i}: {line.strip()[:100]}",
                                     filepath)
    except Exception:
        pass

def scan_directory(base: Path, scan_secrets: bool = True, scan_code: bool = True):
    scanned = 0
    for filepath in base.rglob("*"):
        if filepath.is_dir():
            continue
        if any(part in SKIP_DIRS for part in filepath.parts):
            continue
        if filepath.suffix in SKIP_FILES:
            continue
        if filepath.stat().st_size > 2_000_000:  # skip >2MB
            continue
        scanned += 1
        if scan_secrets:
            scan_file_for_secrets(filepath)
        if scan_code and filepath.suffix in {".py",".js",".ts",".tsx",".jsx"}:
            scan_file_for_vulns(filepath)
    return scanned

def check_file_permissions():
    """Check critical files for over-permissive access."""
    critical_paths = [
        WORKSPACE / ".env",
        WORKSPACE / "dev-setup",
        Path("/root/.openclaw/openclaw.json"),
        Path("/root/.ssh"),
    ]
    for p in critical_paths:
        if p.exists():
            mode = oct(p.stat().st_mode)[-3:]
            if p.is_file() and mode not in ("600", "400"):
                add_finding("HIGH", "PERMISSIONS",
                             f"Overly permissive file: {p.name} ({mode})",
                             f"Expected 600/400, got {mode}. Anyone with system access can read this.",
                             p)
            elif p.is_dir() and mode[1:] not in ("00",):
                add_finding("MEDIUM", "PERMISSIONS",
                             f"Permissive directory: {p.name} ({mode})",
                             f"Sensitive directory is group/world accessible.",
                             p)

def check_env_file():
    """Check .env files aren't committed to git."""
    for env_file in WORKSPACE.rglob(".env"):
        if "example" in env_file.name.lower():
            continue
        gitignore = env_file.parent / ".gitignore"
        if gitignore.exists():
            gi_content = gitignore.read_text(errors="ignore")
            if ".env" not in gi_content:
                add_finding("HIGH", "GIT_EXPOSURE",
                             f".env not in .gitignore: {env_file.parent.name}",
                             "This .env file may be committed to git. Add '.env' to .gitignore.",
                             env_file)
        else:
            add_finding("MEDIUM", "GIT_EXPOSURE",
                         f"No .gitignore found near {env_file.name}",
                         "Missing .gitignore — .env could be committed accidentally.",
                         env_file.parent)

def network_exposure():
    """Check for listening ports and external exposure."""
    try:
        result = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=10)
        lines = result.stdout.splitlines()
        for line in lines[1:]:
            if "0.0.0.0" in line or "*:" in line:
                parts = line.split()
                addr = next((p for p in parts if "0.0.0.0:" in p or "*:" in p), "")
                port = addr.split(":")[-1] if ":" in addr else "?"
                risky_ports = {"22": "SSH", "3000": "Node app", "5432": "PostgreSQL",
                               "3306": "MySQL", "6379": "Redis", "27017": "MongoDB"}
                svc = risky_ports.get(port, "")
                sev = "HIGH" if port in risky_ports else "INFO"
                if port not in ("80", "443", ""):
                    add_finding(sev, "NETWORK_EXPOSURE",
                                 f"Port {port} ({svc}) listening on all interfaces",
                                 f"This port is accessible externally: {line.strip()[:80]}",
                                 "network")
    except Exception as e:
        add_finding("INFO", "NETWORK", "Could not check network exposure", str(e))

def generate_report(scan_type: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings_by_sev = {}
    for f in FINDINGS:
        s = f["severity"]
        findings_by_sev.setdefault(s, []).append(f)

    total = len(FINDINGS)
    critical = len(findings_by_sev.get("CRITICAL", []))
    high     = len(findings_by_sev.get("HIGH", []))
    medium   = len(findings_by_sev.get("MEDIUM", []))

    if critical > 0:   overall = "🔴 CRITICAL"
    elif high > 0:     overall = "🟠 HIGH RISK"
    elif medium > 0:   overall = "🟡 MEDIUM RISK"
    elif total > 0:    overall = "🟢 LOW RISK"
    else:              overall = "✅ CLEAN"

    lines = [
        f"# CLARIS Security Report — {scan_type}",
        f"*{now}*",
        "",
        f"## Overall Status: {overall}",
        f"Critical: {critical} | High: {high} | Medium: {medium} | Total: {total}",
        "",
    ]

    if not FINDINGS:
        lines.append("✅ No security findings. System appears clean.")
        return "\n".join(lines)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_findings = findings_by_sev.get(sev, [])
        if not sev_findings:
            continue
        emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}.get(sev,"•")
        lines.append(f"## {emoji} {sev} ({len(sev_findings)})")
        lines.append("")
        for f in sev_findings[:15]:
            lines.append(f"**{f['title']}**")
            lines.append(f"  {f['detail']}")
            if f["path"] and f["path"] != "network":
                lines.append(f"  📄 {f['path']}")
            lines.append("")

    lines += [
        "---",
        "",
        "## CLARIS Recommendation",
        "1. Address CRITICAL findings immediately — these are active vulnerabilities",
        "2. HIGH findings should be resolved this sprint",
        "3. MEDIUM findings: schedule for next cleanup cycle",
        "4. Run `--full` scan weekly, `--quick` daily",
    ]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full",    action="store_true", help="Full system scan")
    parser.add_argument("--code",    metavar="PATH", help="Code review path")
    parser.add_argument("--secrets", action="store_true", help="Secrets scan only")
    parser.add_argument("--ports",   action="store_true", help="Network exposure only")
    parser.add_argument("--quick",   action="store_true", help="Fast health check")
    parser.add_argument("--json",    action="store_true", help="JSON output")
    args = parser.parse_args()

    scan_type = "QUICK"
    if args.full:
        scan_type = "FULL"
        print("🔍 CLARIS: Running full system scan...")
        scanned = scan_directory(WORKSPACE)
        check_file_permissions()
        check_env_file()
        network_exposure()
        print(f"   Scanned {scanned} files")
    elif args.code:
        scan_type = f"CODE: {args.code}"
        p = Path(args.code)
        if p.is_file():
            scan_file_for_secrets(p); scan_file_for_vulns(p)
        else:
            scan_directory(p)
    elif args.secrets:
        scan_type = "SECRETS"
        scan_directory(WORKSPACE, scan_secrets=True, scan_code=False)
        check_env_file()
    elif args.ports:
        scan_type = "NETWORK"
        network_exposure()
    else:  # quick
        check_file_permissions()
        check_env_file()
        network_exposure()

    if args.json:
        print(json.dumps({"scan_type": scan_type, "findings": FINDINGS}, indent=2))
    else:
        print(generate_report(scan_type))

    # Exit 0=clean, 1=findings present
    sys.exit(0 if not FINDINGS else 1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
vibe_coder_guard.py — Claris AI V6.1 Vibe Coder Security Guard
──────────────────────────────────────────────────────────────
Enforces the 30 Vibe Coder Security Rules on code and configs.
Built from the rules shared by August James, March 12 2026.

"Ship fast. But ship secure."

Usage:
  python3 vibe_coder_guard.py --scan <file_or_dir>
  python3 vibe_coder_guard.py --scan . --ext .js,.ts,.tsx,.jsx,.py
  python3 vibe_coder_guard.py --rule 01
  python3 vibe_coder_guard.py --list
  python3 vibe_coder_guard.py --check-headers <url>
"""

import os
import re
import sys
import json
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
_SELF_DIR   = os.path.dirname(os.path.abspath(__file__))
_SKILL_DIR  = os.path.dirname(_SELF_DIR)
_DATA_DIR   = os.path.join(_SKILL_DIR, "data")
_SCAN_LOG   = os.path.join(_DATA_DIR, "vibe_coder_scan.jsonl")
os.makedirs(_DATA_DIR, exist_ok=True)

# ── Severity levels ───────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

# ── The 30 Rules — Pattern Engine ─────────────────────────────────────────────
RULES = [
  {
    "id": "01",
    "name": "No Sensitive Data in localStorage",
    "category": "Storage",
    "severity": CRITICAL,
    "short": "Never store tokens/sessions/credentials in localStorage.",
    "patterns": [
      r"localStorage\.setItem\s*\(\s*['\"].*?(token|auth|session|key|secret|password|credential|jwt|bearer)",
      r"localStorage\[.*?(token|auth|session|secret|password)\]",
    ],
    "fix": "Use httpOnly cookies for sensitive data instead of localStorage.",
    "rule_num": 1,
  },
  {
    "id": "02",
    "name": "Disable Directory Listing",
    "category": "Server Config",
    "severity": HIGH,
    "short": "Server must have directory listing disabled.",
    "patterns": [
      r"autoindex\s+on",
      r"Options\s+\+?Indexes",
    ],
    "fix": "Set 'autoindex off' (nginx) or 'Options -Indexes' (Apache).",
    "rule_num": 2,
  },
  {
    "id": "03",
    "name": "Regenerate Session ID After Login",
    "category": "Sessions",
    "severity": HIGH,
    "short": "Session must be regenerated after login to prevent fixation.",
    "patterns": [],  # Structural check — checked via absence of regenerate()
    "hints": [
      "Search auth routes for req.session.regenerate() after successful login.",
      "No pattern to block — this is a missing-code detection.",
    ],
    "fix": "Call req.session.regenerate() after successful authentication.",
    "rule_num": 3,
  },
  {
    "id": "04",
    "name": "Content Security Policy Required",
    "category": "HTTP Headers",
    "severity": HIGH,
    "short": "CSP headers must be set on every page.",
    "patterns": [
      r"Content-Security-Policy.*?unsafe-eval",
      r"['\"]Content-Security-Policy['\"].*?['\"]\\*['\"]",
    ],
    "fix": "Set a strict CSP. Never use unsafe-eval. Use nonces for inline scripts.",
    "rule_num": 4,
  },
  {
    "id": "05",
    "name": "Server-Side Validation Required",
    "category": "Input Validation",
    "severity": CRITICAL,
    "short": "Never trust client-side validation alone.",
    "patterns": [
      r"app\.(post|put|patch)\s*\([^)]+\)\s*,\s*(async\s*)?\(req,\s*res\)\s*=>\s*\{(?![^}]*?(schema|validate|parse|zod|joi|yup|validator))",
    ],
    "fix": "Add server-side validation with Zod, Joi, Yup, or similar before processing.",
    "rule_num": 5,
  },
  {
    "id": "06",
    "name": "X-Frame-Options DENY",
    "category": "HTTP Headers",
    "severity": HIGH,
    "short": "X-Frame-Options must be DENY to prevent clickjacking.",
    "patterns": [
      r"X-Frame-Options['\"\s:]+SAMEORIGIN",  # WARN level — SAMEORIGIN is weaker
      r"frameguard.*?sameorigin",
    ],
    "fix": "Set X-Frame-Options: DENY. Use helmet.frameguard({ action: 'deny' }).",
    "rule_num": 6,
  },
  {
    "id": "07",
    "name": "Strip File Metadata",
    "category": "File Security",
    "severity": HIGH,
    "short": "User-uploaded files must have metadata stripped before storage.",
    "patterns": [
      r"multer|formidable|busboy",  # Detect file upload — then check for stripping
    ],
    "hints": [
      "If file upload detected, check that sharp/exiftool/piexif is also used.",
    ],
    "fix": "Use sharp with withMetadata(false) or exiftool to strip all file metadata.",
    "rule_num": 7,
  },
  {
    "id": "08",
    "name": "No Stack Traces in Production",
    "category": "Info Disclosure",
    "severity": HIGH,
    "short": "Stack traces must not be sent in production responses.",
    "patterns": [
      r"res\.(json|send)\s*\(\s*\{[^}]*stack",
      r"res\.(json|send)\s*\(\s*err\b",
      r"res\.(json|send)\s*\(\s*error\b",
    ],
    "fix": "In production, log errors internally and return generic messages only.",
    "rule_num": 8,
  },
  {
    "id": "09",
    "name": "Use Presigned URLs for Private Files",
    "category": "Cloud Storage",
    "severity": HIGH,
    "short": "Private files must use presigned/signed URLs, not public bucket URLs.",
    "patterns": [
      r"ACL.*?public-read",
      r"['\"]public['\"].*?bucket",
      r"makePublic\s*\(",
    ],
    "fix": "Use getSignedUrl() with short expiry. Never set ACL to public-read for private files.",
    "rule_num": 9,
  },
  {
    "id": "10",
    "name": "CSRF Tokens Required",
    "category": "CSRF",
    "severity": HIGH,
    "short": "CSRF tokens must be on every state-changing request.",
    "patterns": [
      r"app\.use\s*\(\s*express\.urlencoded|app\.use\s*\(\s*bodyParser",  # Detect form processing
    ],
    "hints": [
      "If form processing detected without csurf/csrf middleware, flag it.",
    ],
    "fix": "Implement CSRF tokens using csurf or similar middleware.",
    "rule_num": 10,
  },
  {
    "id": "11",
    "name": "Disable Autocomplete on Sensitive Fields",
    "category": "Client Security",
    "severity": MEDIUM,
    "short": "Password and card fields must have autocomplete disabled.",
    "patterns": [
      r'type=["\']password["\'](?!.*autocomplete)',
      r'name=["\']card(Number|number|_number)["\'](?!.*autocomplete.*off)',
    ],
    "fix": "Add autocomplete='new-password' to password fields, autocomplete='off' to card fields.",
    "rule_num": 11,
  },
  {
    "id": "12",
    "name": "bcrypt Cost Factor >= 12",
    "category": "Cryptography",
    "severity": CRITICAL,
    "short": "Password hashing must use bcrypt with cost >= 12.",
    "patterns": [
      r"bcrypt\.(hash|genSalt)\s*\([^,)]+,\s*([1-9])\b",   # cost 1-9 → CRITICAL
      r"bcrypt\.(hash|genSalt)\s*\([^,)]+,\s*1[01]\b",      # cost 10-11 → HIGH
      r"md5\s*\(",
      r"sha1\s*\(",
      r'createHash\s*\(\s*[\'"]md5[\'"]',
      r'createHash\s*\(\s*[\'"]sha1[\'"]',
    ],
    "fix": "Use bcrypt.hash(password, 12) minimum. Never use MD5 or SHA1 for passwords.",
    "rule_num": 12,
  },
  {
    "id": "13",
    "name": "Minimal Dependencies",
    "category": "Supply Chain",
    "severity": HIGH,
    "short": "Every extra package is an attack surface. Keep deps minimal.",
    "patterns": [],
    "hints": [
      "Check package.json for dependency count > 50.",
      "Run npm audit and flag any HIGH/CRITICAL vulnerabilities.",
    ],
    "fix": "Regularly prune unused packages. Use npm audit. Prefer packages with low transitive deps.",
    "rule_num": 13,
  },
  {
    "id": "14",
    "name": "SRI for External Scripts",
    "category": "Supply Chain",
    "severity": HIGH,
    "short": "External scripts must use Subresource Integrity (SRI).",
    "patterns": [
      r'<script\s+src=["\']https?://(?!localhost)[^"\']+["\'](?![^>]*integrity)',
      r'<link\s+href=["\']https?://(?!localhost)[^"\']+["\'](?![^>]*integrity)',
    ],
    "fix": "Add integrity='sha384-...' and crossorigin='anonymous' to all external script/link tags.",
    "rule_num": 14,
  },
  {
    "id": "15",
    "name": "Never Log Sensitive Data",
    "category": "Logging",
    "severity": CRITICAL,
    "short": "Never log passwords, tokens, or PII in any log statement.",
    "patterns": [
      r"console\.log\s*\([^)]*\b(password|passwd|token|secret|key|credential|ssn|card)\b",
      r"logger\.(info|warn|error|debug)\s*\([^)]*\b(password|passwd|token|secret)\b",
      r"console\.log\s*\(req\.body\)",
      r"console\.log\s*\(req\)",
    ],
    "fix": "Never log req.body in auth routes. Explicitly exclude sensitive fields from log objects.",
    "rule_num": 15,
  },
  {
    "id": "16",
    "name": "HTTPS Everywhere",
    "category": "Transport",
    "severity": CRITICAL,
    "short": "All traffic must use HTTPS. HTTP must redirect.",
    "patterns": [
      r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z]',  # non-localhost HTTP URL in code
    ],
    "fix": "Enforce HTTPS via HSTS headers. Redirect HTTP to HTTPS at server level.",
    "rule_num": 16,
  },
  {
    "id": "17",
    "name": "Separate DB Credentials Per Environment",
    "category": "Secrets Management",
    "severity": CRITICAL,
    "short": "Never share production credentials with dev/staging.",
    "patterns": [
      r'DATABASE_URL\s*=\s*["\'].*?prod',  # prod creds potentially in non-prod config
      r'password\s*=\s*["\'][A-Za-z0-9]{8,}["\']',  # hardcoded password
    ],
    "fix": "Use separate .env files per environment. Never hardcode credentials. Use a secrets manager.",
    "rule_num": 17,
  },
  {
    "id": "18",
    "name": "Account Lockout After 5 Failures",
    "category": "Auth",
    "severity": HIGH,
    "short": "Brute force protection required on all auth endpoints.",
    "patterns": [],
    "hints": [
      "Check auth routes for rate limiting middleware.",
      "If no rateLimit(), express-rate-limit, or similar on /login — flag it.",
    ],
    "fix": "Implement login rate limiting. Lock account after 5 failures per time window.",
    "rule_num": 18,
  },
  {
    "id": "19",
    "name": "Validate Content-Type Headers",
    "category": "API Security",
    "severity": MEDIUM,
    "short": "API routes must validate Content-Type on POST/PUT/PATCH.",
    "patterns": [],
    "hints": [
      "Check POST/PUT/PATCH handlers for content-type validation.",
    ],
    "fix": "Validate req.is('application/json') before parsing body on mutating routes.",
    "rule_num": 19,
  },
  {
    "id": "20",
    "name": "Never Use MD5 or SHA1",
    "category": "Cryptography",
    "severity": CRITICAL,
    "short": "MD5 and SHA1 are broken. Never use for security.",
    "patterns": [
      r"require\s*\(\s*['\"]md5['\"]",
      r"require\s*\(\s*['\"]sha1['\"]",
      r'createHash\s*\(\s*[\'"]md5[\'"]',
      r'createHash\s*\(\s*[\'"]sha1[\'"]',
      r"import.*?from\s*['\"]md5['\"]",
      r"import.*?from\s*['\"]sha1['\"]",
      r"hashlib\.md5\s*\(",
      r"hashlib\.sha1\s*\(",
    ],
    "fix": "Use SHA-256+ for non-password hashing. Use bcrypt/argon2 for passwords.",
    "rule_num": 20,
  },
  {
    "id": "21",
    "name": "Minimum OAuth Scope",
    "category": "OAuth",
    "severity": HIGH,
    "short": "OAuth tokens must request minimum required permissions.",
    "patterns": [
      r"scope.*?admin",
      r"scope.*?write:.*?",
      r"scope.*?delete:.*?",
    ],
    "fix": "Request only the OAuth scopes you actually need. Audit scope lists regularly.",
    "rule_num": 21,
  },
  {
    "id": "22",
    "name": "CSP Nonces for Inline Scripts",
    "category": "CSP",
    "severity": HIGH,
    "short": "Use nonces, not unsafe-inline, for CSP compliance.",
    "patterns": [
      r"['\"]unsafe-inline['\"]",
      r"script-src.*?'unsafe-inline'",
    ],
    "fix": "Generate a random nonce per request. Use 'nonce-{value}' instead of 'unsafe-inline'.",
    "rule_num": 22,
  },
  {
    "id": "23",
    "name": "Weekly Dependency Vulnerability Scanning",
    "category": "Supply Chain",
    "severity": HIGH,
    "short": "Dependencies must be scanned for vulnerabilities weekly.",
    "patterns": [],
    "hints": [
      "Check for npm audit, snyk, or dependabot config in repo.",
      "Check CI/CD pipeline for security scanning step.",
    ],
    "fix": "Add 'npm audit' or Snyk to CI pipeline. Set up Dependabot or Renovate.",
    "rule_num": 23,
  },
  {
    "id": "24",
    "name": "Disable Unused HTTP Methods",
    "category": "Attack Surface",
    "severity": MEDIUM,
    "short": "Only allow HTTP methods your app actually uses.",
    "patterns": [
      r"app\.trace\s*\(",
      r"methods.*?TRACE",
    ],
    "fix": "Return 405 for methods not in your allowed list. Block TRACE always.",
    "rule_num": 24,
  },
  {
    "id": "25",
    "name": "Server-Side Session Invalidation on Logout",
    "category": "Sessions",
    "severity": HIGH,
    "short": "Logout must destroy server-side session, not just clear cookie.",
    "patterns": [
      r"res\.clearCookie\s*\([^)]+\)(?!\s*;?\s*req\.session\.destroy)",  # clearCookie without destroy
    ],
    "fix": "Always call req.session.destroy() before clearing the cookie on logout.",
    "rule_num": 25,
  },
  {
    "id": "26",
    "name": "Constant-Time Token Comparison",
    "category": "Timing Attacks",
    "severity": HIGH,
    "short": "Token comparison must be timing-safe to prevent timing attacks.",
    "patterns": [
      r"(token|secret|hmac|signature)\s*===\s*(req\.|expected|stored|valid)",
      r"(req\.|expected|stored|valid).*?(token|secret|hmac)\s*===",
    ],
    "fix": "Use crypto.timingSafeEqual() for all token/HMAC/signature comparisons.",
    "rule_num": 26,
  },
  {
    "id": "27",
    "name": "No-Store Cache for Sensitive Endpoints",
    "category": "Caching",
    "severity": HIGH,
    "short": "Sensitive API responses must not be cached.",
    "patterns": [
      r"Cache-Control.*?public",
      r"['\"]Cache-Control['\"].*?['\"]public",
    ],
    "fix": "Set Cache-Control: no-store, no-cache, must-revalidate for sensitive endpoints.",
    "rule_num": 27,
  },
  {
    "id": "28",
    "name": "Referrer-Policy Strict-Origin",
    "category": "Privacy",
    "severity": MEDIUM,
    "short": "Set Referrer-Policy to stop URL leakage to third parties.",
    "patterns": [
      r"Referrer-Policy.*?no-referrer-when-downgrade",
      r"referrerPolicy.*?no-referrer-when-downgrade",
    ],
    "fix": "Use Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    "rule_num": 28,
  },
  {
    "id": "29",
    "name": "Server-Side Password Complexity",
    "category": "Auth",
    "severity": HIGH,
    "short": "Password complexity must be enforced server-side, not just frontend.",
    "patterns": [],
    "hints": [
      "Check auth registration routes for password complexity validation.",
      "Client-only regex for password strength is insufficient.",
    ],
    "fix": "Use zxcvbn or similar server-side. Minimum 12 chars, strength score >= 3.",
    "rule_num": 29,
  },
  {
    "id": "30",
    "name": "Scan Docker Images Before Deploy",
    "category": "Container Security",
    "severity": HIGH,
    "short": "Docker images must be scanned for CVEs before every deployment.",
    "patterns": [],
    "hints": [
      "Check CI/CD for trivy, snyk container, or similar scan step.",
      "Check Dockerfile for use of :latest tags (unpinned = unscanned).",
    ],
    "fix": "Add Trivy or Snyk container scan to CI pipeline. Pin base image versions.",
    "rule_num": 30,
  },
]


# ── Scanner ───────────────────────────────────────────────────────────────────
class VibeCodingScanner:
    """
    Scans code files for violations of the 30 Vibe Coder Security Rules.
    """

    SCANNABLE_EXTENSIONS = {
        ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
        ".py", ".rb", ".php", ".go",
        ".html", ".htm",
        ".json", ".yaml", ".yml",
        ".nginx", ".conf", ".htaccess",
        ".dockerfile", "Dockerfile",
        ".env.example", ".env.template",
    }

    SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv"}

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: list = []

    def scan_file(self, filepath: Path) -> list:
        """Scan a single file for violations."""
        findings = []
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        for rule in RULES:
            for pattern in rule.get("patterns", []):
                try:
                    rx = re.compile(pattern, re.IGNORECASE)
                    for line_num, line in enumerate(lines, 1):
                        if rx.search(line):
                            findings.append({
                                "rule_id": rule["id"],
                                "rule_name": rule["name"],
                                "severity": rule["severity"],
                                "category": rule["category"],
                                "file": str(filepath),
                                "line": line_num,
                                "content": line.strip()[:120],
                                "fix": rule["fix"],
                            })
                except re.error:
                    pass

        return findings

    def scan_path(self, path: str, extensions: Optional[list] = None) -> dict:
        """Scan a file or directory recursively."""
        target = Path(path)
        all_findings = []
        files_scanned = 0
        exts = set(extensions) if extensions else self.SCANNABLE_EXTENSIONS

        if target.is_file():
            files = [target]
        else:
            files = []
            for f in target.rglob("*"):
                if any(skip in f.parts for skip in self.SKIP_DIRS):
                    continue
                if f.is_file() and (f.suffix in exts or f.name in exts):
                    files.append(f)

        for f in files:
            file_findings = self.scan_file(f)
            all_findings.extend(file_findings)
            files_scanned += 1
            if self.verbose and file_findings:
                print(f"  ⚠️  {f.name}: {len(file_findings)} finding(s)")

        # Group by severity
        by_severity = {CRITICAL: [], HIGH: [], MEDIUM: [], LOW: []}
        for finding in all_findings:
            by_severity.get(finding["severity"], by_severity[LOW]).append(finding)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": str(path),
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "by_severity": by_severity,
            "findings": all_findings,
            "critical_count": len(by_severity[CRITICAL]),
            "high_count": len(by_severity[HIGH]),
            "medium_count": len(by_severity[MEDIUM]),
        }


# ── Report ─────────────────────────────────────────────────────────────────────
def _print_results(results: dict, top: int = 20):
    total = results["total_findings"]
    crit = results["critical_count"]
    high = results["high_count"]
    med  = results["medium_count"]

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║  CLARIS AI — VIBE CODER SECURITY SCAN                            ║
║  V6.1 · 30 Rules · Ship Fast. But Ship Secure.                  ║
╚══════════════════════════════════════════════════════════════════╝

  📁 Path:     {results['path']}
  📄 Files:    {results['files_scanned']}
  🔍 Findings: {total}  |  🔴 CRITICAL: {crit}  |  🟠 HIGH: {high}  |  🟡 MEDIUM: {med}
""")

    if total == 0:
        print("  ✅ CLEAN — No violations detected by pattern engine.\n")
        print("  💡 Note: Some rules require structural analysis (see --list for hints).\n")
        return

    # Print top findings by severity
    shown = 0
    for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
        for f in results["by_severity"].get(sev, []):
            if shown >= top:
                break
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            print(f"  {icon} [{sev}] Rule {f['rule_id']}: {f['rule_name']}")
            print(f"     📄 {f['file']}:{f['line']}")
            print(f"     💬 {f['content']}")
            print(f"     ✅ Fix: {f['fix']}")
            print()
            shown += 1

    if total > top:
        print(f"  ... and {total - top} more findings. Use --json for full output.\n")

    print(f"  ~Claris · Semper Fortis · Ship fast. But ship secure.\n")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Claris AI — Vibe Coder Security Guard V6.1 (30 Rules)"
    )
    parser.add_argument("--scan",    type=str, help="File or directory to scan")
    parser.add_argument("--ext",     type=str, help="Comma-separated extensions to scan (e.g. .js,.ts)")
    parser.add_argument("--rule",    type=str, help="Show details for a specific rule (e.g. '12')")
    parser.add_argument("--list",    action="store_true", help="List all 30 rules")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json",    action="store_true", help="Output as JSON")
    parser.add_argument("--top",     type=int, default=20, help="Max findings to show (default 20)")

    args = parser.parse_args()

    if args.list:
        print("\n🔐 THE 30 VIBE CODER SECURITY RULES — Claris V6.1\n")
        print(f"  {'#':<4} {'Rule Name':<40} {'Category':<20} {'Severity'}")
        print(f"  {'─'*80}")
        for r in RULES:
            sev_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(r["severity"], "⚪")
            print(f"  {r['id']:<4} {r['name']:<40} {r['category']:<20} {sev_color} {r['severity']}")
        print(f"\n  Total: {len(RULES)} rules | Ship fast. But ship secure.\n")
        return

    if args.rule:
        rule_id = args.rule.zfill(2)
        rule = next((r for r in RULES if r["id"] == rule_id), None)
        if not rule:
            print(f"\n  Rule {rule_id} not found. Use --list to see all rules.\n")
            return
        print(f"\n  🔐 RULE {rule['id']}: {rule['name']}")
        print(f"  {'─'*60}")
        print(f"  Category: {rule['category']}")
        print(f"  Severity: {rule['severity']}")
        print(f"\n  Summary: {rule['short']}")
        print(f"\n  Fix: {rule['fix']}")
        if rule.get("patterns"):
            print(f"\n  Patterns detected ({len(rule['patterns'])}):")
            for p in rule["patterns"]:
                print(f"    - {p}")
        if rule.get("hints"):
            print(f"\n  Hints:")
            for h in rule["hints"]:
                print(f"    - {h}")
        print()
        return

    if args.scan:
        extensions = None
        if args.ext:
            extensions = [e.strip() for e in args.ext.split(",")]

        scanner = VibeCodingScanner(verbose=args.verbose)
        print(f"\n  🔍 Scanning: {args.scan}")
        results = scanner.scan_path(args.scan, extensions)

        # Log scan
        with open(_SCAN_LOG, "a") as f:
            f.write(json.dumps({
                "timestamp": results["timestamp"],
                "path": results["path"],
                "total": results["total_findings"],
                "critical": results["critical_count"],
                "high": results["high_count"],
            }) + "\n")

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            _print_results(results, top=args.top)
        return

    parser.print_help()
    print("""
Examples:
  python3 vibe_coder_guard.py --scan ./myapp
  python3 vibe_coder_guard.py --scan ./src --ext .js,.ts,.tsx
  python3 vibe_coder_guard.py --rule 12
  python3 vibe_coder_guard.py --list
""")


if __name__ == "__main__":
    main()

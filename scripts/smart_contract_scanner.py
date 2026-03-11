#!/usr/bin/env python3
"""
CLARIS Smart Contract Security Scanner — V3.0
Scans Solidity, Rust, Move, TypeScript/JavaScript source code for vulnerabilities.
Covers OWASP Smart Contract Top 10 (2026) + Dash Platform patterns.

Usage:
  python3 smart_contract_scanner.py --file contract.sol
  python3 smart_contract_scanner.py --file contract.sol --lang solidity --verbose
  python3 smart_contract_scanner.py --code "$(cat file.sol)" --lang solidity
  python3 smart_contract_scanner.py --file dashboard.ts --lang typescript --json
  cat contract.sol | python3 smart_contract_scanner.py --stdin --lang solidity

Exit codes:
  0 = No findings / informational only
  1 = Warnings/medium findings detected
  2 = High or critical findings detected
"""

import re, sys, json, argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

VERSION = "3.0.0"
SCANNER_SIGN = "~Claris"

# ─── LANGUAGE DETECTION ────────────────────────────────────────────────────────
LANG_EXTENSIONS = {
    ".sol":  "solidity",
    ".rs":   "rust",
    ".move": "move",
    ".ts":   "typescript",
    ".tsx":  "typescript",
    ".js":   "javascript",
    ".jsx":  "javascript",
}

def detect_language(path: str, hint: str = "auto") -> str:
    if hint != "auto":
        return hint.lower()
    ext = Path(path).suffix.lower()
    if ext in LANG_EXTENSIONS:
        return LANG_EXTENSIONS[ext]
    # Heuristic content sniff
    return "solidity"  # default


# ─── VULNERABILITY RULES ───────────────────────────────────────────────────────
# Each rule: (id, name, severity, languages, patterns[], description, remediation)

RULES = [
    # ══ SC01: Access Control ══════════════════════════════════════════════════
    {
        "id": "SC01-A",
        "name": "Unprotected Privileged Function",
        "severity": "CRITICAL",
        "category": "SC01 Access Control",
        "languages": ["solidity"],
        "patterns": [
            r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s+(?!.*(?:onlyOwner|onlyAdmin|onlyRole|require\s*\(.*msg\.sender))",
        ],
        "keywords": ["selfdestruct", "delegatecall"],
        "description": "Privileged function may be callable by anyone. Missing access control modifier.",
        "remediation": "Add onlyOwner/onlyRole modifier or require(msg.sender == owner) check.",
    },
    {
        "id": "SC01-B",
        "name": "tx.origin Authentication",
        "severity": "HIGH",
        "category": "SC01 Access Control",
        "languages": ["solidity"],
        "patterns": [r"tx\.origin\s*=="],
        "keywords": [],
        "description": "Using tx.origin for authentication allows phishing attacks via intermediate contracts.",
        "remediation": "Replace tx.origin with msg.sender for authentication.",
    },
    {
        "id": "SC01-C",
        "name": "Unprotected Initializer",
        "severity": "CRITICAL",
        "category": "SC01 Access Control",
        "languages": ["solidity"],
        "patterns": [r"function\s+initialize\s*\([^)]*\)\s*(?:external|public)(?!.*initializer)"],
        "keywords": [],
        "description": "Proxy initializer function is public without initializer guard. Can be called by anyone.",
        "remediation": "Add OpenZeppelin initializer modifier to prevent re-initialization.",
    },

    # ══ SC02: Business Logic ══════════════════════════════════════════════════
    {
        "id": "SC02-A",
        "name": "Uncapped Token Minting",
        "severity": "HIGH",
        "category": "SC02 Business Logic",
        "languages": ["solidity"],
        "patterns": [r"function\s+mint\s*\([^)]*\)\s*(?:external|public)"],
        "keywords": ["_mint", "mint("],
        "description": "Mint function detected. Verify supply cap and access control are enforced.",
        "remediation": "Implement supply cap check. Add onlyOwner/onlyMinter modifier.",
    },
    {
        "id": "SC02-B",
        "name": "Zero Slippage Tolerance",
        "severity": "HIGH",
        "category": "SC02 Business Logic",
        "languages": ["solidity", "typescript", "javascript"],
        "patterns": [r"amountOutMin\s*[=:]\s*0\b", r"slippage\s*[=:]\s*0\b"],
        "keywords": [],
        "description": "Zero slippage tolerance exposes users to unlimited sandwich attack losses.",
        "remediation": "Set minimum output amounts. Require amountOutMin > 0 from users.",
    },
    {
        "id": "SC02-C",
        "name": "Missing Deadline / Expiry",
        "severity": "MEDIUM",
        "category": "SC02 Business Logic",
        "languages": ["solidity"],
        "patterns": [r"block\.timestamp\s*\+\s*\d{6,}"],
        "keywords": [],
        "description": "Very long deadline allows miners to hold transactions for manipulation.",
        "remediation": "Use user-provided deadlines. Reject transactions with excessively far deadlines.",
    },

    # ══ SC03: Price Oracle Manipulation ═══════════════════════════════════════
    {
        "id": "SC03-A",
        "name": "Spot Price Oracle",
        "severity": "CRITICAL",
        "category": "SC03 Oracle Manipulation",
        "languages": ["solidity"],
        "patterns": [r"getReserves\s*\(\s*\)", r"slot0\s*\(\s*\)"],
        "keywords": [],
        "description": "Using AMM spot price as oracle. Vulnerable to flash loan manipulation in single transaction.",
        "remediation": "Use Chainlink price feeds or TWAP with ≥30 minute window. Never use spot reserves for pricing.",
    },
    {
        "id": "SC03-B",
        "name": "Stale Oracle Price",
        "severity": "HIGH",
        "category": "SC03 Oracle Manipulation",
        "languages": ["solidity"],
        "patterns": [r"latestAnswer\s*\(\s*\)", r"latestRoundData\s*\(\s*\)(?![\s\S]{0,200}answeredInRound)"],
        "keywords": [],
        "description": "Chainlink oracle used without staleness check. May use stale or manipulated price.",
        "remediation": "Check updatedAt timestamp and answeredInRound >= roundId. Set heartbeat threshold.",
    },

    # ══ SC04: Flash Loans ═════════════════════════════════════════════════════
    {
        "id": "SC04-A",
        "name": "Flash Loan Callback",
        "severity": "HIGH",
        "category": "SC04 Flash Loan Attacks",
        "languages": ["solidity"],
        "patterns": [r"function\s+(?:executeOperation|uniswapV2Call|pancakeCall|onFlashLoan)\s*\("],
        "keywords": [],
        "description": "Flash loan callback detected. Verify caller validation and reentrancy protection.",
        "remediation": "Validate initiator == address(this). Check amounts. Use nonReentrant modifier.",
    },
    {
        "id": "SC04-B",
        "name": "Single-Block Governance",
        "severity": "HIGH",
        "category": "SC04 Flash Loan Attacks",
        "languages": ["solidity"],
        "patterns": [r"balanceOf\s*\(msg\.sender\).*vote", r"votes?\s*\[.*block\.number\]"],
        "keywords": [],
        "description": "Governance uses current balance for voting power. Vulnerable to flash loan vote manipulation.",
        "remediation": "Use historical balance snapshots (ERC20Votes). Implement voting delay.",
    },

    # ══ SC05: Input Validation ════════════════════════════════════════════════
    {
        "id": "SC05-A",
        "name": "Missing Zero Address Check",
        "severity": "MEDIUM",
        "category": "SC05 Input Validation",
        "languages": ["solidity"],
        "patterns": [r"function\s+\w+\s*\(\s*address\s+\w+[^)]*\)\s*(?:external|public)[^{]*{(?![\s\S]{0,100}require\s*\([^)]*!=\s*address\s*\(\s*0\s*\))"],
        "keywords": [],
        "description": "Address parameter accepted without zero address validation.",
        "remediation": "Add require(_addr != address(0), 'Zero address') at function entry.",
    },
    {
        "id": "SC05-B",
        "name": "ABI Decode Without Validation",
        "severity": "MEDIUM",
        "category": "SC05 Input Validation",
        "languages": ["solidity"],
        "patterns": [r"abi\.decode\s*\("],
        "keywords": [],
        "description": "ABI decode of external data. Ensure length and type validation before decode.",
        "remediation": "Validate calldata length before abi.decode. Use try/catch for external decodes.",
    },

    # ══ SC06: Unchecked External Calls ════════════════════════════════════════
    {
        "id": "SC06-A",
        "name": "Unchecked Call Return Value",
        "severity": "HIGH",
        "category": "SC06 Unchecked External Calls",
        "languages": ["solidity"],
        "patterns": [r"\.call\s*\{[^}]*\}\s*\([^)]*\)\s*;"],
        "keywords": [],
        "description": "Low-level .call() return value may not be checked. Silent failures possible.",
        "remediation": "Always check: (bool success,) = addr.call{...}(...); require(success, 'Call failed');",
    },
    {
        "id": "SC06-B",
        "name": "Raw Token Transfer (No SafeERC20)",
        "severity": "MEDIUM",
        "category": "SC06 Unchecked External Calls",
        "languages": ["solidity"],
        "patterns": [r"IERC20\s*\([^)]+\)\s*\.\s*transfer\s*\(", r"\.transfer\s*\(\s*\w+\s*,\s*\w+\s*\)(?!.*SafeERC20)"],
        "keywords": [],
        "description": "Direct ERC20 transfer without SafeERC20. USDT and other tokens don't return bool.",
        "remediation": "Use SafeERC20.safeTransfer() for all ERC20 token transfers.",
    },

    # ══ SC07: Arithmetic Errors ═══════════════════════════════════════════════
    {
        "id": "SC07-A",
        "name": "Division Before Multiplication",
        "severity": "HIGH",
        "category": "SC07 Arithmetic Errors",
        "languages": ["solidity"],
        "patterns": [r"\w+\s*/\s*\d+\s*\*\s*\w+", r"\w+\s*/\s*\w+\s*\*\s*\w+(?!.*mulDiv|.*FullMath)"],
        "keywords": [],
        "description": "Division before multiplication causes precision loss. x/100*y loses precision vs x*y/100.",
        "remediation": "Always multiply before dividing. Use Math.mulDiv() for safe full-precision math.",
    },
    {
        "id": "SC07-B",
        "name": "Unchecked Arithmetic Block",
        "severity": "MEDIUM",
        "category": "SC07 Arithmetic Errors",
        "languages": ["solidity"],
        "patterns": [r"unchecked\s*\{[^}]*(?:\+|\-|\*)[^}]*\}"],
        "keywords": [],
        "description": "Unchecked arithmetic block disables overflow protection. Review for safety.",
        "remediation": "Verify unchecked blocks are mathematically safe (bounds pre-validated).",
    },

    # ══ SC08: Reentrancy ═══════════════════════════════════════════════════════
    {
        "id": "SC08-A",
        "name": "External Call Before State Update",
        "severity": "CRITICAL",
        "category": "SC08 Reentrancy",
        "languages": ["solidity"],
        "patterns": [r"\.call\s*\{[^}]*value[^}]*\}[^;]*;[\s\S]{0,200}balances?\s*\["],
        "keywords": [],
        "description": "External call with ETH value appears before state update. Classic reentrancy pattern.",
        "remediation": "Follow Checks-Effects-Interactions. Update state before external calls. Use ReentrancyGuard.",
    },
    {
        "id": "SC08-B",
        "name": "Missing ReentrancyGuard",
        "severity": "HIGH",
        "category": "SC08 Reentrancy",
        "languages": ["solidity"],
        "patterns": [r"function\s+withdraw\s*\([^)]*\)\s*(?:external|public)(?![\s\S]{0,100}nonReentrant)"],
        "keywords": [],
        "description": "Withdraw function without nonReentrant modifier. Common reentrancy target.",
        "remediation": "Add nonReentrant modifier from OpenZeppelin ReentrancyGuard.",
    },

    # ══ SC09: Integer Overflow/Underflow ═════════════════════════════════════
    {
        "id": "SC09-A",
        "name": "Old Solidity Version (No Auto-Overflow Protection)",
        "severity": "HIGH",
        "category": "SC09 Integer Overflow/Underflow",
        "languages": ["solidity"],
        "patterns": [r"pragma\s+solidity\s+[\^~]?0\.[1-7]\."],
        "keywords": [],
        "description": "Solidity version < 0.8.0 lacks automatic overflow protection. Manual SafeMath required.",
        "remediation": "Upgrade to Solidity 0.8.0+ or use SafeMath library throughout.",
    },
    {
        "id": "SC09-B",
        "name": "Inline Assembly Math",
        "severity": "HIGH",
        "category": "SC09 Integer Overflow/Underflow",
        "languages": ["solidity"],
        "patterns": [r"assembly\s*\{[^}]*(?:add|sub|mul)\s*\("],
        "keywords": [],
        "description": "Assembly arithmetic bypasses Solidity 0.8 overflow checks.",
        "remediation": "Add explicit bounds checks before assembly math operations.",
    },

    # ══ SC10: Proxy & Upgradeability ══════════════════════════════════════════
    {
        "id": "SC10-A",
        "name": "Unprotected Upgrade Function",
        "severity": "CRITICAL",
        "category": "SC10 Proxy Upgradeability",
        "languages": ["solidity"],
        "patterns": [r"function\s+upgradeTo\s*\([^)]*\)\s*(?:external|public)(?![\s\S]{0,100}(?:onlyOwner|onlyAdmin|onlyProxy))"],
        "keywords": [],
        "description": "Proxy upgrade function accessible without authorization check.",
        "remediation": "Add onlyOwner/onlyAdmin restriction to upgradeTo. Use OpenZeppelin UUPSUpgradeable.",
    },
    {
        "id": "SC10-B",
        "name": "Non-EIP1967 Storage Slot",
        "severity": "MEDIUM",
        "category": "SC10 Proxy Upgradeability",
        "languages": ["solidity"],
        "patterns": [r"_implementation\s*=\s*\w+", r"implementation\s*=\s*(?!.*EIP1967|.*0x360894)"],
        "keywords": [],
        "description": "Implementation slot not using EIP-1967 standard. Risk of storage collision.",
        "remediation": "Use EIP-1967 storage slots: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)",
    },

    # ══ DASH PLATFORM PATTERNS ═════════════════════════════════════════════════
    {
        "id": "DP02-A",
        "name": "Unbounded String Field in Schema",
        "severity": "HIGH",
        "category": "DP02 Dash Schema Injection",
        "languages": ["javascript", "typescript"],
        "patterns": [r'"type"\s*:\s*"string"(?![\s\S]{0,100}"maxLength")'],
        "keywords": [],
        "description": "String field in data contract schema without maxLength. Enables DoS via large payloads.",
        "remediation": 'Add "maxLength": 1024 (or appropriate limit) to all string fields.',
    },
    {
        "id": "DP02-B",
        "name": "Unbounded Array in Schema",
        "severity": "HIGH",
        "category": "DP02 Dash Schema Injection",
        "languages": ["javascript", "typescript"],
        "patterns": [r'"type"\s*:\s*"array"(?![\s\S]{0,100}"maxItems")'],
        "keywords": [],
        "description": "Array field in data contract schema without maxItems limit.",
        "remediation": 'Add "maxItems": 20 (or appropriate limit) to all array fields.',
    },
    {
        "id": "DP03-A",
        "name": "Missing DAPI Rate Limiting",
        "severity": "HIGH",
        "category": "DP03 DAPI Abuse",
        "languages": ["javascript", "typescript"],
        "patterns": [r"broadcastStateTransition\s*\(", r"documents\.broadcast\s*\("],
        "keywords": [],
        "description": "State transition broadcast without apparent rate limiting wrapper.",
        "remediation": "Implement client-side rate limiting (≤5 TPS). Add retry backoff logic.",
    },
    {
        "id": "DP05-A",
        "name": "Missing Identity Nonce Management",
        "severity": "HIGH",
        "category": "DP05 State Transition Replay",
        "languages": ["javascript", "typescript"],
        "patterns": [r"stateTransition(?![\s\S]{0,200}nonce)", r"documents\.broadcast(?![\s\S]{0,200}nonce)"],
        "keywords": [],
        "description": "State transition submitted without explicit nonce management. Risk of replay or nonce collision.",
        "remediation": "Always fetch current identity nonce before broadcasting state transitions.",
    },
    {
        "id": "DP08-A",
        "name": "Exposed RPC Credentials",
        "severity": "CRITICAL",
        "category": "DP08 Evonode Security",
        "languages": ["javascript", "typescript", "solidity"],
        "patterns": [
            r"rpcpassword\s*=\s*\w+",
            r"masternodeblsprivkey\s*=\s*[a-fA-F0-9]+",
            r"rpcbind\s*=\s*0\.0\.0\.0",
        ],
        "keywords": [],
        "description": "Evonode RPC credentials or keys visible in source code.",
        "remediation": "Store RPC credentials in environment variables. Bind RPC to localhost only.",
    },

    # ══ GENERAL SECURITY PATTERNS ══════════════════════════════════════════════
    {
        "id": "GEN-A",
        "name": "Hardcoded Private Key",
        "severity": "CRITICAL",
        "category": "Secrets Exposure",
        "languages": ["solidity", "typescript", "javascript", "rust", "move"],
        "patterns": [
            r"(?:private[_\s]?key|privateKey|PRIVATE_KEY)\s*[=:]\s*['\"]?[0-9a-fA-F]{64}['\"]?",
            r"(?:mnemonic|seed[_\s]?phrase|MNEMONIC)\s*[=:]\s*['\"][a-z\s]{40,}['\"]",
        ],
        "keywords": [],
        "description": "Hardcoded private key or mnemonic phrase in source code.",
        "remediation": "Move to environment variables. Rotate immediately if exposed. Never commit to git.",
    },
    {
        "id": "GEN-B",
        "name": "Hardcoded API Key",
        "severity": "CRITICAL",
        "category": "Secrets Exposure",
        "languages": ["solidity", "typescript", "javascript", "rust", "move"],
        "patterns": [
            r"sk-[a-zA-Z0-9]{32,}",
            r"sk-ant-[a-zA-Z0-9\-_]{32,}",
            r"[0-9]{8,12}:[A-Za-z0-9_\-]{30,}",
        ],
        "keywords": [],
        "description": "API key pattern detected in source code.",
        "remediation": "Use environment variables. Rotate exposed keys immediately.",
    },
    {
        "id": "GEN-C",
        "name": "Dangerous eval() Usage",
        "severity": "HIGH",
        "category": "Code Injection",
        "languages": ["typescript", "javascript"],
        "patterns": [r"\beval\s*\(", r"new\s+Function\s*\(.*user"],
        "keywords": [],
        "description": "Dynamic code evaluation with potentially user-controlled input.",
        "remediation": "Remove eval(). Use JSON.parse() for data. Never evaluate user input.",
    },
]

# ─── SCANNER ENGINE ────────────────────────────────────────────────────────────

def get_line_number(code: str, match_start: int) -> int:
    """Return 1-indexed line number for a character offset in code."""
    return code[:match_start].count('\n') + 1


def scan_code(code: str, language: str, filename: str = "<code>") -> list:
    """
    Scan source code for vulnerabilities.
    Returns list of finding dicts.
    """
    findings = []
    lines = code.split('\n')

    for rule in RULES:
        # Language filter
        if language not in rule["languages"] and "all" not in rule["languages"]:
            continue

        matched = False

        # Pattern matching
        for pattern in rule.get("patterns", []):
            for m in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                line_no = get_line_number(code, m.start())
                line_content = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "line": line_no,
                    "match": m.group()[:80].replace('\n', ' '),
                    "line_content": line_content[:120],
                    "description": rule["description"],
                    "remediation": rule["remediation"],
                    "filename": filename,
                })
                matched = True
                break  # One finding per rule per pattern match is enough

        # Keyword matching (simpler — just search for keyword presence)
        if not matched:
            for keyword in rule.get("keywords", []):
                for i, line in enumerate(lines, 1):
                    if keyword.lower() in line.lower():
                        findings.append({
                            "rule_id": rule["id"],
                            "name": rule["name"],
                            "severity": rule["severity"],
                            "category": rule["category"],
                            "line": i,
                            "match": keyword,
                            "line_content": line.strip()[:120],
                            "description": rule["description"],
                            "remediation": rule["remediation"],
                            "filename": filename,
                        })
                        break

    return findings


def deduplicate(findings: list) -> list:
    """Remove duplicate findings (same rule_id + line)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f["rule_id"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def compute_summary(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    return counts


def exit_code_for(findings: list) -> int:
    sev = {f["severity"] for f in findings}
    if "CRITICAL" in sev or "HIGH" in sev:
        return 2
    if "MEDIUM" in sev:
        return 1
    return 0


# ─── OUTPUT FORMATTERS ─────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

def format_human(findings: list, summary: dict, filename: str,
                  language: str, verbose: bool = False) -> str:
    lines = [
        f"\n{'═'*65}",
        f"🔍 CLARIS Smart Contract Scanner V{VERSION}",
        f"   File: {filename} | Language: {language}",
        f"   Scanned: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"{'═'*65}",
    ]

    if not findings:
        lines += [
            "\n✅ NO VULNERABILITIES DETECTED",
            "   No known patterns matched. Recommend formal audit for production.",
            f"\n   {SCANNER_SIGN} · Semper Fortis\n",
        ]
        return "\n".join(lines)

    lines.append(f"\n  {'CRITICAL':8} {summary['CRITICAL']}")
    lines.append(f"  {'HIGH':8} {summary['HIGH']}")
    lines.append(f"  {'MEDIUM':8} {summary['MEDIUM']}")
    lines.append(f"  {'LOW':8} {summary['LOW']}")
    lines.append("")

    # Group by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_findings = [f for f in findings if f["severity"] == sev]
        if not sev_findings:
            continue
        for f in sev_findings:
            emoji = SEVERITY_EMOJI.get(sev, "❓")
            lines.append(f"  {emoji} [{sev}] {f['name']} ({f['rule_id']})")
            lines.append(f"     Line {f['line']:4d} | {f['filename']}")
            if verbose:
                lines.append(f"     Code: {f['line_content']}")
                lines.append(f"     Category: {f['category']}")
                lines.append(f"     Issue: {f['description']}")
                lines.append(f"     Fix: {f['remediation']}")
            else:
                lines.append(f"     → {f['description']}")
            lines.append("")

    lines.append(f"  Total findings: {len(findings)} | {SCANNER_SIGN} · Semper Fortis\n")
    return "\n".join(lines)


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CLARIS Smart Contract Security Scanner V3.0"
    )
    parser.add_argument("--file",    help="Source file to scan")
    parser.add_argument("--code",    help="Source code string to scan")
    parser.add_argument("--stdin",   action="store_true", help="Read from stdin")
    parser.add_argument("--lang",    default="auto",
                        choices=["auto", "solidity", "rust", "move", "typescript", "javascript"],
                        help="Language (default: auto-detect)")
    parser.add_argument("--json",    action="store_true", help="Output JSON")
    parser.add_argument("--verbose", action="store_true", help="Show full finding details")
    args = parser.parse_args()

    # Load source
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(2)
        code = path.read_text(errors='ignore')
        filename = args.file
        language = detect_language(args.file, args.lang)
    elif args.stdin:
        code = sys.stdin.read()
        filename = "<stdin>"
        language = args.lang if args.lang != "auto" else "solidity"
    elif args.code:
        code = args.code
        filename = "<inline>"
        language = args.lang if args.lang != "auto" else "solidity"
    else:
        parser.print_help()
        sys.exit(1)

    # Scan
    raw_findings = scan_code(code, language, filename)
    findings = deduplicate(raw_findings)
    summary = compute_summary(findings)

    if args.json:
        output = {
            "scanner": f"CLARIS Smart Contract Scanner V{VERSION}",
            "filename": filename,
            "language": language,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "finding_count": len(findings),
            "findings": findings,
            "signed": SCANNER_SIGN,
        }
        print(json.dumps(output, indent=2))
    else:
        print(format_human(findings, summary, filename, language, args.verbose))

    sys.exit(exit_code_for(findings))


if __name__ == "__main__":
    main()

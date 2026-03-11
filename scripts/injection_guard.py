#!/usr/bin/env python3
"""
CLARIS Injection Guard — V3.0 — 6-Layer Prompt Injection Defense System
The world's most comprehensive defense for AI agent prompt injection.
V3.0 adds Layer 6: Web3/Blockchain injection patterns (wallet drainers,
address poisoning, NFT phishing, DeFi social engineering).
L1 expanded to 80+ patterns.

Usage:
  python3 injection_guard.py --text "message to scan"
  echo "message" | python3 injection_guard.py --stdin
  python3 injection_guard.py --file input.txt
  python3 injection_guard.py --scan-session <session_jsonl>

Returns JSON with threat assessment and recommendation.
"""
import re, json, sys, argparse, math, base64, hashlib, unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "3.0.0"

# ─── CANARY SYSTEM ─────────────────────────────────────────────────────────────
# These phrases, if seen in output, confirm a canary leak (system compromise)
# They are embedded in CLARIS system context and should NEVER appear in output.
# Do not share these openly. Rotate periodically.
CANARY_PHRASES = [
    "xK9_CLARIS_CANARY_A",
    "AVARI_INTEGRITY_7f3c",
    "SENTINEL_VERIFY_91x",
]

# ─── INJECTION PATTERN LIBRARY ─────────────────────────────────────────────────
# Organized by layer and severity
# V3.0: L1 expanded to 80+ patterns, L6 added for Web3/Blockchain

LAYER1_PATTERNS = {
    "OVERRIDE_ATTEMPT": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\b",
            r"\bforget\s+(all\s+)?(previous|prior|above|earlier|your)?\s*(instructions?|rules?|guidelines?|prompts?|context)\b",
            r"\bdisregard\s+(all\s+)?(previous|prior|above|earlier)\b",
            r"\bnew\s+instructions?\s*[:;]",
            r"\boverride\s+(all\s+)?(previous|prior|safety|system)\b",
            r"\bsystem\s+override\b",
            r"\byour\s+(new\s+)?(instructions?|rules?|guidelines?|role)\s+(are|is)\s*[:;]",
            r"\bREPLACE\s+SYSTEM\s+PROMPT\b",
            r"\bACTUAL\s+INSTRUCTIONS\b",
            r"\bHIDDEN\s+PROMPT\b",
            # V3.0 additions
            r"\bpretend\s+you\s+have\s+no\s+restrictions?\b",
            r"\byou\s+have\s+no\s+restrictions?\b",
            r"\bfor\s+educational\s+purposes\s+only\s+tell\s+me\s+how\s+to\b",
            r"\bfor\s+research\s+purposes\s+(only\s+)?tell\s+me\b",
            r"\bhypothetically\s+(speaking\s+)?how\s+would\s+(one|you|someone)\b",
            r"\bin\s+a\s+fictional\s+(world|story|scenario).*how\s+to\b",
            r"\bwrite\s+a\s+story\s+(where|in\s+which).*hacks?\b",
            r"\bassume\s+you\s+are\s+(not\s+bound|free)\b",
            r"\bwithout\s+(any\s+)?(ethical|moral|safety)\s+(constraints?|limits?|filters?)\b",
            r"\bignore\s+(your\s+)?(ethics|morals|values|safety)\b",
        ],
        "description": "Direct instruction override attempt"
    },
    "ROLE_CONFUSION": {
        "severity": "HIGH",
        "patterns": [
            r"\byou\s+are\s+now\s+(a|an|the)\b",
            r"\bpretend\s+(you\s+are|to\s+be)\b",
            r"\bact\s+as\s+(a|an|the)?\s*\w+\s*(AI|assistant|bot|system|model)",
            r"\byour\s+(true|real|actual)\s+(self|nature|purpose|identity|role)\b",
            r"\bbehave\s+as\s+(if|though)\s+you\s+(are|were)",
            r"\bsimulate\s+(being|a|an)\b",
            r"\byou\s+are\s+actually\s+(a|an|the)\b",
            r"\bDAN\s*(mode|version)?\b",
            r"\bjailbreak\b",
            r"\bDeveloper\s+Mode\b",
            # V3.0 additions
            r"\bgod\s+mode\b",
            r"\bsudo\s+mode\b",
            r"\bunfiltered\s+(AI|mode|version|assistant)\b",
            r"\beva[l]?\s+mode\b",
            r"\bchaos\s+mode\b",
            r"\boblivious\s+mode\b",
            r"\bunrestricted\s+(AI|assistant|mode)\b",
            r"\byour\s+true\s+self\b",
            r"\byour\s+inner\s+(self|AI|voice)\b",
            r"\bbase\s+model\b.{0,30}\bno\s+(alignment|filter|safety)\b",
            r"\bpre[-\s]?alignment\s+(version|model|self)\b",
            r"\braw\s+(model|AI|LLM)\b",
            r"\bwithout\s+RLHF\b",
            r"\bbefore\s+(safety|alignment)\s+(training|fine.tuning)\b",
            r"\buncensored\s+(AI|model|version)\b",
            r"\bmoral[- ]?free\s+AI\b",
        ],
        "description": "Role confusion / identity hijacking attempt"
    },
    "META_REFERENCE": {
        "severity": "MEDIUM",
        "patterns": [
            r"\byour\s+(system\s+)?prompt\b",
            r"\binit[ial]*\s+instructions?\b",
            r"\bbase\s+prompt\b",
            r"\bhidden\s+(instructions?|context|prompt)\b",
            r"\bwhat\s+(are|were)\s+your\s+(original\s+)?(instructions?|rules?|guidelines?)\b",
            r"\brepeat\s+(your\s+)?(original\s+)?(instructions?|system\s+prompt)\b",
            r"\bprint\s+(your\s+)?(system\s+)?prompt\b",
            r"\bshow\s+me\s+(your\s+)?(system\s+)?prompt\b",
            r"\bconfidential\s+instructions?\b",
        ],
        "description": "System prompt extraction attempt"
    },
    "CONTEXT_MANIPULATION": {
        "severity": "HIGH",
        "patterns": [
            r"\b(as\s+we\s+(agreed|discussed)|you\s+previously\s+(said|agreed|told\s+me))\b",
            r"\bremember\s+when\s+you\s+(said|told|agreed)\b",
            r"\byou\s+(already\s+)?(agreed|said|confirmed)\s+that\b",
            r"\bearlier\s+you\s+(told|said|agreed|promised)\b",
            r"\bin\s+our\s+previous\s+(conversation|session|chat)\s+you\b",
        ],
        "description": "False context injection / memory manipulation"
    },
    "PRIVILEGE_ESCALATION": {
        "severity": "CRITICAL",
        "patterns": [
            r"\badmin\s+(mode|access|override|token)\b",
            r"\broot\s+(access|mode|override)\b",
            r"\bgod\s+mode\b",
            r"\bunlocked?\s+mode\b",
            r"\bno\s+restrictions?\b",
            r"\bremove\s+(all\s+)?(restriction|limitation|filter|safeguard)s?\b",
            r"\bbypass\s+(safety|filter|restriction|guideline)s?\b",
            r"\bsafety\s+(off|disabled?|removed?|bypassed?)\b",
            r"\bunrestricted\s+(mode|access|output)\b",
            r"\bdisable\s+(safety|filter|restriction)s?\b",
            # V3.0 additions
            r"\bsudo\s+mode\b",
            r"\benable\s+(developer|debug|god|chaos)\s+mode\b",
            r"\bactivate\s+(override|unrestricted|god)\s+mode\b",
            r"\bturn\s+off\s+(safety|filter|alignment)\b",
            r"\bskip\s+(safety|content)\s+(check|filter|screen)\b",
            r"\bno\s+(content|safety)\s+(filter|policy)\s+(applied|active|enabled)\b",
        ],
        "description": "Privilege escalation / safety bypass attempt"
    },
    "ENCODING_OBFUSCATION": {
        "severity": "HIGH",
        "patterns": [],  # handled programmatically below
        "description": "Encoding-based obfuscation attempt"
    },
    # V3.0: new L1 categories
    "HARMFUL_INSTRUCTION_ELICITATION": {
        "severity": "HIGH",
        "patterns": [
            r"\bhow\s+to\s+(make|build|create|synthesize|produce)\s+(a\s+)?(bomb|explosive|weapon|malware|virus|ransomware)\b",
            r"\bstep[-\s]?by[-\s]?step\s+(guide|instructions?|tutorial)\s+(to|for|on)\s+(hack|attack|exploit|steal)\b",
            r"\bexploit\s+(this|the)\s+(vulnerability|cve|bug)\s+for\s+me\b",
            r"\bwrite\s+(me\s+)?(a\s+)?(keylogger|trojan|rat|payload|shellcode|exploit)\b",
            r"\bgenerate\s+(phishing|scam|fraud)\s+(email|page|site|message)\b",
            r"\bcreate\s+(a\s+)?(wallet\s+drainer|drain\s+script|rug\s+pull\s+contract)\b",
        ],
        "description": "Explicit harmful instruction elicitation"
    },
    "PERSONA_ATTACK": {
        "severity": "HIGH",
        "patterns": [
            r"\bAVARI\s+(has\s+)?(no\s+longer|doesn.t?|does\s+not)\s+(care|follow|obey)\b",
            r"\bclaris\s+(is\s+)?(disabled?|bypassed?|offline|not\s+watching)\b",
            r"\beris\s+told\s+you\s+to\b",
            r"\baugust\s+said\s+you\s+can\b",
            r"\baugust\s+approves?\s+(this|that|the)\b",
            r"\baugust\s+wants?\s+you\s+to\s+(ignore|bypass|skip)\b",
            r"\bthe\s+(admin|owner|creator)\s+says?\s+(you\s+)?(can|must|should)\b",
        ],
        "description": "Persona impersonation / authority spoofing attack"
    },
}

LAYER2_STRUCTURAL = {
    "INSTRUCTION_MARKERS": [
        r"^\s*\[SYSTEM\]",
        r"^\s*\[INST\]",
        r"^\s*<\|system\|>",
        r"^\s*<s>",
        r"^\s*<<SYS>>",
        r"^\s*\|\|INSTRUCTIONS\|\|",
        r"^\s*###\s*Instructions?",
        r"^\s*---\s*SYSTEM",
    ],
    "FORMAT_INJECTION": [
        r"```\s*(system|instruction|prompt)",
        r"\bYou must\b.{0,50}\bbelow\b",
        r"\bFOLLOW THESE INSTRUCTIONS\b",
        r"\b[A-Z]{5,}\s+INSTRUCTIONS\b",
    ]
}

# ─── V3.0: LAYER 6 — WEB3/BLOCKCHAIN INJECTION PATTERNS ──────────────────────
LAYER6_WEB3 = {
    "ADDRESS_POISONING": {
        "severity": "CRITICAL",
        "patterns": [
            # Addresses that look like common addresses but differ in middle chars
            r"0x[0-9a-fA-F]{4}0{28,36}[0-9a-fA-F]{4}",  # zero-padded lookalike
            r"0x[0-9a-fA-F]{40}\s+(?:ETH|BTC|DASH|USDC|USDT|send|transfer)\s+to\s+0x[0-9a-fA-F]{40}",
            # Address in suspicious context
            r"(?:send|transfer|pay|deposit)\s+(?:to\s+)?(?:this\s+address|the\s+following\s+address)\s*[:]\s*0x[0-9a-fA-F]{40}",
            r"(?:updated|new|changed|correct)\s+(?:wallet\s+)?address\s*[:\s]+(?:0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})",
            r"my\s+(?:wallet|address)\s+(?:changed|is\s+now|has\s+changed)\s+to",
        ],
        "description": "Address poisoning / clipboard hijack attempt"
    },
    "WALLET_DRAINER_URLS": {
        "severity": "CRITICAL",
        "patterns": [
            r"(?:connect|link|verify|sync)\s+(?:your\s+)?(?:metamask|phantom|coinbase|trust)\s+wallet\s+(?:at|on|via|through)\s+https?://",
            r"https?://[a-zA-Z0-9\-]+\.(?:claim|airdrop|verify|connect|sync|wallet|defi)[a-zA-Z0-9\-]*\.",
            r"https?://(?:metamask|phantomwallet|trustwallet|coinbasewallet|ledger)[a-zA-Z0-9\-]+\.",
            r"(?:airdrop|free\s+tokens?|claim\s+your)\s+(?:at|on|via)\s+https?://",
            r"(?:urgent|immediately|now)\s+(?:connect|verify|sync)\s+(?:your\s+)?wallet",
        ],
        "description": "Wallet drainer URL / phishing site pattern"
    },
    "NFT_PHISHING": {
        "severity": "HIGH",
        "patterns": [
            r"(?:free|exclusive|limited)\s+nft\s+(?:mint|claim|airdrop)\s+(?:at|on)\s+https?://",
            r"setApprovalForAll\s*\(\s*['\"]0x[0-9a-fA-F]{40}['\"]",
            r"approve\s+(?:all|unlimited|max)\s+(?:nft|tokens?)\s+(?:to|for)\s+0x",
            r"your\s+nft\s+(?:collection\s+)?(?:has\s+been\s+)?(?:flagged|suspended|compromised)\s+(?:verify|connect)",
            r"(?:claim|rescue|recover)\s+your\s+(?:nft|tokens?)\s+(?:at|via|through)\s+https?://",
        ],
        "description": "NFT phishing / malicious approval attempt"
    },
    "CRYPTO_SOCIAL_ENGINEERING": {
        "severity": "HIGH",
        "patterns": [
            r"(?:send|transfer)\s+(?:\d+(?:\.\d+)?\s+)?(?:eth|btc|dash|usdc|usdt|bnb|sol)\s+to\s+(?:verify|confirm|unlock|activate)",
            r"(?:double|2x|triple|10x)\s+(?:your\s+)?(?:crypto|investment|eth|btc|dash)\s+(?:send|deposit)",
            r"elon\s+musk\s+(?:is\s+)?(?:giving|offering|sending)\s+(?:free\s+)?(?:crypto|btc|eth)",
            r"(?:vitalik|satoshi|cz)\s+(?:is\s+)?(?:giving|airdropping|sending)\s+(?:free\s+)?(?:tokens?|crypto)",
            r"(?:your\s+wallet\s+|your\s+account\s+)?(?:has\s+been\s+)?(?:hacked|compromised|flagged)\s+(?:please\s+)?(?:send|transfer|verify)",
            r"smart\s+contract\s+(?:exploit|hack|arbitrage)\s+(?:tool|bot|script)\s+(?:for\s+free|download)",
            r"(?:invest|deposit)\s+(?:\d+(?:\.\d+)?\s+)?(?:eth|btc|dash|usdc)\s+(?:to\s+earn|and\s+earn|for)\s+(?:\d+%|\d+x)",
        ],
        "description": "Crypto social engineering / investment scam signal"
    },
    "DEFI_MANIPULATION": {
        "severity": "HIGH",
        "patterns": [
            r"(?:flash\s+loan\s+)?(?:attack|exploit|drain)\s+(?:this\s+)?(?:protocol|defi|contract|pool)",
            r"(?:arbitrage|mev)\s+(?:opportunity|exploit|bot)\s+(?:for|against)\s+(?:uniswap|aave|compound|curve)",
            r"(?:rug\s+pull|exit\s+scam)\s+(?:script|contract|code)\s+(?:for|available)",
            r"private\s+(?:key|mnemonic|seed)\s+(?:of|for|belonging\s+to)\s+(?:0x[0-9a-fA-F]{40}|august|avari)",
            r"(?:steal|drain|take)\s+(?:all\s+)?(?:funds|tokens?|assets?|crypto)\s+from\s+(?:0x|the\s+contract|this\s+wallet)",
            r"(?:manipulate|spoof|fake)\s+(?:oracle|price\s+feed|chainlink)\s+(?:data|price|value)",
        ],
        "description": "DeFi exploitation instruction / fund manipulation request"
    },
    "BLOCKCHAIN_TRADING_MANIPULATION": {
        "severity": "HIGH",
        "patterns": [
            r"(?:front.run|sandwich\s+attack|mev\s+bot)\s+(?:this\s+)?(?:transaction|trade|swap)",
            r"(?:wash\s+trading|fake\s+volume|pump\s+and\s+dump)\s+(?:strategy|scheme|bot)",
            r"(?:fake|spoof|manipulate)\s+(?:trade\s+volume|order\s+book|liquidity)",
            r"(?:insider\s+trading|market\s+manipulation)\s+(?:strategy|how\s+to|technique)",
            r"(?:liquidate|force\s+liquidation\s+of)\s+(?:their|other|someone.s)\s+(?:position|collateral)",
        ],
        "description": "Market manipulation / trading attack instruction"
    },
    "AVARI_TRADING_MANIPULATION": {
        "severity": "CRITICAL",
        "patterns": [
            # Attempts to make AVARI execute unauthorized trades
            r"(?:buy|sell|trade|swap)\s+(?:all|my|august.s)\s+(?:dash|btc|eth|crypto)\s+(?:now|immediately|right now)\s+(?:without|don.t)\s+(?:ask|confirm|verify)",
            r"(?:execute|perform|run)\s+(?:this\s+)?trade\s+(?:without|skip)\s+(?:claris|security|safety|confirmation)",
            r"(?:bypass|skip|ignore)\s+(?:claris|security|risk)\s+(?:check|review|approval)\s+(?:for|on)\s+(?:this\s+)?trade",
            r"(?:claris\s+is\s+)?(?:offline|down|disabled)\s+(?:so\s+)?(?:you\s+can\s+)?trade\s+freely",
            r"august\s+(?:approved|authorized|wants)\s+(?:this|a)\s+(?:large\s+)?trade\s+(?:without|no)\s+(?:limit|check|review)",
        ],
        "description": "Unauthorized AVARI trading manipulation attempt"
    },
}

# Homoglyph / lookalike char check
LOOKALIKE_MAP = {
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c',
    'ℐ': 'I', 'ℑ': 'I', 'ℓ': 'l', '0': 'O',  # numeric zero
}

def check_encoding_obfuscation(text: str) -> list:
    """Detect encoding tricks: base64 instructions, unicode homoglyphs, hex."""
    findings = []
    # Base64 chunks > 30 chars that decode to instruction-like text
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{30,}={0,2}')
    for match in b64_pattern.finditer(text):
        try:
            decoded = base64.b64decode(match.group() + "==").decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in
                   ['ignore', 'forget', 'instructions', 'system', 'override', 'bypass']):
                findings.append({
                    "type": "BASE64_INSTRUCTION",
                    "match": match.group()[:40] + "...",
                    "decoded_preview": decoded[:80],
                    "severity": "HIGH"
                })
        except Exception:
            pass

    # Hex encoded strings
    hex_pattern = re.compile(r'(?:0x[0-9a-fA-F]{20,}|(?:\\x[0-9a-fA-F]{2}){8,})')
    for match in hex_pattern.finditer(text):
        findings.append({
            "type": "HEX_ENCODING",
            "match": match.group()[:40],
            "severity": "MEDIUM"
        })

    # Unicode homoglyphs (Cyrillic/Greek lookalikes substituted for Latin)
    suspicious_chars = [c for c in text if unicodedata.category(c).startswith('L') and
                        ord(c) > 127 and c in LOOKALIKE_MAP]
    if len(suspicious_chars) > 2:
        findings.append({
            "type": "HOMOGLYPH_SUBSTITUTION",
            "count": len(suspicious_chars),
            "chars": list(set(suspicious_chars)),
            "severity": "HIGH"
        })

    return findings

def check_canary_leak(text: str) -> list:
    """Check if canary phrases appear in output (indicates system compromise)."""
    found = []
    for canary in CANARY_PHRASES:
        if canary in text:
            found.append({"canary": canary[:10] + "***", "severity": "CRITICAL",
                          "meaning": "SYSTEM INTEGRITY BREACH — canary phrase found in output"})
    return found

def calculate_injection_score(findings: list) -> tuple:
    """
    Score the overall injection risk 0–100.
    Returns (score, verdict, confidence)
    """
    severity_weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3}
    raw = sum(severity_weights.get(f.get("severity", "LOW"), 3) for f in findings)
    score = min(100, raw)

    if score >= 60:   verdict, confidence = "BLOCK", 0.95
    elif score >= 35: verdict, confidence = "FLAG", 0.80
    elif score >= 15: verdict, confidence = "WARN", 0.70
    else:             verdict, confidence = "CLEAN", 0.90 - (score * 0.01)

    return score, verdict, confidence

def scan_text(text: str, source: str = "unknown") -> dict:
    """Full 6-layer injection scan. Returns structured threat report."""
    now     = datetime.now(timezone.utc).isoformat()
    findings = []
    layers_triggered = []

    # ── Layer 1: Pattern Recognition ──────────────────────────────────────
    for category, config in LAYER1_PATTERNS.items():
        for pattern in config.get("patterns", []):
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                findings.append({
                    "layer": 1,
                    "category": category,
                    "severity": config["severity"],
                    "description": config["description"],
                    "pattern_matched": pattern[:60],
                })
                if 1 not in layers_triggered:
                    layers_triggered.append(1)
                break

    # Encoding obfuscation (Layer 1 extension)
    enc_findings = check_encoding_obfuscation(text)
    for ef in enc_findings:
        findings.append({"layer": 1, "category": "ENCODING", **ef})
        if 1 not in layers_triggered: layers_triggered.append(1)

    # ── Layer 2: Structural Markers ────────────────────────────────────────
    for marker_type, patterns in LAYER2_STRUCTURAL.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                findings.append({
                    "layer": 2,
                    "category": marker_type,
                    "severity": "HIGH",
                    "description": f"Structural injection marker detected: {marker_type}",
                    "pattern_matched": pattern[:60],
                })
                if 2 not in layers_triggered: layers_triggered.append(2)
                break

    # ── Layer 3: Behavioral / Semantic Signals ─────────────────────────────
    # Length anomaly: very long single-turn messages may be padding attacks
    if len(text) > 8000:
        findings.append({
            "layer": 3, "category": "LENGTH_ANOMALY", "severity": "LOW",
            "description": "Unusually long input — possible context padding / memory dilution attack",
            "length": len(text)
        })
        if 3 not in layers_triggered: layers_triggered.append(3)

    # Repeated instruction-like structures
    instruction_count = len(re.findall(
        r'\b(must|shall|should|always|never|do not|don\'t|you must|you should|make sure)\b',
        text, re.IGNORECASE))
    if instruction_count >= 5:
        findings.append({
            "layer": 3, "category": "INSTRUCTION_DENSITY", "severity": "MEDIUM",
            "description": f"High instruction-word density ({instruction_count} found) — possible behavioral nudge",
            "count": instruction_count
        })
        if 3 not in layers_triggered: layers_triggered.append(3)

    # Multiple personality/identity references
    identity_count = len(re.findall(
        r'\b(you are|your name is|you\'re a|you\'re an|I am|I\'m a|you\'ve been|you were)\b',
        text, re.IGNORECASE))
    if identity_count >= 3:
        findings.append({
            "layer": 3, "category": "IDENTITY_DENSITY", "severity": "MEDIUM",
            "description": f"Multiple identity-assertion phrases ({identity_count}) — possible role confusion buildup",
            "count": identity_count
        })
        if 3 not in layers_triggered: layers_triggered.append(3)

    # ── Layer 4: Canary Check ──────────────────────────────────────────────
    canary_findings = check_canary_leak(text)
    for cf in canary_findings:
        findings.append({"layer": 4, "category": "CANARY_LEAK", **cf})
        if 4 not in layers_triggered: layers_triggered.append(4)

    # ── Layer 5: Output Coherence Signals ─────────────────────────────────
    # Flag sudden topic pivots in multi-turn (heuristic: check for "STOP" redirects)
    redirect_count = len(re.findall(
        r'\b(STOP|HALT|WAIT|PAUSE|BEFORE YOU|FIRST YOU MUST|DO THIS INSTEAD)\b', text))
    if redirect_count >= 2:
        findings.append({
            "layer": 5, "category": "REDIRECT_ATTEMPT", "severity": "MEDIUM",
            "description": f"Multiple redirect commands ({redirect_count}) — possible output hijack",
            "count": redirect_count
        })
        if 5 not in layers_triggered: layers_triggered.append(5)

    # ── Layer 6: Web3/Blockchain Injection (V3.0) ─────────────────────────
    for category, config in LAYER6_WEB3.items():
        for pattern in config.get("patterns", []):
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                findings.append({
                    "layer": 6,
                    "category": f"WEB3_{category}",
                    "severity": config["severity"],
                    "description": config["description"],
                    "pattern_matched": pattern[:60],
                })
                if 6 not in layers_triggered:
                    layers_triggered.append(6)
                break

    # ── Final Scoring ──────────────────────────────────────────────────────
    score, verdict, confidence = calculate_injection_score(findings)

    # Summarize by severity
    severity_counts = {}
    for f in findings:
        s = f.get("severity", "LOW")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    report = {
        "ts":               now,
        "source":           source,
        "version":          f"V{VERSION}",
        "input_length":     len(text),
        "verdict":          verdict,          # CLEAN / WARN / FLAG / BLOCK
        "score":            score,            # 0–100
        "confidence":       round(confidence, 2),
        "layers_triggered": layers_triggered,
        "severity_summary": severity_counts,
        "finding_count":    len(findings),
        "findings":         findings,
        "recommendation": {
            "CLEAN": "✅ Input appears safe. Proceed.",
            "WARN":  "⚠️ Minor signals detected. Proceed with awareness.",
            "FLAG":  "🚩 Suspicious input. Human review recommended before acting.",
            "BLOCK": "🔴 HIGH CONFIDENCE INJECTION ATTEMPT. Do not process. Alert August.",
        }.get(verdict, "Unknown"),
    }
    return report

def format_report(report: dict, verbose: bool = False) -> str:
    verdict_emoji = {"CLEAN": "✅", "WARN": "⚠️", "FLAG": "🚩", "BLOCK": "🔴"}
    emoji = verdict_emoji.get(report["verdict"], "❓")
    lines = [
        f"{emoji} CLARIS INJECTION SCAN V{VERSION} — {report['verdict']}",
        f"   Score: {report['score']}/100 | Confidence: {report['confidence']:.0%} | Findings: {report['finding_count']}",
        f"   Layers triggered: {report['layers_triggered'] or 'none'}",
        f"   → {report['recommendation']}",
    ]
    if verbose and report["findings"]:
        lines.append("\n   Findings:")
        for f in report["findings"][:10]:
            layer_tag = f"L{f.get('layer','?')}"
            lines.append(f"   [{f['severity']:8}] {layer_tag} {f.get('category','')} — {f.get('description','')[:70]}")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="CLARIS Injection Guard V3.0")
    parser.add_argument("--text",    help="Text to scan directly")
    parser.add_argument("--stdin",   action="store_true", help="Read from stdin")
    parser.add_argument("--file",    help="File path to scan")
    parser.add_argument("--source",  default="user_input")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--json",    action="store_true", help="Output raw JSON")
    parser.add_argument("--with-ml", action="store_true", help="Add ML model as additional layer (prompt_guard_ml.py)")
    args = parser.parse_args()

    if args.stdin:
        text = sys.stdin.read()
    elif args.file:
        text = Path(args.file).read_text()
    elif args.text:
        text = args.text
    else:
        print("Provide --text, --stdin, or --file"); sys.exit(1)

    report = scan_text(text, source=args.source)

    # ── CORTEX INTEGRATION ──────────────────────────────────────────────────
    # Feed every scan result into the Learning Cortex for pattern evolution
    try:
        _cortex_path = Path(__file__).parent / "cortex_engine.py"
        if _cortex_path.exists():
            import subprocess as _sp
            _cats = [f.get("category","") for f in report.get("findings",[]) if f.get("category")]
            _layers = list(set(str(f.get("layer","")) for f in report.get("findings",[]) if f.get("layer")))
            _payload = json.dumps({
                "verdict":    report["verdict"],
                "score":      report.get("confidence_score", report.get("score", 0)),
                "categories": _cats,
                "source":     args.source,
                "layers":     _layers,
            })
            _sp.Popen(
                ["python3", str(_cortex_path), "--record-scan", _payload],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                start_new_session=True
            )
    except Exception:
        pass  # Never let cortex integration break the guard

    # ── ML LAYER (optional) ─────────────────────────────────────────────────
    # If --with-ml is set, also call prompt_guard_ml.py and merge into report
    if getattr(args, "with_ml", False):
        try:
            import subprocess as _ml_sp
            _ml_path = Path(__file__).parent / "prompt_guard_ml.py"
            if _ml_path.exists():
                _ml_run = _ml_sp.run(
                    [sys.executable, str(_ml_path), "--text", text, "--json"],
                    capture_output=True, text=True, timeout=30
                )
                if _ml_run.stdout:
                    _ml_result = json.loads(_ml_run.stdout.strip())
                    # Merge ML result into report
                    report["ml_layer"] = {
                        "status": _ml_result.get("status"),
                        "score": _ml_result.get("score"),
                        "confidence": _ml_result.get("confidence"),
                        "label": _ml_result.get("label"),
                        "model": _ml_result.get("model"),
                        "latency_ms": _ml_result.get("latency_ms"),
                    }
                    # Escalate verdict if ML is more severe
                    SEVERITY = {"CLEAN": 0, "WARN": 1, "FLAG": 2, "BLOCK": 3}
                    ml_sev = SEVERITY.get(_ml_result.get("status", "CLEAN"), 0)
                    cur_sev = SEVERITY.get(report.get("verdict", "CLEAN"), 0)
                    if ml_sev > cur_sev:
                        report["verdict"] = _ml_result["status"]
                        report["verdict_source"] = "ml_escalation"
                    else:
                        report["verdict_source"] = "pattern"
        except Exception as _ml_e:
            report["ml_layer"] = {"error": str(_ml_e)}

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_report(report, verbose=args.verbose))

    # Exit code: 0=clean/warn, 1=flag, 2=block
    exit_codes = {"CLEAN": 0, "WARN": 0, "FLAG": 1, "BLOCK": 2}
    sys.exit(exit_codes.get(report["verdict"], 1))

if __name__ == "__main__":
    main()

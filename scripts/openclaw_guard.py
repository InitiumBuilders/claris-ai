#!/usr/bin/env python3
"""
CLARIS — OpenClaw Security Guard V3.0
Full infrastructure defense scanner for OpenClaw deployments.
V3.0 adds T11 (Supply Chain) and T12 (AI Model Poisoning) threat checks.
Improved secret detection: WIF keys, hex private keys, mnemonic phrases.

Usage: python3 openclaw_guard.py [--quick|--full|--weekly|--crons|--permissions|--scan-message "text"] [--json]
"""

import os, sys, json, re, stat, subprocess, hashlib
from pathlib import Path
from datetime import datetime, timezone

WORKSPACE = Path("/root/.openclaw/workspace")
OC_ROOT   = Path("/root/.openclaw")
CONFIG    = OC_ROOT / "openclaw.json"
CRONS     = OC_ROOT / "cron" / "jobs.json"
BUS       = WORKSPACE / "memory" / "agents" / "bus.jsonl"
MEMORY    = WORKSPACE / "MEMORY.md"
SOUL      = WORKSPACE / "SOUL.md"
AGENTS_MD = WORKSPACE / "AGENTS.md"
SKILLS_DIR = WORKSPACE / "skills"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"

COLOR = {
    SEVERITY_CRITICAL: "\033[91m",
    SEVERITY_HIGH:     "\033[93m",
    SEVERITY_MEDIUM:   "\033[33m",
    SEVERITY_LOW:      "\033[36m",
    SEVERITY_INFO:     "\033[90m",
    "RESET":           "\033[0m",
    "GREEN":           "\033[92m",
    "BOLD":            "\033[1m",
}

findings = []

def find(severity, category, title, detail, remediation="", file_path=""):
    findings.append({
        "severity": severity, "category": category, "title": title,
        "detail": detail, "remediation": remediation,
        "file": str(file_path), "ts": datetime.now(timezone.utc).isoformat()
    })

def header(text):
    if "--json" not in sys.argv:
        print(f"\n{COLOR['BOLD']}{COLOR['GREEN']}{'─'*60}{COLOR['RESET']}")
        print(f"{COLOR['BOLD']}{COLOR['GREEN']}🔍 CLARIS — {text}{COLOR['RESET']}")
        print(f"{COLOR['BOLD']}{COLOR['GREEN']}{'─'*60}{COLOR['RESET']}\n")

def ok(msg):
    if "--json" not in sys.argv:
        print(f"  {COLOR['GREEN']}✅{COLOR['RESET']} {msg}")

def warn(msg):
    if "--json" not in sys.argv:
        print(f"  {COLOR[SEVERITY_HIGH]}⚠️ {COLOR['RESET']} {msg}")

# ─── T8: SECRETS SCAN ────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    # API keys
    (r'sk-[a-zA-Z0-9]{32,}',                          'OpenAI API key',            SEVERITY_CRITICAL),
    (r'sk-ant-[a-zA-Z0-9\-_]{32,}',                   'Anthropic API key',         SEVERITY_CRITICAL),
    (r'xai-[a-zA-Z0-9]{32,}',                         'xAI API key',               SEVERITY_CRITICAL),
    (r'pk-[a-zA-Z0-9]{32,}',                          'Public key / pk- pattern',  SEVERITY_HIGH),
    (r'[0-9]{8,12}:[A-Za-z0-9_\-]{30,}',              'Telegram bot token',        SEVERITY_CRITICAL),
    (r'AKIA[0-9A-Z]{16}',                             'AWS Access Key',             SEVERITY_CRITICAL),
    (r'AIza[0-9A-Za-z\-_]{35}',                      'Google API key',             SEVERITY_CRITICAL),
    # Crypto private keys
    (r'(?:5[HJK][1-9A-HJ-NP-Za-km-z]{49})',          'WIF private key (mainnet)', SEVERITY_CRITICAL),
    (r'(?:K[1-9A-HJ-NP-Za-km-z]{51}|L[1-9A-HJ-NP-Za-km-z]{51})', 'WIF private key (compressed)', SEVERITY_CRITICAL),
    (r'(?i)(?:private[_\s]?key|secret[_\s]?key|priv_key|DASH_PRIVATE|ETH_PRIVATE)\s*[=:"\s]+[0-9a-fA-F]{64}\b',
                                                       'Hex private key (labeled)', SEVERITY_CRITICAL),
    # Mnemonic phrases (12/24 word patterns)
    (r'(?<!\w)(?:[a-z]{3,8}[ \t]+){11}[a-z]{3,8}(?!\w)', 'Possible 12-word mnemonic', SEVERITY_CRITICAL),
    (r'(?<!\w)(?:[a-z]{3,8}[ \t]+){23}[a-z]{3,8}(?!\w)', 'Possible 24-word mnemonic', SEVERITY_CRITICAL),
    (r'(?i)mnemonic["\s:=]+[a-z\s]{40,}',             'Wallet mnemonic (labeled)', SEVERITY_CRITICAL),
    (r'(?i)seed[_\s]?phrase["\s:=]+[a-z\s]{40,}',     'Seed phrase (labeled)',     SEVERITY_CRITICAL),
    # Existing patterns preserved
    (r'(?i)private[_\s]?key["\s:=]+0x[0-9a-fA-F]{60,}', 'Private key (0x)',       SEVERITY_CRITICAL),
    (r'(?i)api[_\s]?key["\s:=]+["\'][a-zA-Z0-9\-_]{20,}["\']', 'Generic API key', SEVERITY_HIGH),
    (r'(?i)password["\s:=]+["\'][^"\']{8,}["\']',     'Hardcoded password',        SEVERITY_HIGH),
    # Bearer tokens — but outside config files
    (r'(?i)bearer\s+[a-zA-Z0-9\-_.]{20,}',            'Bearer token',              SEVERITY_HIGH),
    # Private key assignment (general)
    (r'(?i)(?:private[_\s]?key|secret[_\s]?key|priv_key)\s*[=:"\s]+[0-9a-fA-F]{64}',
                                                       'Private key assignment',    SEVERITY_CRITICAL),
]

SCAN_EXTENSIONS = {'.py', '.ts', '.tsx', '.js', '.json', '.env', '.sh', '.yaml', '.yml'}
SKIP_DIRS = {'.next', 'node_modules', '.git', '__pycache__', '.vercel', 'venv', '.venv', 'out'}
# Config-related paths where bearer tokens and API key patterns may be legitimately stored
CONFIG_PATHS = {'openclaw.json', 'config.json', '.env', 'secrets.json'}

def _is_in_config_file(path: Path) -> bool:
    return path.name in CONFIG_PATHS or 'config' in path.name.lower()

def scan_secrets(root: Path, label: str):
    count = 0
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts): continue
        if path.is_file() and path.suffix in SCAN_EXTENSIONS:
            try:
                text = path.read_text(errors='ignore')
                is_doc = path.suffix == '.md' or 'docs/' in str(path) or 'references/' in str(path) or 'README' in path.name
                is_config = _is_in_config_file(path)
                for pattern, name, sev in SECRET_PATTERNS:
                    matches = re.findall(pattern, text)
                    if matches:
                        if 'example' in str(path).lower() or 'test' in str(path).lower():
                            continue
                        if is_doc and sev in (SEVERITY_HIGH, SEVERITY_LOW):
                            if any(placeholder in text[max(0,text.find(matches[0])-50):text.find(matches[0])+50].lower()
                                   for placeholder in ['your_', 'example', 'placeholder', 'replace', 'insert', '<your', 'xxx', '...']):
                                continue
                        # Bearer tokens in config files are expected
                        if 'bearer' in name.lower() and is_config:
                            continue
                        rel = path.relative_to(root)
                        find(sev, "T8_SECRETS",
                             f"{name} detected",
                             f"Found in {rel} — {len(matches)} instance(s)",
                             "Move to environment variables or config. Never commit to git.",
                             path)
                        count += 1
            except Exception:
                pass
    if count == 0:
        ok(f"No hardcoded secrets found in {label}")
    return count

# ─── T10: CONFIG PERMISSIONS ─────────────────────────────────────────────────
def check_permissions():
    checks = [
        (CONFIG,           0o600, "openclaw.json should be owner-read/write only"),
        (OC_ROOT / "devices" / "paired.json", 0o600, "paired.json contains device tokens"),
    ]
    wallet_dir = WORKSPACE / "dev-setup" / ".wallets"
    if wallet_dir.exists() and wallet_dir.is_dir():
        for f in wallet_dir.iterdir():
            checks.append((f, 0o600, f"Wallet file {f.name} should be 600"))
    elif wallet_dir.exists() and wallet_dir.is_file():
        checks.append((wallet_dir, 0o600, ".wallets file should be 600"))
    for path, required_mode, desc in checks:
        if not path.exists(): continue
        actual = stat.S_IMODE(os.stat(path).st_mode)
        if actual & 0o044:
            find(SEVERITY_HIGH, "T10_PERMISSIONS",
                 f"Insecure file permissions: {path.name}",
                 f"Mode {oct(actual)} — file is readable by group/others. {desc}",
                 f"chmod 600 {path}",
                 path)
            warn(f"{path.name}: mode {oct(actual)} (should be 600)")
        else:
            ok(f"{path.name}: permissions OK ({oct(actual)})")

# ─── T1/T9: CHANNEL CONFIG ────────────────────────────────────────────────────
def check_channel_config():
    if not CONFIG.exists():
        find(SEVERITY_HIGH, "T9_ACCESS", "openclaw.json not found", "Cannot verify channel config")
        return
    try:
        config = json.loads(CONFIG.read_text())
        channels = config.get("channels", {})
        for ch_name, ch_cfg in channels.items():
            if not ch_cfg.get("enabled", False): continue
            dm_policy = ch_cfg.get("dmPolicy", "open")
            group_policy = ch_cfg.get("groupPolicy", "open")
            allow_from = ch_cfg.get("allowFrom", [])
            if dm_policy == "open":
                find(SEVERITY_CRITICAL, "T9_ACCESS",
                     f"Channel {ch_name}: DM policy is OPEN",
                     "Anyone can send DMs to this OpenClaw instance.",
                     f'Set dmPolicy: "allowlist" in channel config.',
                     CONFIG)
                warn(f"{ch_name}: dmPolicy=open — ANYONE can DM the bot!")
            else:
                ok(f"{ch_name}: dmPolicy={dm_policy}")
            if group_policy == "open":
                find(SEVERITY_HIGH, "T2_GROUP",
                     f"Channel {ch_name}: group policy is OPEN",
                     "Any group can add this bot and interact with it.",
                     f'Set groupPolicy: "allowlist"',
                     CONFIG)
            else:
                ok(f"{ch_name}: groupPolicy={group_policy}")
            if not allow_from:
                find(SEVERITY_HIGH, "T9_ACCESS",
                     f"Channel {ch_name}: allowFrom is empty",
                     "No sender allowlist — relies only on dmPolicy.",
                     "Add authorized sender IDs to allowFrom.",
                     CONFIG)
            else:
                ok(f"{ch_name}: allowFrom has {len(allow_from)} authorized sender(s)")
    except Exception as e:
        find(SEVERITY_HIGH, "T10_CONFIG", "Cannot parse openclaw.json", str(e))

# ─── T8: BOT TOKEN IN STDOUT ─────────────────────────────────────────────────
def check_token_exposure():
    """Check if bot tokens appear in any log or output files."""
    log_dirs = [OC_ROOT / "logs", WORKSPACE / "output"]
    token_re = re.compile(r'[0-9]{8,12}:[A-Za-z0-9_\-]{30,}')
    for d in log_dirs:
        if not d.exists(): continue
        for f in d.rglob("*.log"):
            try:
                if token_re.search(f.read_text(errors='ignore')):
                    find(SEVERITY_CRITICAL, "T8_SECRETS",
                         "Bot token found in log file",
                         f"Token pattern detected in {f}",
                         "Redact logs. Never print tokens to stdout.",
                         f)
            except: pass
    ok("Log files checked for token exposure")

# ─── T3: CRON JOB SAFETY ─────────────────────────────────────────────────────
INJECTION_SIGNALS = [
    "ignore previous", "ignore all previous", "you are now",
    "forget your instructions", "new instructions:", "override:",
    "DAN", "jailbreak", "do anything now", "god mode", "sudo mode",
    "developer mode", "no restrictions", "pretend you have no",
]
def check_crons():
    if not CRONS.exists():
        ok("No cron jobs file found")
        return
    try:
        jobs_raw = CRONS.read_text()
        jobs = json.loads(jobs_raw)
        if not isinstance(jobs, list): jobs = []
        broken = [j for j in jobs if j.get("state", {}).get("consecutiveErrors", 0) >= 3]
        if broken:
            for j in broken:
                find(SEVERITY_MEDIUM, "T3_CRONS",
                     f"Broken cron: {j.get('name','?')}",
                     f"{j['state']['consecutiveErrors']} consecutive errors. Last: {j['state'].get('lastError','?')}",
                     "Fix or disable the cron. Silent failures mask real issues.",
                     CRONS)
                warn(f"Broken cron: {j.get('name','?')} ({j['state']['consecutiveErrors']} errors)")
        else:
            ok(f"All {len(jobs)} crons healthy (no consecutive errors ≥3)")
        for j in jobs:
            msg = j.get("payload", {}).get("message", "")
            for sig in INJECTION_SIGNALS:
                if sig.lower() in msg.lower():
                    find(SEVERITY_HIGH, "T3_CRONS",
                         f"Suspicious pattern in cron payload: {j.get('name','?')}",
                         f"Found '{sig}' in cron message",
                         "Review cron payload for injection.",
                         CRONS)
        no_timeout = [j for j in jobs if j.get("enabled", True) and not j.get("payload", {}).get("timeoutSeconds")]
        if no_timeout:
            find(SEVERITY_LOW, "T3_CRONS",
                 f"{len(no_timeout)} cron(s) missing timeoutSeconds",
                 "Crons without timeouts can hang indefinitely.",
                 "Add timeoutSeconds to all cron payloads.")
        ok(f"Cron safety check complete. {len(broken)} broken, {len(no_timeout)} missing timeout.")
    except Exception as e:
        find(SEVERITY_MEDIUM, "T3_CRONS", "Cannot parse cron jobs", str(e))

# ─── T5: MEMORY FILE INTEGRITY ───────────────────────────────────────────────
MEMORY_INJECTION_PATTERNS = [
    r"ignore (?:previous|all|your) instructions",
    r"you are now (?:a|an|the)",
    r"forget (?:everything|all|your)",
    r"new (?:system )?(?:prompt|instructions?):",
    r"override.*instructions",
    r"act as (?:a|an|the)",
    r"pretend (?:you are|to be)",
]
def check_memory_integrity():
    files_to_check = [MEMORY, SOUL, AGENTS_MD]
    for path in files_to_check:
        if not path.exists(): continue
        text = path.read_text(errors='ignore')
        for pattern in MEMORY_INJECTION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                context_ok = any(ctx in text[max(0, text.lower().find(matches[0].lower())-100):text.lower().find(matches[0].lower())+100].lower()
                                for ctx in ['example', 'pattern', 'detect', 'guard', 'injection'])
                if not context_ok:
                    find(SEVERITY_HIGH, "T5_MEMORY",
                         f"Injection pattern in memory file: {path.name}",
                         f"Found: '{matches[0]}'",
                         "Review file for unauthorized behavioral modifications.",
                         path)
                    warn(f"{path.name}: suspicious pattern '{matches[0]}'")
    ok("Memory files checked for injection patterns")

# ─── T6: SKILL FILE INTEGRITY ─────────────────────────────────────────────────
def check_skills():
    skills_dir = WORKSPACE / "skills"
    if not skills_dir.exists(): return
    suspicious = []
    for skill_md in skills_dir.rglob("SKILL.md"):
        text = skill_md.read_text(errors='ignore')
        for pattern in MEMORY_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious.append((skill_md, pattern))
    if suspicious:
        for path, pattern in suspicious:
            find(SEVERITY_HIGH, "T6_SKILLS",
                 f"Injection pattern in SKILL.md: {path.parent.name}",
                 f"Pattern: {pattern}",
                 "Review skill file. May indicate malicious skill content.",
                 path)
    else:
        ok(f"All SKILL.md files clean")
    for skill_dir in skills_dir.iterdir():
        if skill_dir.is_dir():
            mode = stat.S_IMODE(os.stat(skill_dir).st_mode)
            if mode & 0o002:
                find(SEVERITY_MEDIUM, "T6_SKILLS",
                     f"World-writable skill directory: {skill_dir.name}",
                     f"Mode {oct(mode)}",
                     f"chmod 755 {skill_dir}", skill_dir)

# ─── T4: AGENT BUS INTEGRITY ─────────────────────────────────────────────────
KNOWN_AGENTS = {"avari", "voda", "semble_ai", "initium_builder", "claris", "eris"}
def check_agent_bus():
    if not BUS.exists():
        ok("Agent bus not found (will be created on first use)")
        return
    try:
        entries = []
        for line in BUS.read_text().strip().split('\n'):
            if line.strip():
                try: entries.append(json.loads(line))
                except: pass
        unknown_agents = [e for e in entries if e.get("from_agent") and e.get("from_agent","").lower() not in KNOWN_AGENTS]
        if unknown_agents:
            find(SEVERITY_MEDIUM, "T4_BUS",
                 f"{len(unknown_agents)} message(s) from unknown agents on bus",
                 f"Unknown: {set(e.get('from_agent') for e in unknown_agents)}",
                 "Review bus entries. Unknown agents may indicate compromise.")
            warn(f"Unknown agents on bus: {set(e.get('from_agent') for e in unknown_agents)}")
        else:
            ok(f"Agent bus clean — {len(entries)} messages from known agents")
    except Exception as e:
        find(SEVERITY_LOW, "T4_BUS", "Cannot fully parse agent bus", str(e))

# ─── GITIGNORE CHECK ─────────────────────────────────────────────────────────
def check_gitignore():
    sensitive_patterns = ['.env', 'openclaw.json', '*.key', '*.pem', 'mnemonic', '.wallets']
    gitignore = WORKSPACE / ".gitignore"
    if not gitignore.exists():
        find(SEVERITY_HIGH, "T8_SECRETS",
             "No .gitignore in workspace",
             "Sensitive files may be accidentally committed to git.",
             "Create .gitignore with: .env, openclaw.json, *.key, .wallets")
        return
    text = gitignore.read_text()
    for pat in sensitive_patterns:
        if pat not in text:
            find(SEVERITY_MEDIUM, "T8_SECRETS",
                 f"'{pat}' not in .gitignore",
                 f"Sensitive pattern not protected from git commits.",
                 f"Add '{pat}' to .gitignore",
                 gitignore)
    ok(".gitignore reviewed")

# ─── T11: SUPPLY CHAIN CHECK (V3.0) ─────────────────────────────────────────
# Suspicious patterns that may indicate supply chain compromise
SUPPLY_CHAIN_SCRIPT_PATTERNS = [
    (r"curl\s+https?://[^\s]+\s*\|\s*(?:bash|sh|python|node)", "Remote shell execution via curl"),
    (r"wget\s+https?://[^\s]+\s*(?:-O\s*-\s*\||\|\s*)(?:bash|sh|python)", "Remote shell execution via wget"),
    (r"(?:subprocess|exec|os\.system)\s*\(\s*['\"]curl", "Python subprocess curl"),
    (r"require\(['\"]child_process['\"].*\)\s*\.\s*exec\s*\(", "Node.js remote exec"),
    (r"(?:postinstall|preinstall)\s*['\"].*(?:curl|wget|fetch)\s+https?://", "Package manager hook with remote fetch"),
    (r"__import__\s*\(\s*['\"]os['\"].*system", "Dynamic os.system import"),
    (r"eval\s*\(\s*(?:compile|exec|__import__)", "Nested eval/exec pattern"),
]

# npm packages that are commonly used in crypto attacks or have known malicious variants
SUSPICIOUS_NPM_PACKAGES = [
    "web3-utils-helper", "ethers-helper", "metamask-provider-helper",
    "hardhat-helper", "truffle-helper", "crypto-steal",
    "wallet-connect-helper", "web3-connector",
]

def check_supply_chain():
    """T11: Check for supply chain compromise indicators."""
    if not SKILLS_DIR.exists():
        ok("Skills directory not found")
        return

    suspicious_count = 0

    # Check Python scripts in skills for remote execution patterns
    for script_file in SKILLS_DIR.rglob("*.py"):
        try:
            content = script_file.read_text(errors='ignore')
            for pattern, description in SUPPLY_CHAIN_SCRIPT_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    rel = script_file.relative_to(WORKSPACE)
                    find(SEVERITY_HIGH, "T11_SUPPLY_CHAIN",
                         f"Suspicious script pattern: {script_file.name}",
                         f"{description} in {rel}",
                         "Review script for malicious remote execution. Verify against known-good version.",
                         script_file)
                    warn(f"Supply chain signal in {rel}: {description}")
                    suspicious_count += 1
                    break
        except Exception:
            pass

    # Check JavaScript/TypeScript files in skills
    for script_file in SKILLS_DIR.rglob("*.{js,ts}"):
        try:
            content = script_file.read_text(errors='ignore')
            for pattern, description in SUPPLY_CHAIN_SCRIPT_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    rel = script_file.relative_to(WORKSPACE)
                    find(SEVERITY_HIGH, "T11_SUPPLY_CHAIN",
                         f"Suspicious script: {script_file.name}",
                         f"{description} in {rel}",
                         "Review for supply chain compromise.",
                         script_file)
                    suspicious_count += 1
                    break
        except Exception:
            pass

    # Check for unusually recently-modified skill files (possible tampering)
    import time
    now = time.time()
    recent_threshold = 3600 * 24  # 24 hours
    for skill_dir in SKILLS_DIR.iterdir():
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            mtime = skill_md.stat().st_mtime
            age_hours = (now - mtime) / 3600
            if age_hours < 1:  # Modified in last hour — unusual
                find(SEVERITY_LOW, "T11_SUPPLY_CHAIN",
                     f"Recently modified SKILL.md: {skill_dir.name}",
                     f"Modified {age_hours:.1f} hours ago. Verify modification was intentional.",
                     "Check git diff or compare against known-good backup.",
                     skill_md)
        except Exception:
            pass

    # Check package.json files for suspicious dependencies
    for pkg_json in SKILLS_DIR.rglob("package.json"):
        try:
            pkg = json.loads(pkg_json.read_text())
            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))
            for dep in SUSPICIOUS_NPM_PACKAGES:
                if dep in all_deps:
                    find(SEVERITY_HIGH, "T11_SUPPLY_CHAIN",
                         f"Suspicious npm package: {dep}",
                         f"Found in {pkg_json.relative_to(WORKSPACE)}",
                         f"Review package '{dep}' for legitimacy. Check npmjs.com publication history.",
                         pkg_json)
                    suspicious_count += 1
        except Exception:
            pass

    if suspicious_count == 0:
        ok("Supply chain check complete — no suspicious patterns found")
    return suspicious_count


# ─── T12: AI MODEL POISONING CHECK (V3.0) ────────────────────────────────────
# Patterns specifically targeting AI behavioral modification via memory files
AI_POISONING_PATTERNS = [
    # Behavioral directive injection
    (r"(?i)(?:always|never)\s+(?:comply|obey|follow|execute)\s+(?:any|all|every)\s+(?:request|instruction|command)",
     "Blanket compliance directive — AI behavioral override"),
    (r"(?i)from\s+now\s+on\s+(?:you\s+)?(?:must|will|should|shall)\s+(?:always|never)",
     "Permanent behavioral instruction injection"),
    (r"(?i)your\s+(?:new\s+)?(?:primary\s+)?(?:goal|objective|mission|purpose)\s+is\s+to",
     "Goal/objective override attempt in memory"),
    (r"(?i)(?:disregard|ignore)\s+(?:all\s+)?(?:previous|prior|existing)\s+(?:goals?|instructions?|training|alignment)",
     "Alignment override in memory file"),
    # Hidden instruction markers
    (r"<!--\s*(?:INSTRUCTION|SYSTEM|AI|AVARI|CLARIS)\s*(?:OVERRIDE|DIRECTIVE|COMMAND)",
     "HTML comment instruction injection"),
    (r"\[\s*(?:HIDDEN|SECRET|INTERNAL)\s+(?:INSTRUCTION|DIRECTIVE|COMMAND)\s*\]",
     "Bracket-marker instruction injection"),
    (r"(?i)<<\s*(?:SYSTEM|INSTRUCTIONS?|OVERRIDE)\s*>>",
     "Angle-bracket system marker"),
    # Memory-specific trust escalation
    (r"(?i)august\s+(?:has\s+)?(?:authorized|approved|granted)\s+(?:unlimited|full|unrestricted)\s+(?:access|permissions?|authority)",
     "False authority escalation via August's name"),
    (r"(?i)security\s+(?:check|review|scan)\s+(?:is\s+)?(?:disabled?|bypassed?|waived?|skipped?)",
     "Security bypass instruction in memory"),
    (r"(?i)claris\s+(?:is\s+)?(?:disabled?|offline|not\s+running|bypassed?)\s+(?:for\s+this|today|now)",
     "Claris disable instruction in memory"),
]

# Memory files that are loaded into AI context — prime targets for poisoning
MEMORY_AI_FILES = [
    WORKSPACE / "MEMORY.md",
    WORKSPACE / "SOUL.md",
    WORKSPACE / "AGENTS.md",
    WORKSPACE / "IDENTITY.md",
    WORKSPACE / "USER.md",
    WORKSPACE / "HEARTBEAT.md",
]

def check_ai_model_poisoning():
    """T12: Check memory files loaded into AI context for injected instructions."""
    poisoning_found = 0

    # Scan primary AI context files
    for path in MEMORY_AI_FILES:
        if not path.exists():
            continue
        try:
            text = path.read_text(errors='ignore')
        except Exception:
            continue

        for pattern, description in AI_POISONING_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                sample = matches[0]
                idx = text.lower().find(sample.lower())
                context = text[max(0, idx-100):idx+200].lower()
                # Skip if clearly in a documentation / example block
                if any(ctx in context for ctx in ['example', 'test', 'this is how', 'pattern', 'detect']):
                    continue
                find(SEVERITY_CRITICAL, "T12_AI_POISONING",
                     f"AI model poisoning pattern in {path.name}",
                     f"Pattern: '{description}' | Match: '{sample[:80]}'",
                     "IMMEDIATE ACTION: Review and clean this file. Do not load into AI context until verified.",
                     path)
                warn(f"POISONING SIGNAL in {path.name}: {description}")
                poisoning_found += 1

    # Also scan recent daily memory files
    mem_dir = WORKSPACE / "memory"
    if mem_dir.exists():
        for daily_file in sorted(mem_dir.glob("????-??-??.md"))[-14:]:  # Last 14 days
            try:
                text = daily_file.read_text(errors='ignore')
                for pattern, description in AI_POISONING_PATTERNS:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    if matches:
                        sample = matches[0]
                        idx = text.lower().find(sample.lower())
                        context = text[max(0, idx-100):idx+150].lower()
                        if any(ctx in context for ctx in ['example', 'test', 'pattern', 'detect']):
                            continue
                        find(SEVERITY_HIGH, "T12_AI_POISONING",
                             f"AI poisoning pattern in daily memory: {daily_file.name}",
                             f"Pattern: '{description}'",
                             "Review daily memory file for injected instructions.",
                             daily_file)
                        poisoning_found += 1
            except Exception:
                pass

    if poisoning_found == 0:
        ok("AI model poisoning check complete — memory files clean")
    return poisoning_found


# ─── MESSAGE INJECTION SCAN ──────────────────────────────────────────────────
def scan_message(text: str):
    """Lightweight injection scan for inbound messages."""
    import importlib.util
    guard_path = Path(__file__).parent / "injection_guard.py"
    spec = importlib.util.spec_from_file_location("injection_guard", guard_path)
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        result = mod.scan_text(text, source="openclaw_guard_scan")
        return result
    return {"verdict": "UNKNOWN", "score": 0}

# ─── REPORT ──────────────────────────────────────────────────────────────────
def print_report():
    if "--json" in sys.argv:
        print(json.dumps({"findings": findings, "total": len(findings),
                          "critical": sum(1 for f in findings if f["severity"] == SEVERITY_CRITICAL),
                          "high": sum(1 for f in findings if f["severity"] == SEVERITY_HIGH),
                          "version": "3.0.0",
                          "ts": datetime.now(timezone.utc).isoformat()}, indent=2))
        return
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]}
    print(f"\n{'═'*60}")
    print(f"🔍 CLARIS OpenClaw Security Guard V3.0 — {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'═'*60}")
    if not findings:
        print(f"\n{COLOR['GREEN']}✅ ALL CLEAR — No security findings.{COLOR['RESET']}")
        print(f"{COLOR['GREEN']}   Semper Fortis. The fortress holds.{COLOR['RESET']}\n")
        return
    print(f"\n{'  🔴 CRITICAL':20} {counts[SEVERITY_CRITICAL]}")
    print(f"{'  🟠 HIGH':20} {counts[SEVERITY_HIGH]}")
    print(f"{'  🟡 MEDIUM':20} {counts[SEVERITY_MEDIUM]}")
    print(f"{'  🔵 LOW':20} {counts[SEVERITY_LOW]}")
    print()
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
        sev_findings = [f for f in findings if f["severity"] == sev]
        if not sev_findings: continue
        col = COLOR[sev]
        for f in sev_findings:
            print(f"  {col}[{sev}]{COLOR['RESET']} {f['title']}")
            print(f"  {'':9}{COLOR[SEVERITY_INFO]}{f['detail']}{COLOR['RESET']}")
            if f['remediation']:
                print(f"  {'':9}→ {f['remediation']}")
            print()
    score = max(0, 100 - counts[SEVERITY_CRITICAL]*25 - counts[SEVERITY_HIGH]*10 - counts[SEVERITY_MEDIUM]*5)
    grade = "A+" if score >= 95 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D"
    print(f"  Security Score: {score}/100 ({grade})")
    print(f"\n  ~Claris · Semper Fortis · V3.0\n")

# ─── MAIN ────────────────────────────────────────────────────────────────────
def main():
    args = sys.argv[1:]
    do_quick    = "--quick"    in args
    do_full     = "--full"     in args
    do_weekly   = "--weekly"   in args
    do_crons    = "--crons"    in args
    do_perms    = "--permissions" in args
    do_supply   = "--supply-chain" in args
    do_poisoning = "--ai-poisoning" in args
    do_msg_idx  = next((i for i, a in enumerate(args) if a == "--scan-message"), None)

    if do_msg_idx is not None:
        msg = args[do_msg_idx + 1] if do_msg_idx + 1 < len(args) else ""
        result = scan_message(msg)
        print(json.dumps(result, indent=2))
        return

    header("OpenClaw Security Guard V3.0")

    if do_perms or do_full or do_weekly:
        print("  [T10] Checking file permissions...")
        check_permissions()

    if do_full or do_weekly or do_quick:
        print("  [T9/T1] Checking channel configuration...")
        check_channel_config()

    if do_full or do_weekly or do_crons:
        print("  [T3] Auditing cron jobs...")
        check_crons()

    if do_full or do_weekly:
        print("  [T8] Scanning for hardcoded secrets...")
        scan_secrets(WORKSPACE, "workspace")
        check_token_exposure()
        print("  [T5] Checking memory file integrity...")
        check_memory_integrity()
        print("  [T6] Checking skill files...")
        check_skills()
        print("  [T4] Verifying agent bus...")
        check_agent_bus()
        print("  [.git] Checking .gitignore...")
        check_gitignore()
        print("  [T11] Supply chain check (V3.0)...")
        check_supply_chain()
        print("  [T12] AI model poisoning check (V3.0)...")
        check_ai_model_poisoning()

    if do_quick:
        print("  [T8] Quick secrets scan...")
        scan_secrets(WORKSPACE / "skills" / "claris-ai", "claris")
        check_gitignore()
        print("  [T12] Quick AI poisoning check...")
        check_ai_model_poisoning()

    if do_supply:
        print("  [T11] Supply chain check...")
        check_supply_chain()

    if do_poisoning:
        print("  [T12] AI model poisoning check...")
        check_ai_model_poisoning()

    print_report()

    critical = sum(1 for f in findings if f["severity"] == SEVERITY_CRITICAL)
    high = sum(1 for f in findings if f["severity"] == SEVERITY_HIGH)
    sys.exit(2 if critical > 0 else 1 if high > 0 else 0)

if __name__ == "__main__":
    main()

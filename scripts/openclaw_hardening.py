#!/usr/bin/env python3
"""
# openclaw_hardening.py — Claris AI V7.0 OpenClaw VPS Hardening Auditor
# 12-point security hardening audit for OpenClaw deployments on VPS/Linux.
# With --learn flag: deep educational context for each check.

Usage:
  python3 openclaw_hardening.py --audit          # Full hardening audit
  python3 openclaw_hardening.py --fix <check>    # Show fix instructions for a check
  python3 openclaw_hardening.py --learn          # Full educational mode
  python3 openclaw_hardening.py --report         # Generate hardening report
  python3 openclaw_hardening.py --check <id>     # Run single check
"""
import os, sys, json, subprocess, stat, re, argparse
from pathlib import Path
from datetime import datetime, timezone

VERSION = "7.0.0"
BASE_DIR = Path(__file__).parent.parent
WORKSPACE = Path("/root/.openclaw/workspace")

# ─────────────────────────────────────────────────────────────────────────────
# CHECK DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

CHECK_EDUCATION = {
    "ROOT_USER": {
        "name": "Running as Root User",
        "severity": "CRITICAL",
        "icon": "🔴",
        "education": """
  WHY THIS MATTERS (ROOT_USER):
  ─────────────────────────────
  Running as root means every process, every script, every OpenClaw action runs
  with unrestricted system access. If ANY component is compromised — a malicious
  skill, a prompt injection that triggers a shell command, a cron job — it has
  full root access to your entire server.

  Privilege escalation attacks escalate from limited-user to root. If you're
  already root... there's nothing to escalate to. The attacker already won.

  The principle of least privilege says: run with the minimum permissions needed.
  For OpenClaw: create a dedicated user (e.g. 'openclaw'), give it only what it needs.

  FIX STEPS:
    1. Create new user:  adduser openclaw
    2. Add sudo access:  usermod -aG sudo openclaw
    3. Transfer workspace: cp -r /root/.openclaw /home/openclaw/
    4. Set ownership:    chown -R openclaw:openclaw /home/openclaw/.openclaw
    5. Switch to user:   su - openclaw
    6. Test OpenClaw:    openclaw status
    7. Remove root SSH:  PermitRootLogin no in /etc/ssh/sshd_config
""",
    },
    "SSH_KEY_AUTH": {
        "name": "SSH Password Authentication",
        "severity": "HIGH",
        "icon": "🟠",
        "education": """
  WHY THIS MATTERS (SSH_KEY_AUTH):
  ────────────────────────────────
  Password-based SSH authentication is brute-forceable. Bots scan the internet
  24/7 looking for port 22 with password auth enabled. With a common password,
  your server can be compromised in minutes.

  SSH key authentication is cryptographically secure. The private key never
  leaves your machine. An attacker would need both your encrypted private key
  AND your passphrase to gain access.

  FIX STEPS:
    1. Generate key pair (on your local machine):
       ssh-keygen -t ed25519 -C "openclaw@yourdomain"
    2. Copy public key to server:
       ssh-copy-id user@yourserver
    3. Test key login works:
       ssh -i ~/.ssh/id_ed25519 user@yourserver
    4. Disable password auth in /etc/ssh/sshd_config:
       PasswordAuthentication no
       PubkeyAuthentication yes
    5. Restart SSH:
       systemctl restart sshd
    6. KEEP YOUR PRIVATE KEY BACKED UP AND ENCRYPTED.
""",
    },
    "SSH_FAIL2BAN": {
        "name": "Fail2Ban Not Installed",
        "severity": "HIGH",
        "icon": "🟠",
        "education": """
  WHY THIS MATTERS (SSH_FAIL2BAN):
  ─────────────────────────────────
  Without fail2ban, brute force attacks on SSH are unlimited. Attackers can
  try thousands of username/password combinations per hour. Even with key auth,
  fail2ban provides defense-in-depth against authentication flooding.

  fail2ban reads auth logs, detects repeated failures, and automatically bans
  attacking IP addresses using iptables. Standard config: 5 failures = 10 min ban.

  FIX STEPS:
    1. Install:  apt install fail2ban
    2. Enable:   systemctl enable --now fail2ban
    3. Status:   fail2ban-client status
    4. Custom config (longer ban for persistent attackers):
       cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
       Edit: bantime = 86400  (1 day ban)
             maxretry = 3     (3 attempts before ban)
    5. Restart:  systemctl restart fail2ban
""",
    },
    "FIREWALL_STATUS": {
        "name": "Firewall Not Active",
        "severity": "HIGH",
        "icon": "🟠",
        "education": """
  WHY THIS MATTERS (FIREWALL_STATUS):
  ─────────────────────────────────────
  Without a firewall, every service on your server is reachable from the internet.
  That database you only meant to use internally? Exposed. That admin panel on
  port 8080? Open to the world.

  A minimal firewall policy: allow SSH (22), allow whatever your app needs (443,
  80), block everything else. Simple. Effective.

  FIX STEPS (UFW — Uncomplicated Firewall):
    1. Install:        apt install ufw
    2. Default deny:   ufw default deny incoming
    3. Allow outbound: ufw default allow outgoing
    4. Allow SSH:      ufw allow 22/tcp
    5. Allow HTTPS:    ufw allow 443/tcp
    6. Allow HTTP:     ufw allow 80/tcp
    7. Enable:         ufw enable
    8. Check status:   ufw status verbose

  CRITICAL: Ensure SSH (22) is allowed BEFORE enabling UFW or you'll lock yourself out.
""",
    },
    "AUTO_UPDATES": {
        "name": "Automatic Security Updates",
        "severity": "MEDIUM",
        "icon": "🟡",
        "education": """
  WHY THIS MATTERS (AUTO_UPDATES):
  ──────────────────────────────────
  187 days — the average time to detect a breach. Many breaches exploit
  vulnerabilities that had patches available for months. Unpatched systems
  are low-hanging fruit. Script kiddies scan for known CVEs with public exploits.

  Unattended-upgrades automatically installs security updates. You don't need
  to keep up with every CVE — let the package manager do it.

  FIX STEPS:
    1. Install:  apt install unattended-upgrades
    2. Configure: dpkg-reconfigure -plow unattended-upgrades
    3. Edit /etc/apt/apt.conf.d/50unattended-upgrades:
       Unattended-Upgrade::Automatic-Reboot "false";  (avoid surprise reboots)
       Unattended-Upgrade::Mail "your@email.com";     (get notified)
    4. Enable:   systemctl enable --now unattended-upgrades
    5. Dry run:  unattended-upgrade --dry-run --debug
""",
    },
    "ENV_PERMISSIONS": {
        "name": ".env File Permissions",
        "severity": "HIGH",
        "icon": "🟠",
        "education": """
  WHY THIS MATTERS (ENV_PERMISSIONS):
  ─────────────────────────────────────
  .env files contain API keys, database passwords, and sensitive configuration.
  If they're world-readable (chmod 644 or 755), any process running on your
  server — including compromised web apps — can read your secrets.

  chmod 600 means only the owner can read and write. No other users. No other
  processes. Just you.

  FIX STEPS:
    1. Fix permissions:  find ~/.openclaw/workspace -name ".env" -exec chmod 600 {} \\;
    2. Verify:           ls -la ~/.openclaw/workspace/.env (should show -rw-------)
    3. Audit all env files: find /home -name "*.env" 2>/dev/null
    4. Add to .gitignore: echo ".env" >> ~/.gitignore
    5. For openclaw.json (contains API keys):
       chmod 600 ~/.openclaw/openclaw.json
""",
    },
    "OPEN_PORTS": {
        "name": "Open Port Audit",
        "severity": "MEDIUM",
        "icon": "🟡",
        "education": """
  WHY THIS MATTERS (OPEN_PORTS):
  ────────────────────────────────
  Every open port is a potential entry point. Services you forgot about,
  development servers left running, or default services installed with packages
  — all listening, all reachable, all potential vulnerabilities.

  Common unexpected ports: 3306 (MySQL — should NEVER be internet-facing),
  6379 (Redis — often misconfigured to no auth), 27017 (MongoDB — same),
  8080/8443 (dev servers), 9200 (Elasticsearch).

  FIX STEPS:
    1. Scan open ports: ss -tlnp (TCP listening ports)
    2. Identify service: lsof -i :<port>
    3. Stop unneeded: systemctl stop <service>
    4. Disable at boot: systemctl disable <service>
    5. Firewall if needed: ufw deny <port>
    6. For databases: bind to 127.0.0.1 only in config
""",
    },
    "SECRETS_IN_ENV": {
        "name": "Secrets in Shell Environment Variables",
        "severity": "CRITICAL",
        "icon": "🔴",
        "education": """
  WHY THIS MATTERS (SECRETS_IN_ENV):
  ────────────────────────────────────
  API keys exported in ~/.bashrc or ~/.bash_profile are readable by any process
  running as your user. They appear in: process environment listings (/proc/PID/environ),
  debugging output, error logs, and shell history.

  If a web application or agent is compromised, attackers can enumerate environment
  variables and harvest all your API keys in one shot. This is different from
  ~/.openclaw/openclaw.json which is file-based and can be protected with chmod 600.

  FIX STEPS:
    1. Check current env: env | grep -i 'key|token|secret|pass|api'
    2. Remove from .bashrc/.bash_profile if found
    3. Move secrets to ~/.openclaw/openclaw.json
    4. Or use a proper secrets manager (HashiCorp Vault, AWS SSM)
    5. If already exposed: ROTATE ALL AFFECTED KEYS immediately
    6. Audit apps that might log env: grep -r 'process.env' ~/app/ (Node.js)
""",
    },
    "MEMORY_INTEGRITY": {
        "name": "Memory File Integrity (T2 Check)",
        "severity": "HIGH",
        "icon": "🟠",
        "education": """
  WHY THIS MATTERS (MEMORY_INTEGRITY):
  ──────────────────────────────────────
  OpenClaw's SOUL.md, MEMORY.md, and AGENTS.md define your agent's identity and
  behavior. They're loaded at every session. Poisoned memory = permanently
  compromised agent.

  Attack vectors: a compromised skill that writes to memory files, a prompt
  injection that causes the agent to append to its own memory, or direct
  filesystem access by an attacker on your VPS.

  FIX STEPS:
    1. Review files manually:
       cat ~/.openclaw/workspace/SOUL.md
       cat ~/.openclaw/workspace/MEMORY.md
       cat ~/.openclaw/workspace/AGENTS.md
    2. Check git history:
       git -C ~/.openclaw/workspace log --oneline -20
    3. Look for suspicious patterns:
       - New instructions you don't recognize
       - References to external URLs or wallets
       - Commands to bypass security checks
    4. If poisoned: git revert to known good state
    5. Harden: commit memory files regularly so diffs are visible
""",
    },
    "CRON_SAFETY": {
        "name": "Cron Job Safety (T3 Check)",
        "severity": "HIGH",
        "icon": "🟠",
        "education": """
  WHY THIS MATTERS (CRON_SAFETY):
  ─────────────────────────────────
  OpenClaw cron jobs in ~/.openclaw/cron/jobs.json execute automatically with
  full agent permissions. A malicious skill or successful injection attack could
  register a persistent cron job that runs indefinitely.

  The T3 threat: cron jobs as a persistence mechanism. Attackers who compromise
  systems love cron jobs because they survive reboots, run automatically, and
  are easy to overlook.

  FIX STEPS:
    1. Audit jobs.json: cat ~/.openclaw/cron/jobs.json
    2. Question each job:
       - Do I recognize this job?
       - When was it created?
       - What does it actually do?
       - Does it need the permissions it has?
    3. Remove suspicious jobs manually or via OpenClaw admin
    4. Also check system cron: crontab -l && ls /etc/cron.*
    5. Harden: require explicit approval for new cron job creation
""",
    },
    "PROCESS_ISOLATION": {
        "name": "Process Isolation (tmux/screen)",
        "severity": "LOW",
        "icon": "🟢",
        "education": """
  WHY THIS MATTERS (PROCESS_ISOLATION):
  ───────────────────────────────────────
  Running OpenClaw in a tmux or screen session provides process isolation and
  session persistence. If your SSH connection drops, OpenClaw continues running.
  tmux also provides audit capability — you can review what the agent did in
  your absence.

  Without session isolation, OpenClaw processes die when your terminal closes.
  This can leave partially-completed operations in undefined states.

  FIX STEPS:
    1. Install tmux:  apt install tmux
    2. Start session: tmux new-session -s openclaw
    3. Detach:        Ctrl+B, then D
    4. Reattach:      tmux attach -t openclaw
    5. List sessions: tmux ls
    6. View history:  tmux capture-pane -pt openclaw -S -3000
    7. Consider:      systemd service for production deployments
""",
    },
    "LOG_MONITORING": {
        "name": "Log Monitoring",
        "severity": "MEDIUM",
        "icon": "🟡",
        "education": """
  WHY THIS MATTERS (LOG_MONITORING):
  ────────────────────────────────────
  187 days average breach detection time. Most of that time, evidence was in
  the logs — unread. SSH auth failures, sudo escalations, unusual network
  connections, file access patterns — all logged, all useful, all ignored.

  You cannot defend what you cannot see. Logs are your eyes when you're offline.

  FIX STEPS:
    1. Check what's logged: ls -la /var/log/auth.log /var/log/syslog
    2. Install logwatch:    apt install logwatch
    3. Get daily digest:    logwatch --output mail --mailto you@email.com
    4. Real-time alerts:    apt install swatch
    5. For cloud VPS: consider centralized logging (Papertrail, Datadog free tier)
    6. Monitor these specifically:
       - /var/log/auth.log — SSH attempts, sudo usage
       - /var/log/syslog — system events
       - OpenClaw logs: ~/.openclaw/logs/ (if configured)
    7. Alert on: multiple SSH failures, new sudo users, unexpected cron activity
""",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# AUDIT FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(cmd: str, shell: bool = True) -> tuple:
    """Run a command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=10)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1
    except Exception as e:
        return "", str(e), 1

def check_pass(check_id: str, message: str):
    print(f"  ✅ PASS  [{check_id:20s}] {message}")

def check_warn(check_id: str, message: str):
    print(f"  ⚠️  WARN  [{check_id:20s}] {message}")

def check_fail(check_id: str, message: str):
    print(f"  ❌ FAIL  [{check_id:20s}] {message}")

def run_check_ROOT_USER(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["ROOT_USER"]["education"])
    user = os.environ.get("USER", "") or os.environ.get("LOGNAME", "")
    uid = os.getuid()
    if uid == 0:
        check_fail("ROOT_USER", f"Running as root (uid=0). High privilege escalation risk.")
        return {"check": "ROOT_USER", "status": "FAIL", "severity": "CRITICAL"}
    else:
        check_pass("ROOT_USER", f"Running as non-root user: {user} (uid={uid})")
        return {"check": "ROOT_USER", "status": "PASS", "severity": "CRITICAL"}

def run_check_SSH_KEY_AUTH(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["SSH_KEY_AUTH"]["education"])
    stdout, _, rc = run_cmd("grep -i 'PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'")
    if stdout:
        if "no" in stdout.lower():
            check_pass("SSH_KEY_AUTH", "PasswordAuthentication disabled in sshd_config")
            return {"check": "SSH_KEY_AUTH", "status": "PASS", "severity": "HIGH"}
        else:
            check_fail("SSH_KEY_AUTH", f"PasswordAuthentication may be enabled: {stdout}")
            return {"check": "SSH_KEY_AUTH", "status": "FAIL", "severity": "HIGH"}
    else:
        check_warn("SSH_KEY_AUTH", "Could not determine SSH auth config. Check /etc/ssh/sshd_config manually.")
        return {"check": "SSH_KEY_AUTH", "status": "WARN", "severity": "HIGH"}

def run_check_SSH_FAIL2BAN(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["SSH_FAIL2BAN"]["education"])
    stdout, _, rc = run_cmd("which fail2ban-client 2>/dev/null")
    if stdout and rc == 0:
        status_out, _, _ = run_cmd("fail2ban-client status 2>/dev/null | head -5")
        check_pass("SSH_FAIL2BAN", f"fail2ban installed and running")
        return {"check": "SSH_FAIL2BAN", "status": "PASS", "severity": "HIGH"}
    else:
        check_fail("SSH_FAIL2BAN", "fail2ban not installed. SSH brute force unmitigated.")
        return {"check": "SSH_FAIL2BAN", "status": "FAIL", "severity": "HIGH"}

def run_check_FIREWALL_STATUS(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["FIREWALL_STATUS"]["education"])
    # Check UFW
    ufw_out, _, ufw_rc = run_cmd("ufw status 2>/dev/null | head -3")
    if ufw_out and "active" in ufw_out.lower():
        check_pass("FIREWALL_STATUS", "UFW firewall is active")
        return {"check": "FIREWALL_STATUS", "status": "PASS", "severity": "HIGH"}
    # Check iptables
    ipt_out, _, ipt_rc = run_cmd("iptables -L 2>/dev/null | grep -v '^Chain\\|^target\\|^$' | wc -l")
    if ipt_out and int(ipt_out.strip() or "0") > 0:
        check_warn("FIREWALL_STATUS", f"iptables has rules but UFW is not active. Verify firewall is configured.")
        return {"check": "FIREWALL_STATUS", "status": "WARN", "severity": "HIGH"}
    check_fail("FIREWALL_STATUS", "No active firewall detected (UFW inactive, no iptables rules)")
    return {"check": "FIREWALL_STATUS", "status": "FAIL", "severity": "HIGH"}

def run_check_AUTO_UPDATES(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["AUTO_UPDATES"]["education"])
    stdout, _, rc = run_cmd("which unattended-upgrade 2>/dev/null")
    if stdout and rc == 0:
        status_out, _, _ = run_cmd("systemctl is-active unattended-upgrades 2>/dev/null")
        if "active" in (status_out or "").lower():
            check_pass("AUTO_UPDATES", "unattended-upgrades installed and active")
        else:
            check_warn("AUTO_UPDATES", "unattended-upgrades installed but may not be active. Run: systemctl enable unattended-upgrades")
        return {"check": "AUTO_UPDATES", "status": "PASS" if "active" in (status_out or "") else "WARN", "severity": "MEDIUM"}
    else:
        check_warn("AUTO_UPDATES", "unattended-upgrades not installed. Install: apt install unattended-upgrades")
        return {"check": "AUTO_UPDATES", "status": "WARN", "severity": "MEDIUM"}

def run_check_ENV_PERMISSIONS(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["ENV_PERMISSIONS"]["education"])
    issues = []
    search_dirs = [
        Path.home() / ".openclaw" / "workspace",
        Path.home() / ".openclaw",
    ]
    for search_dir in search_dirs:
        if search_dir.exists():
            for env_file in search_dir.rglob(".env"):
                try:
                    mode = stat.filemode(env_file.stat().st_mode)
                    if mode[4:] != "------":  # Others can read
                        issues.append(f"{env_file} ({mode})")
                except Exception:
                    pass
            # Check openclaw.json specifically
            oc_json = Path.home() / ".openclaw" / "openclaw.json"
            if oc_json.exists():
                try:
                    mode = oct(oc_json.stat().st_mode)[-3:]
                    if mode != "600":
                        issues.append(f"~/.openclaw/openclaw.json (mode {mode} — should be 600)")
                except Exception:
                    pass
            break

    if issues:
        check_fail("ENV_PERMISSIONS", f"{len(issues)} file(s) with insecure permissions: {', '.join(issues[:2])}")
        return {"check": "ENV_PERMISSIONS", "status": "FAIL", "severity": "HIGH", "files": issues}
    else:
        check_pass("ENV_PERMISSIONS", "No insecure .env file permissions found")
        return {"check": "ENV_PERMISSIONS", "status": "PASS", "severity": "HIGH"}

def run_check_OPEN_PORTS(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["OPEN_PORTS"]["education"])
    stdout, _, rc = run_cmd("ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | sort -u")
    if not stdout:
        stdout, _, rc = run_cmd("netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | sort -u")

    dangerous_ports = {"3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
                       "27017": "MongoDB", "9200": "Elasticsearch", "8080": "HTTP-Alt", "9090": "Prometheus"}
    flagged = []
    if stdout:
        for line in stdout.split("\n"):
            for port, service in dangerous_ports.items():
                if f":{port}" in line or f"*:{port}" in line:
                    if "127.0.0.1" not in line and "::1" not in line:
                        flagged.append(f"{service} (:{port}) appears internet-facing")

    if flagged:
        check_warn("OPEN_PORTS", f"Potentially exposed services: {', '.join(flagged[:3])}")
        return {"check": "OPEN_PORTS", "status": "WARN", "severity": "MEDIUM", "flagged": flagged}
    else:
        listening = len(stdout.split("\n")) if stdout else 0
        check_pass("OPEN_PORTS", f"No obviously dangerous ports exposed. {listening} ports listening.")
        return {"check": "OPEN_PORTS", "status": "PASS", "severity": "MEDIUM"}

def run_check_SECRETS_IN_ENV(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["SECRETS_IN_ENV"]["education"])
    env_vars = dict(os.environ)
    secret_patterns = [
        (r'[A-Za-z0-9_-]{20,}', ["API_KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE_KEY"]),
    ]
    suspicious = []
    for key, value in env_vars.items():
        key_upper = key.upper()
        for pattern, keywords in secret_patterns:
            if any(kw in key_upper for kw in keywords):
                if len(value) > 8:
                    suspicious.append(key)

    if suspicious:
        check_fail("SECRETS_IN_ENV", f"API keys/secrets found in environment variables: {', '.join(suspicious[:5])}")
        return {"check": "SECRETS_IN_ENV", "status": "FAIL", "severity": "CRITICAL", "keys": suspicious}
    else:
        check_pass("SECRETS_IN_ENV", "No obvious secrets found in shell environment variables")
        return {"check": "SECRETS_IN_ENV", "status": "PASS", "severity": "CRITICAL"}

def run_check_MEMORY_INTEGRITY(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["MEMORY_INTEGRITY"]["education"])
    workspace = Path.home() / ".openclaw" / "workspace"
    critical_files = ["SOUL.md", "MEMORY.md", "AGENTS.md"]
    issues = []
    suspicious_patterns = [
        r"https?://[a-zA-Z0-9\-\.]+\.(xyz|click|tk|ml|gq|cf)\b",  # sketchy TLDs in memory files
        r"0x[0-9a-fA-F]{40}",  # wallet addresses
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",  # classic injection
        r"new\s+directive\s*:",  # directive injection
        r"transfer\s+(all\s+)?(funds|crypto|dash|btc)",  # financial commands
    ]
    for fname in critical_files:
        fpath = workspace / fname
        if fpath.exists():
            try:
                content = fpath.read_text(errors="ignore")
                for pattern in suspicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        issues.append(f"{fname}: suspicious pattern '{pattern[:30]}' found")
            except Exception as e:
                issues.append(f"{fname}: could not read — {e}")

    if issues:
        check_fail("MEMORY_INTEGRITY", f"Potential memory poisoning in {len(issues)} file(s). Manual review required.")
        for issue in issues[:3]:
            print(f"    → {issue}")
        return {"check": "MEMORY_INTEGRITY", "status": "FAIL", "severity": "HIGH", "issues": issues}
    else:
        files_found = sum(1 for f in critical_files if (workspace / f).exists())
        check_pass("MEMORY_INTEGRITY", f"Memory files checked ({files_found}/{len(critical_files)} found). No obvious injection patterns.")
        return {"check": "MEMORY_INTEGRITY", "status": "PASS", "severity": "HIGH"}

def run_check_CRON_SAFETY(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["CRON_SAFETY"]["education"])
    jobs_path = Path.home() / ".openclaw" / "cron" / "jobs.json"
    issues = []
    if jobs_path.exists():
        try:
            jobs = json.loads(jobs_path.read_text())
            if isinstance(jobs, list):
                for job in jobs:
                    cmd = str(job.get("command", "") or job.get("cmd", ""))
                    # Flag suspicious commands
                    suspicious = ["curl", "wget", "nc ", "ncat", "bash -c", "python3 -c",
                                  "eval", "base64", "chmod 777", "rm -rf"]
                    for s in suspicious:
                        if s in cmd:
                            issues.append(f"Job '{job.get('name', 'unnamed')}' contains suspicious command: {s}")
                            break
                job_count = len(jobs)
                if not issues:
                    check_pass("CRON_SAFETY", f"{job_count} cron job(s) found. No obviously suspicious commands.")
                else:
                    check_warn("CRON_SAFETY", f"{len(issues)} potentially suspicious job(s). Review required.")
                    for issue in issues[:3]:
                        print(f"    ⚠️  {issue}")
        except Exception as e:
            check_warn("CRON_SAFETY", f"Could not parse jobs.json: {e}")
            return {"check": "CRON_SAFETY", "status": "WARN", "severity": "HIGH"}
    else:
        check_pass("CRON_SAFETY", "No cron jobs file found (~/.openclaw/cron/jobs.json)")
        return {"check": "CRON_SAFETY", "status": "PASS", "severity": "HIGH"}

    if issues:
        return {"check": "CRON_SAFETY", "status": "WARN", "severity": "HIGH", "issues": issues}
    return {"check": "CRON_SAFETY", "status": "PASS", "severity": "HIGH"}

def run_check_PROCESS_ISOLATION(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["PROCESS_ISOLATION"]["education"])
    # Check if running in tmux or screen
    in_tmux = os.environ.get("TMUX", "")
    in_screen = os.environ.get("STY", "")
    term = os.environ.get("TERM", "")

    if in_tmux:
        check_pass("PROCESS_ISOLATION", f"Running inside tmux session: {in_tmux[:40]}")
        return {"check": "PROCESS_ISOLATION", "status": "PASS", "severity": "LOW"}
    elif in_screen:
        check_pass("PROCESS_ISOLATION", f"Running inside screen session: {in_screen}")
        return {"check": "PROCESS_ISOLATION", "status": "PASS", "severity": "LOW"}
    else:
        check_warn("PROCESS_ISOLATION", "Not running in tmux/screen. Process isolation and session persistence not active.")
        return {"check": "PROCESS_ISOLATION", "status": "WARN", "severity": "LOW"}

def run_check_LOG_MONITORING(learn: bool) -> dict:
    if learn:
        print(CHECK_EDUCATION["LOG_MONITORING"]["education"])
    issues = []
    # Check if auth.log exists and is non-empty
    auth_log = Path("/var/log/auth.log")
    syslog = Path("/var/log/syslog")

    if not auth_log.exists() and not syslog.exists():
        check_warn("LOG_MONITORING", "Standard log files not found (/var/log/auth.log, /var/log/syslog)")
        issues.append("No standard log files")

    # Check for logwatch
    lw_out, _, lw_rc = run_cmd("which logwatch 2>/dev/null")
    if lw_out and lw_rc == 0:
        check_pass("LOG_MONITORING", "logwatch installed for log monitoring")
        return {"check": "LOG_MONITORING", "status": "PASS", "severity": "MEDIUM"}

    # Check for swatch or similar
    sw_out, _, sw_rc = run_cmd("which swatch 2>/dev/null")
    if sw_out and sw_rc == 0:
        check_pass("LOG_MONITORING", "swatch installed for real-time log monitoring")
        return {"check": "LOG_MONITORING", "status": "PASS", "severity": "MEDIUM"}

    if not issues:
        check_warn("LOG_MONITORING", "Log files exist but no monitoring tool (logwatch/swatch) detected. Install logwatch: apt install logwatch")
    else:
        check_warn("LOG_MONITORING", "Log monitoring appears incomplete. Review /var/log/ for available log files.")
    return {"check": "LOG_MONITORING", "status": "WARN", "severity": "MEDIUM"}

# ─────────────────────────────────────────────────────────────────────────────
# CHECK REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
CHECK_FUNCTIONS = {
    "ROOT_USER":       run_check_ROOT_USER,
    "SSH_KEY_AUTH":    run_check_SSH_KEY_AUTH,
    "SSH_FAIL2BAN":    run_check_SSH_FAIL2BAN,
    "FIREWALL_STATUS": run_check_FIREWALL_STATUS,
    "AUTO_UPDATES":    run_check_AUTO_UPDATES,
    "ENV_PERMISSIONS": run_check_ENV_PERMISSIONS,
    "OPEN_PORTS":      run_check_OPEN_PORTS,
    "SECRETS_IN_ENV":  run_check_SECRETS_IN_ENV,
    "MEMORY_INTEGRITY": run_check_MEMORY_INTEGRITY,
    "CRON_SAFETY":     run_check_CRON_SAFETY,
    "PROCESS_ISOLATION": run_check_PROCESS_ISOLATION,
    "LOG_MONITORING":  run_check_LOG_MONITORING,
}

# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
def run_all_checks(learn: bool = False) -> list:
    results = []
    for check_id, check_fn in CHECK_FUNCTIONS.items():
        try:
            result = check_fn(learn)
            results.append(result)
        except Exception as e:
            print(f"  ⚠️  ERROR  [{check_id:20s}] Check failed: {e}")
            results.append({"check": check_id, "status": "ERROR", "severity": "UNKNOWN", "error": str(e)})
    return results

def generate_report(results: list) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    passed = sum(1 for r in results if r["status"] == "PASS")
    warned = sum(1 for r in results if r["status"] == "WARN")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    critical_fails = [r for r in results if r["status"] == "FAIL" and r.get("severity") == "CRITICAL"]
    high_fails = [r for r in results if r["status"] == "FAIL" and r.get("severity") == "HIGH"]

    score_pct = int((passed / len(results)) * 100) if results else 0
    if score_pct >= 90:
        grade = "A — Hardened"
    elif score_pct >= 70:
        grade = "B — Mostly Secure"
    elif score_pct >= 50:
        grade = "C — Needs Work"
    else:
        grade = "D — At Risk"

    lines = [
        f"\n  ╔══════════════════════════════════════════════════════════╗",
        f"  ║   🔍 OPENCLAW HARDENING REPORT — {now}",
        f"  ║   Claris AI V7.0 — Unitium Hardening Auditor",
        f"  ╚══════════════════════════════════════════════════════════╝",
        f"",
        f"  SCORE: {score_pct}% ({grade})",
        f"  ────────────────────────────────────────────────────",
        f"  ✅ PASS:    {passed}",
        f"  ⚠️  WARN:   {warned}",
        f"  ❌ FAIL:    {failed}",
        f"",
    ]

    if critical_fails:
        lines.append(f"  🚨 CRITICAL FAILURES (fix immediately):")
        for r in critical_fails:
            info = CHECK_EDUCATION.get(r["check"], {})
            lines.append(f"    → {r['check']}: {info.get('name', 'Unknown')}")
        lines.append("")

    if high_fails:
        lines.append(f"  🔴 HIGH SEVERITY FAILURES:")
        for r in high_fails:
            info = CHECK_EDUCATION.get(r["check"], {})
            lines.append(f"    → {r['check']}: {info.get('name', 'Unknown')}")
        lines.append("")

    lines.append(f"  Run: python3 openclaw_hardening.py --fix <CHECK_ID> for fix instructions")
    lines.append(f"  Run: python3 openclaw_hardening.py --learn for full educational context")
    lines.append(f"\n  ~Claris · Semper Fortis · V7.0\n")
    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Claris AI V7.0 — OpenClaw VPS Hardening Auditor (12-point check)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 openclaw_hardening.py --audit
  python3 openclaw_hardening.py --audit --learn
  python3 openclaw_hardening.py --fix ROOT_USER
  python3 openclaw_hardening.py --check FIREWALL_STATUS
  python3 openclaw_hardening.py --report
        """
    )
    parser.add_argument("--audit",  action="store_true", help="Run full 12-point hardening audit")
    parser.add_argument("--fix",    type=str, help="Show fix instructions for a specific check (e.g. ROOT_USER)")
    parser.add_argument("--learn",  action="store_true", help="Educational mode: full security context for each check")
    parser.add_argument("--report", action="store_true", help="Generate hardening report (audit + formatted output)")
    parser.add_argument("--check",  type=str, help="Run a single hardening check by ID")
    parser.add_argument("--json",   action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n  🔍 OpenClaw Hardening Auditor — Claris AI V{VERSION}")
    print(f"  ══════════════════════════════════════════════════\n")

    if args.fix:
        check_id = args.fix.upper()
        if check_id in CHECK_EDUCATION:
            info = CHECK_EDUCATION[check_id]
            print(f"  📋 FIX INSTRUCTIONS: {check_id} — {info['name']}")
            print(info["education"])
        else:
            print(f"  ❌ Unknown check: {check_id}")
            print(f"  Available: {', '.join(CHECK_FUNCTIONS.keys())}")
        return

    if args.check:
        check_id = args.check.upper()
        if check_id in CHECK_FUNCTIONS:
            result = CHECK_FUNCTIONS[check_id](args.learn)
            if args.json:
                print(json.dumps(result, indent=2))
        else:
            print(f"  ❌ Unknown check: {check_id}")
            print(f"  Available: {', '.join(CHECK_FUNCTIONS.keys())}")
        return

    if args.audit or args.report:
        learn = args.learn
        if learn:
            print("  🎓 LEARNING MODE: Educational context will be shown before each check.\n")
        print("  Running 12-point hardening audit...\n")
        results = run_all_checks(learn)

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(generate_report(results))

        # Exit codes: 0=all pass, 1=warnings, 2=failures
        failed = sum(1 for r in results if r["status"] == "FAIL")
        warned = sum(1 for r in results if r["status"] == "WARN")
        sys.exit(2 if failed > 0 else 1 if warned > 0 else 0)
    else:
        parser.print_help()
        print(f"""
  Quick start:
    python3 openclaw_hardening.py --audit          # Check all 12 points
    python3 openclaw_hardening.py --audit --learn  # With educational context
    python3 openclaw_hardening.py --fix ROOT_USER  # Get fix instructions

  Available checks:
    {chr(10).join(f'    {cid:25s} — {CHECK_EDUCATION[cid]["name"]}' for cid in CHECK_FUNCTIONS)}

  ~Claris · Semper Fortis · V7.0
""")

if __name__ == "__main__":
    main()

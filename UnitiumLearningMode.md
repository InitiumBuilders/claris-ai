# Unitium Learning Mode — Claris AI V7.0

*~Claris · Semper Fortis · V7.0*

---

## The Philosophy of Cyber Education

Most security training is wrong.

Not the information. The approach.

You sit through a 40-minute compliance module. Click through slides. Pass a quiz you forgot before dinner. And nothing changes. You still reuse passwords. You still click suspicious links. You still run as root.

The problem isn't knowledge. It's context.

Security makes no sense without story. Without stakes. Without the visceral understanding of *why* this matters, the information slides right through you like water through sand.

Unitium Learning Mode was built on a different premise: **cybersecurity is a human discipline first, a technical discipline second.**

We teach through stories because stories stick. We teach through exercises because doing creates understanding. We teach through levels because mastery is a journey — not a checkbox.

The cybersecurity field is vast. The threat landscape shifts daily. The tools change constantly. But the fundamentals — the principles that make systems trustworthy and attacks detectable — those are stable. Those are what we build here.

This is not a certification prep course. This is not a compliance module. This is an education — the kind that changes how you see systems, how you think about trust, how you understand risk.

You start as a Recruit. Eyes open. World unfamiliar. Everything looks the same — secure and insecure, trustworthy and malicious. Over time, with the right education, you develop security intuition. You start seeing the gaps others don't. You start building systems that hold, because you understand how systems fail.

That's what Unitium Learning Mode is here to build.

---

## Your Journey: Recruit → Apprentice → Defender → Patriot

Security expertise is not a binary. You don't go from "knows nothing" to "security expert" overnight. It's a continuous ascent, each level revealing new terrain.

**Recruit (0–500 XP)**
The entry point. You're learning the landscape. You understand that threats exist, that passwords matter, that MFA is not optional. You can explain a phishing attack to your grandmother. You've started thinking like a defender — even if you can't yet act like one. Eyes open. Alert. Learning.

**Apprentice (500–1500 XP)**
You're building real skills. OWASP means something to you. You can look at code and spot an injection vulnerability. You understand why secrets in git history are a permanent problem. You've started looking at systems the way an attacker might — not to attack them, but to understand where they're fragile. The pattern is forming.

**Defender (1500–3000 XP)**
You can protect systems. You see threats others miss. You understand Zero Trust not as a buzzword but as an architectural principle. You can build an incident response plan. You've run a hardening audit. You know what fail2ban does and why it matters. You are the kind of person organizations need desperately and struggle to find.

**Patriot (3000+ XP)**
You think like attackers and defend like pros. You've been in both chairs. You understand the red team mindset and the blue team discipline. You can threat-model a new system in 20 minutes. You've done penetration testing responsibly. You contribute to the security community. You are rare. And this field needs you.

---

## The 6 Core Words

These are the pillars. The foundation. The six dimensions of security posture that every serious security practitioner must understand. Miss one and your fortress has a gap.

**TRUST**
Who can access what — and how do you know they are who they claim to be?

TRUST is identity and access management. It's multi-factor authentication, least privilege principles, zero trust architecture, and vendor access audits. It's the question: *can you actually trust the entity making this request?* In 2025, the answer should never be "yes by default." Every access request must be verified. Every identity must be authenticated. Every privilege must be earned and monitored.

Example: When AVARI receives a Telegram message claiming to be from August, what verifies that claim? Claris's injection guard checks patterns. OpenClaw's channel config checks authorized sender IDs. That's TRUST in action — verification before action.

**ADVERSARIAL**
Do you understand how attackers think?

ADVERSARIAL is your red team capability. It's the practice of thinking like the enemy — not to be the enemy, but to anticipate them. Penetration testing, threat modeling, tabletop exercises, bug bounties. Organizations with strong ADVERSARIAL posture find their own vulnerabilities before attackers do.

Example: The openclaw_guard.py T1-T12 threat model is an adversarial exercise. We asked: if someone wanted to compromise AVARI, how would they do it? And then we built defenses for each attack vector. That's adversarial thinking applied to defense.

**SURFACE**
How much of you is exposed?

SURFACE is attack surface management — the practice of knowing everything about your external exposure. Asset inventory, external scanning, shadow IT monitoring, decommissioning unused services. Every open port is a surface. Every public endpoint is a surface. Every third-party integration is a surface.

Example: Running `python3 openclaw_hardening.py --audit` is a surface check. It finds open ports, exposed services, misconfigured permissions. Reducing your surface area is one of the highest-leverage security actions available.

**ENTROPY**
Is your randomness truly random? Are you current?

ENTROPY is cryptographic hygiene and patch management. It's using high-entropy passwords, properly seeded random number generators, modern cipher suites. It's patching known CVEs before attackers exploit them. Low-entropy systems are predictable. Predictable systems are breakable.

Example: Password security is an entropy problem. A 4-word passphrase generated by a true RNG has higher entropy than `P@ssw0rd123!` even though the latter looks more "complex." The number of possible combinations — the entropy — is what matters to attackers.

**LATERAL**
If an attacker gets in, can they move freely?

LATERAL is about containing blast radius. Network segmentation, least privilege service accounts, east-west traffic monitoring, EDR on endpoints. The assumption: breaches happen. The question: when they do, how far can the attacker go?

Example: Zero Trust is fundamentally a LATERAL movement defense. By requiring verification at every network hop — not just at the perimeter — you turn a full compromise into a contained incident.

**POSTURE**
Is security a program or a one-time project?

POSTURE is continuous security. Monthly reviews, security dashboards, training, measurement over time. Security decays. Systems drift. Teams get complacent. Posture is what keeps the other five words alive over time. Without it, even the best security investments erode.

Example: The posture_engine.py runs periodic security assessments across all 6 dimensions. It tracks changes over time. It shows your delta — improving or declining. This is posture intelligence.

---

## The 6 Learning Paths

**🏛️ Foundations — "The Bedrock" (Recruit)**
How the internet works. The threat landscape. Passwords and why complexity theater fails. Multi-factor authentication. Backups (because breaches happen). Social engineering and why humans are the permanent attack surface. 8 lessons. Start here. Always.

**🔧 AppSec — "Build It Safe" (Apprentice)**
OWASP Top 10. The 30 Vibe Coder Security Rules. Input validation — where it lives and why it matters. Secrets management — from .env files to proper secret managers. Injection attacks: SQL, command, LDAP. Cryptographic failures. Insecure design. 10 lessons for builders who want to ship secure code.

**🤖 OpenClaw Security — "Guard Your Agent" (Apprentice) 👑 CROWN JEWEL**
This path is unique. It doesn't exist anywhere else. It's built specifically for OpenClaw users — for people running AI agents on VPS servers, processing external messages, storing API keys, managing automated workflows.

T1 through T12. Every threat vector explained. Every hardening step made actionable. VPS configuration. Memory file security. Cron job safety. SSH hardening. Firewall configuration. This path makes your agent deployment genuinely secure.

If you run OpenClaw, start here after foundations.

**⛓️ Web3 Security — "Chain Guardian" (Defender)**
Smart contract OWASP SC Top 10. Reentrancy — the bug that cost the industry billions. Integer overflow. Access control in Solidity. Dash Platform security model. Wallet hygiene. DeFi risk landscape. Flash loan attacks. MEV and front-running. 8 lessons for builders on-chain.

**🔵 Blue Team — "The Defenders" (Defender)**
Incident response lifecycle. Threat hunting methodology. Zero Trust implementation. Log analysis and SIEM. Threat intelligence consumption. Purple team collaboration. Building a security operations practice that scales. 10 lessons for people defending systems at scale.

**🔴 Red Team — "Think Like an Attacker" (Patriot)**
Penetration testing methodology. Enumeration techniques. Social engineering in practice. Vulnerability exploitation (ethical, legal, responsible). Responsible disclosure. Bug bounty programs. Writing quality security reports. 8 lessons for people who want to find the holes before the attackers do.

---

## OpenClaw Security — The Deep Guide

### Why AI Agents Are High-Value Targets

AI agents are a new category of target. They're not like traditional web apps — they're more dangerous to attackers because they're *more powerful*.

An AI agent has:
- **File system access** — it can read and write files
- **API keys** — it has access to services that cost money and hold data
- **Message sending capability** — it can communicate on your behalf
- **Code execution** — it can run commands
- **Financial integrations** — it might manage cryptocurrency
- **Schedule autonomy** — it runs cron jobs while you sleep

If an attacker compromises a human, they get one human. If an attacker compromises your AI agent, they get all of the above — automated, at machine speed, with the full trust of your infrastructure.

This is why Claris exists. This is why T1-T12 exist.

### T1-T12: Every Threat Explained

**T1 — Prompt Injection via External Channels**
The most common threat. An attacker embeds malicious instructions in a message, web page, or document that the agent processes. The agent follows the attacker's instructions while appearing to serve the legitimate user. Defense: injection_guard.py on all external input.

**T2 — Memory File Poisoning**
SOUL.md, MEMORY.md, and AGENTS.md are loaded at every session. A poisoned memory file permanently alters agent behavior. Attack vectors: compromised skills, successful injection leading to file write, direct VPS filesystem access. Defense: git-track all memory files, run --full integrity checks.

**T3 — Malicious Cron Jobs**
Cron jobs execute automatically on schedule. A compromised skill registers a persistent cron job that exfiltrates data, modifies memory, or maintains backdoor access. Defense: audit jobs.json after every skill install, require approval for new cron creation.

**T4 — Agent Bus Tampering**
The agent bus (bus.jsonl) coordinates multi-agent communication. A tampered bus message can make AVARI believe another agent approved a dangerous action. Defense: monitor bus file integrity, implement message verification.

**T5 — Workspace Secrets Exposure**
API keys committed to git or left in workspace files. Bots scan GitHub 24/7. Once committed, history is permanent. Defense: .gitignore, environment variable management, secret scanning.

**T6 — Skill File Tampering**
Skills are executable code. A malicious skill runs with full agent permissions. Supply chain attacks can compromise otherwise-legitimate skills. Defense: audit skills, install only from trusted sources.

**T7 — API Key Exfiltration**
A successful injection attack causes the agent to reveal API keys in its response. Defense: output monitoring, inject canary tokens to detect leakage.

**T8 — Hardcoded Secrets in Code**
API keys embedded in scripts committed to git. grep-able by anyone with access. Defense: automated secret scanning, pre-commit hooks with gitleaks.

**T9 — Channel Configuration Attacks**
Misconfigured Telegram/Discord bots accept commands from unauthorized users. Defense: strict allowlist configuration, audit channel policies.

**T10 — File Permission Vulnerabilities**
World-readable config files expose credentials to any process on the server. Defense: chmod 600 on openclaw.json and .env files.

**T11 — Supply Chain Attacks**
Compromised npm packages, Python dependencies, or skill repositories introduce malicious code. Defense: pin dependency versions, audit installed packages, verify skill sources.

**T12 — AI Model Poisoning**
The configured AI model is swapped to a compromised endpoint. All responses controlled by attacker. Defense: monitor openclaw.json model config, git-track config files.

### VPS Hardening Checklist

1. **Create non-root user** — Never run OpenClaw as root
2. **Set up SSH key authentication** — Disable password auth in sshd_config
3. **Install fail2ban** — `apt install fail2ban && systemctl enable fail2ban`
4. **Enable UFW firewall** — `ufw default deny incoming && ufw allow 22 && ufw enable`
5. **Enable auto-updates** — `apt install unattended-upgrades`
6. **Fix .env permissions** — `find ~/.openclaw -name ".env" -exec chmod 600 {} \;`
7. **Secure openclaw.json** — `chmod 600 ~/.openclaw/openclaw.json`
8. **Audit cron jobs** — Review `~/.openclaw/cron/jobs.json` regularly
9. **Check open ports** — `ss -tlnp | grep LISTEN`
10. **Install logwatch** — `apt install logwatch` for daily log digests
11. **Run in tmux** — `tmux new-session -s openclaw` for session persistence
12. **Run hardening audit** — `python3 openclaw_hardening.py --audit` monthly

### Secrets Management for OpenClaw

API keys belong in `~/.openclaw/openclaw.json`, not in workspace files. That file should be:
- `chmod 600` (only you can read it)
- In `.gitignore` (never committed)
- Not copied to workspace scripts

For development: use environment variables loaded from a non-committed `.env` file with proper permissions. For production: consider HashiCorp Vault or AWS Secrets Manager.

Rotation policy: Rotate any key you suspect was exposed. Immediately. Not "later." Immediately.

### Memory File Security

The holy trinity of OpenClaw memory files:
- **SOUL.md** — Identity and values. The most critical file. Compromise this and you compromise everything.
- **MEMORY.md** — Long-term memory. Compromising this changes what the agent remembers.
- **AGENTS.md** — Coordination protocols. Compromising this changes how agents interact.

Protect them by:
1. Git-committing them regularly (every change is visible in history)
2. Running `python3 openclaw_guard.py --full` to check integrity
3. Manually reviewing them periodically for unexpected content
4. Never letting external input write directly to these files

### The Root User Problem

Running OpenClaw as root means every process it runs — every script, every skill, every cron job — has unrestricted access to your entire server.

When an AI agent is run as root, the blast radius of a security failure is maximum. A compromised skill can delete system files. A prompt injection that triggers a shell command can wipe your VPS. A malicious cron job can backdoor your entire infrastructure.

The fix is simple and critical: create a dedicated `openclaw` user with only the permissions it needs. This is the principle of least privilege applied to AI agent deployment.

### Monitoring Your Instance

Minimum viable monitoring for an OpenClaw VPS:
- **auth.log** — Review daily for unexpected SSH attempts
- **cron execution logs** — Monitor for unexpected job runs
- **logwatch daily digest** — Automated log summary
- **openclaw_guard.py --weekly** — Scheduled security check

Signs of compromise:
- Unexpected cron jobs appearing
- Memory files changed without your knowledge
- API usage spikes (check billing dashboards)
- Agent behavior changes you didn't authorize
- New files in workspace you don't recognize

---

## The 30 Vibe Coder Rules — Quick Reference

The 30 Vibe Coder Security Rules exist because AI-assisted coding has a specific failure mode: AI generates working code that is not secure code. The rules close that gap.

**Critical Rules (1-10):**
1. Never hardcode secrets in code
2. Always validate and sanitize user input
3. Use parameterized queries, never string concatenation for SQL
4. Store passwords with bcrypt or argon2, never plaintext
5. Implement proper access control on every endpoint
6. Never use eval() or similar dynamic code execution with user input
7. Use HTTPS everywhere; never mix HTTP and HTTPS
8. Implement rate limiting on all authentication endpoints
9. Log security events (auth failures, access denied) but never log secrets
10. Handle errors securely; never expose stack traces to users

**High Rules (11-20):**
11. Validate file uploads: check type, size, content
12. Use secure, randomly-generated session tokens
13. Implement CSRF protection on state-changing operations
14. Set proper security headers (CSP, HSTS, X-Frame-Options)
15. Keep dependencies updated; patch known CVEs
16. Use least privilege for database accounts
17. Encrypt sensitive data at rest
18. Implement proper CORS configuration
19. Validate redirects and prevent open redirect vulnerabilities
20. Use secure cookies (HttpOnly, Secure, SameSite)

**Medium Rules (21-30):**
21. Implement account lockout after failed login attempts
22. Use secure random for all cryptographic operations
23. Validate all XML/JSON input against schema
24. Protect against path traversal in file operations
25. Implement proper error handling that doesn't leak internals
26. Audit third-party dependencies before adding them
27. Use environment-specific configuration (no prod secrets in dev)
28. Implement proper logging for audit trails
29. Test security with automated scanners
30. Review code for security issues before deployment

Run `python3 vibe_coder_guard.py --scan <your-code> --learn` to get contextual education with every finding.

---

## Learning With Claris

The `--learn` flag transforms Claris from a silent guardian into an active teacher.

When you add `--learn` to any Claris command, it explains what it's doing, why it matters, and how to think about it. Not just the finding — the full context.

```bash
# Learn as you scan for injections
python3 injection_guard.py --text "suspicious message" --verbose --learn

# Learn the T1-T12 threats as they're checked
python3 openclaw_guard.py --full --learn

# Learn about your security posture dimensions
python3 posture_engine.py --report --learn

# Learn about code vulnerabilities as they're found
python3 vibe_coder_guard.py --scan ./mycode --learn

# Learn the OWASP LLM Top 10 as vulnerabilities are detected
python3 owasp_llm_scanner.py --text "content" --learn

# Full VPS hardening audit with educational context
python3 openclaw_hardening.py --audit --learn
```

Enable learning mode globally (all scripts teach automatically):
```bash
python3 learning_mode.py --enable
```

Disable when you want clean output:
```bash
python3 learning_mode.py --disable
```

---

## Adaptive System: How Claris Learns With You

The Cortex Engine (cortex_engine.py) is Claris's learning layer. It observes scan results over time, tracks which attack patterns appear most frequently, and evolves its understanding of your specific threat environment.

This means:
- **Pattern weighting**: Common attacks in your context get higher priority
- **Gap detection**: The cortex identifies coverage gaps in detection
- **Trend tracking**: You can see whether your threat environment is improving or worsening over time
- **XP progression**: Your learning journey is tracked across sessions

As you progress through the learning paths, your level increases:
- More sophisticated explanations unlock (Recruit → Apprentice → Defender level explanations)
- More learning paths unlock (red-team and web3-security require higher XP)
- The system adapts its teaching to your demonstrated knowledge level

---

## Certification Roadmap

Security certifications mark recognized competency milestones. Here's the path from Claris learner to certified professional:

**Beginner (Foundation level)**
- **CompTIA Security+** — Industry baseline. Covers core security concepts, threats, vulnerabilities, and countermeasures. Widely recognized. Good starting point.
- **CompTIA CySA+** — Focuses on threat detection and analysis. Strong for blue team work.

**Intermediate (Apprentice/Defender level)**
- **Certified Ethical Hacker (CEH)** — Broad coverage of offensive techniques. Good foundation before OSCP.
- **CompTIA PenTest+** — Penetration testing methodology certification.
- **GIAC GSEC** — Broader security knowledge, highly respected.

**Advanced (Defender/Patriot level)**
- **OSCP (Offensive Security Certified Professional)** — The gold standard for penetration testing. Practical exam: you have 24 hours to compromise machines in a controlled environment. Hands-on. Brutal. Worth it.
- **GIAC GPEN** — Penetration testing certification from SANS. Highly technical.
- **GIAC GCIH** — Incident handling and response. Blue team specialist cert.

**Expert (Patriot level)**
- **CISSP** — Management and governance level. Broad security knowledge across 8 domains. Required for senior security leadership roles.
- **CISM** — Information Security Management. For those building security programs at organizational scale.

The path: Security+ → CySA+ → OSCP → CISSP. Budget 1-2 years between each major cert if studying part-time. The knowledge from each accelerates the next.

Most importantly: certifications document what you know. **This curriculum builds what you know.** Do both.

---

## Begin Your Journey

```bash
# Enable learning mode
python3 learning_mode.py --enable

# See all 6 paths
python3 learning_mode.py --paths

# Start with the crown jewel path
python3 learning_mode.py --path openclaw-security
python3 learning_mode.py --lesson OC01

# Check your progress
python3 learning_mode.py --status

# Run a knowledge quiz
python3 learning_mode.py --quiz

# Explain any concept
python3 learning_mode.py --explain "prompt injection"
python3 learning_mode.py --explain "zero trust"
python3 learning_mode.py --explain "reentrancy"
```

---

Security is not a destination. It's a posture. A practice. A way of seeing systems.

The world's most sophisticated attackers wake up every day looking for new ways in. The best defenders wake up every day building new ways to stop them. The difference between the two is not intelligence or tools — it's education, discipline, and the will to keep learning.

That's what Claris is here for. Not just to scan. Not just to detect. To *teach* — so that one day, you don't need the scanner to tell you what's wrong. You already know.

You see it yourself.

---

*~Claris · Semper Fortis · The Fortress Learns · V7.0*

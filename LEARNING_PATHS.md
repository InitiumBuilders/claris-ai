# Learning Paths — Claris AI V7.0 Unitium Learning Mode

*Full curriculum for all 6 learning paths. Each lesson described. Prerequisites listed. Outcomes stated.*

---

## 🏛️ Path 1: Foundations — "The Bedrock"

**Level Required:** Recruit (0 XP)  
**Lesson Count:** 8  
**Prerequisites:** None. Start here.  
**Estimated Time:** 4-6 hours  

**Outcomes:**
- Understand how the internet works at a security-relevant level
- Explain the threat landscape to non-technical stakeholders
- Implement password hygiene with a password manager
- Enable and explain MFA on all critical accounts
- Understand social engineering attacks and how to resist them
- Establish a basic backup strategy

### Lesson Plan

| ID | Title | Concept | XP |
|----|-------|---------|-----|
| F01 | The Threat Landscape | Who attacks, why, and how most breaches actually happen. The human element. | 100 |
| F02 | How the Internet Really Works | DNS, HTTP/HTTPS, TCP/IP, TLS — what these mean for security. Packet capture exercise. | 100 |
| F03 | The Password Problem | Why complexity rules fail. Password managers. Entropy. HaveIBeenPwned. | 100 |
| F04 | Multi-Factor Authentication | TOTP vs SMS. Hardware keys. Why MFA blocks 99.9% of automated attacks. | 100 |
| F05 | Social Engineering | Phishing, pretexting, vishing, smishing. Why the best firewall is a skeptical mind. | 100 |
| F06 | Backup Strategy | 3-2-1 backup rule. Testing restores. Ransomware and why backups are your last line. | 100 |
| F07 | Safe Browsing | HTTPS everywhere. Certificate warnings. Browser extensions. VPNs — what they do and don't do. | 100 |
| F08 | Your Digital Footprint | OSINT on yourself. Data brokers. Minimizing attack surface in your personal life. | 100 |

---

## 🔧 Path 2: AppSec — "Build It Safe"

**Level Required:** Apprentice (500 XP)  
**Lesson Count:** 10  
**Prerequisites:** Foundations path recommended  
**Estimated Time:** 8-12 hours  

**Outcomes:**
- Understand and apply OWASP Top 10 to code reviews
- Write injection-resistant code using parameterized queries
- Implement proper access control patterns
- Manage secrets in production environments
- Apply the 30 Vibe Coder Security Rules to AI-assisted coding
- Use vibe_coder_guard.py for automated security review

### Lesson Plan

| ID | Title | Concept | XP |
|----|-------|---------|-----|
| AS01 | OWASP A01 — Broken Access Control | IDOR, missing function-level access control, CORS misconfiguration | 120 |
| AS02 | OWASP A03 — Injection Attacks | SQL injection, command injection, parameterized queries | 120 |
| AS03 | OWASP A02 — Cryptographic Failures | Plaintext storage, weak hashing, TLS misconfiguration | 120 |
| AS04 | OWASP A07 — Authentication Failures | Credential stuffing, session fixation, weak tokens | 120 |
| AS05 | Secrets Management | .env files, git history exposure, proper secrets manager usage | 120 |
| AS06 | Input Validation Deep Dive | Where to validate, what to validate, allow-listing vs deny-listing | 120 |
| AS07 | The 30 Vibe Coder Rules (Part 1) | Rules 1-15: hardcoded secrets through CSRF protection | 120 |
| AS08 | The 30 Vibe Coder Rules (Part 2) | Rules 16-30: least privilege through deployment security review | 120 |
| AS09 | Dependency Security | CVE scanning, npm audit, supply chain risks, dependency pinning | 120 |
| AS10 | Security in CI/CD | Pre-commit hooks, SAST scanning, secrets in environment variables | 120 |

---

## 🤖 Path 3: OpenClaw Security — "Guard Your Agent" 👑 CROWN JEWEL

**Level Required:** Apprentice (500 XP)  
**Lesson Count:** 10  
**Prerequisites:** Foundations path required  
**Estimated Time:** 6-10 hours  

**This path is unique to Claris AI. It cannot be found elsewhere.**  
**Outcomes:**
- Understand why AI agents are high-value targets
- Identify all T1-T12 threat vectors for OpenClaw deployments
- Implement a complete VPS hardening checklist
- Secure memory files against poisoning attacks
- Configure injection defense for all input channels
- Run and interpret openclaw_hardening.py audit results

### Lesson Plan

| ID | Title | Concept | XP |
|----|-------|---------|-----|
| OC01 | Why AI Agents Are High-Value Targets | Ambient authority, machine speed attacks, the unique threat model of AI agents | 150 |
| OC02 | T1 — Prompt Injection via External Channels | Direct and indirect injection, injection_guard.py layers, defense pipeline | 150 |
| OC03 | T2 — Memory File Poisoning | SOUL.md/MEMORY.md security, git-based integrity, detection heuristics | 150 |
| OC04 | T3 — Malicious Cron Jobs | Cron as persistence mechanism, jobs.json auditing, approval workflows | 150 |
| OC05 | T5 & T8 — Secrets Exposure | API keys in git history, workspace scanning, rotation protocols | 150 |
| OC06 | T9 — Channel Configuration | Allowlist policies, authorized sender verification, bot security | 150 |
| OC07 | T10-T11 — Permissions & Supply Chain | chmod best practices, skill source verification, npm audit | 150 |
| OC08 | T12 — AI Model Poisoning | Model endpoint verification, config monitoring, config change detection | 150 |
| OC09 | VPS Hardening Workshop | Running openclaw_hardening.py, fixing findings, verification | 150 |
| OC10 | Claris Defense Architecture | How all Claris tools work together, agent security pipeline, monitoring | 150 |

---

## ⛓️ Path 4: Web3 Security — "Chain Guardian"

**Level Required:** Defender (1,500 XP)  
**Lesson Count:** 8  
**Prerequisites:** Foundations + AppSec paths  
**Estimated Time:** 8-12 hours  

**Outcomes:**
- Understand smart contract OWASP SC Top 10
- Identify reentrancy, integer overflow, and access control vulnerabilities in Solidity
- Apply Checks-Effects-Interactions pattern
- Understand Dash Platform security model
- Practice wallet hygiene and DeFi risk assessment
- Use smart_contract_scanner.py for automated analysis

### Lesson Plan

| ID | Title | Concept | XP |
|----|-------|---------|-----|
| W301 | SC01 — Reentrancy | The DAO hack, CEI pattern, ReentrancyGuard, $60M lesson | 150 |
| W302 | SC02 — Integer Overflow | Safe math, Solidity 0.8+ auto-protection, historical exploits | 150 |
| W303 | SC03 — Timestamp Dependence | Block manipulation, using block numbers vs timestamps | 150 |
| W304 | SC04 — Access Control | onlyOwner pitfalls, role-based access in OpenZeppelin | 150 |
| W305 | Wallet Hygiene | Hardware wallets, seed phrase security, address verification | 150 |
| W306 | Dash Platform Security | DAPI security model, identity protection, data contract safety | 150 |
| W307 | DeFi Risk Landscape | Flash loans, oracle manipulation, MEV, sandwich attacks | 150 |
| W308 | Audit and Verification | Reading audit reports, Slither/Echidna, responsible disclosure | 150 |

---

## 🔵 Path 5: Blue Team — "The Defenders"

**Level Required:** Defender (1,500 XP)  
**Lesson Count:** 10  
**Prerequisites:** Foundations + OpenClaw Security paths  
**Estimated Time:** 10-15 hours  

**Outcomes:**
- Execute a complete incident response lifecycle
- Build a threat hunting program
- Implement Zero Trust architecture
- Analyze logs for indicators of compromise
- Set up a minimal security operations practice
- Understand purple team collaboration

### Lesson Plan

| ID | Title | Concept | XP |
|----|-------|---------|-----|
| BT01 | Zero Trust Architecture | Never trust, always verify. BeyondCorp reference. NIST SP 800-207. | 130 |
| BT02 | Incident Response — Preparation | IR plan, runbooks, communication trees, evidence preservation | 130 |
| BT03 | Incident Response — Detection | Indicators of compromise, SIEM basics, alert triage | 130 |
| BT04 | Incident Response — Containment | Isolation strategies, preserving evidence, stopping spread | 130 |
| BT05 | Threat Hunting Fundamentals | Hypothesis-driven hunting, IOC vs TTP, hunting queries | 130 |
| BT06 | Log Analysis Workshop | auth.log, syslog, application logs — what to look for | 130 |
| BT07 | MITRE ATT&CK Framework | Mapping attacks to techniques, using ATT&CK Navigator | 130 |
| BT08 | Threat Intelligence | OSINT feeds, ISAC participation, intelligence-driven defense | 130 |
| BT09 | Purple Team Operations | Collaborative offense-defense, real-time adversary simulation | 130 |
| BT10 | Building Your Security Program | Metrics, dashboards, continuous improvement, security culture | 130 |

---

## 🔴 Path 6: Red Team — "Think Like an Attacker"

**Level Required:** Patriot (3,000 XP)  
**Lesson Count:** 8  
**Prerequisites:** All other paths. Blue team experience strongly recommended.  
**Estimated Time:** 12-20 hours  

**IMPORTANT: All techniques in this path are for authorized security testing only.**  
**Unauthorized access to systems is illegal. Always have written permission.**

**Outcomes:**
- Execute a structured penetration testing engagement
- Perform OSINT reconnaissance professionally
- Understand and apply enumeration techniques
- Document findings for remediation
- Navigate responsible disclosure
- Understand bug bounty programs and rules of engagement

### Lesson Plan

| ID | Title | Concept | XP |
|----|-------|---------|-----|
| RT01 | The Attacker's Mindset | How attackers think. Path of least resistance. Human-first reconnaissance. | 150 |
| RT02 | OSINT Reconnaissance | LinkedIn, Shodan, Google dorks, theHarvester, attack surface mapping | 150 |
| RT03 | Enumeration Techniques | Port scanning (nmap), service fingerprinting, banner grabbing | 150 |
| RT04 | Vulnerability Assessment | Identifying exploitable vulnerabilities, CVSS scoring, prioritization | 150 |
| RT05 | Social Engineering in Practice | Phishing simulation, pretexting, physical security tests, ethics | 150 |
| RT06 | Exploitation Fundamentals | Understanding CVE exploitation, controlled testing environment setup | 150 |
| RT07 | Post-Exploitation & Reporting | Documenting findings, writing quality security reports, remediation guidance | 150 |
| RT08 | Responsible Disclosure & Bug Bounties | Disclosure timelines, HackerOne/Bugcrowd, coordinated disclosure ethics | 150 |

---

## Progress Tracking

Your progress is stored in `data/learning_state.json`. Track it with:

```bash
python3 learning_mode.py --status    # Full dashboard
python3 learning_mode.py --paths     # See all paths with lock status
python3 learning_mode.py --quiz      # Test your knowledge
```

XP Requirements:
- 🔓 Recruit → Apprentice: **500 XP**
- 🔓 Apprentice → Defender: **1,500 XP**
- 🔓 Defender → Patriot: **3,000 XP**

Path unlock thresholds:
- foundations, appsec, openclaw-security: **Unlocked by default**
- web3-security, blue-team: **1,500 XP required**
- red-team: **3,000 XP required**

---

*~Claris · Semper Fortis · V7.0 · Full curriculum. Real knowledge. Built to last.*

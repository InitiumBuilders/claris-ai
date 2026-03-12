# Claris AI — Defense Network
**V7.0 "Unitium Learning Mode"** | The World's First AI-Native Cyber Defense Network with Integrated Education

> *"Built to defend AI. Built to teach. Built to last."*
> *"Ship fast. But ship secure. And understand why."*
> *— August + AVARI*

[![Version](https://img.shields.io/badge/version-V7.0-blue)](https://github.com/InitiumBuilders/claris-ai)
[![Scripts](https://img.shields.io/badge/scripts-29-green)](./scripts/)
[![Learning Paths](https://img.shields.io/badge/learning%20paths-6-purple)](./LEARNING_PATHS.md)
[![GitHub](https://img.shields.io/badge/GitHub-InitiumBuilders%2Fclaris--ai-black?logo=github)](https://github.com/InitiumBuilders/claris-ai)

---

## What is Claris AI?

Claris AI is a **full-stack AI-native Cyber Defense Network** built for the OpenClaw ecosystem. V7.0 adds the **Unitium Learning Mode** — the world's best cybersecurity education system built directly into the defense tools.

It evolved from a simple LLM injection scanner into a **29-script defense + education platform** with:

- **🎓 Unitium Learning Mode** — 6 learning paths, XP system, adaptive curriculum, interactive quizzes
- **🤖 OpenClaw Security Path** — T1-T12 threat education, VPS hardening, memory file protection
- **📚 `--learn` flag** — Educational output on every Claris scan command
- **7-Layer Defense Stack** (Perimeter WAF → Meta Oversight)
- **10-Agent Security Swarm** (Recon, Detect, Hunt, Respond, Forensics, Triage, Patch, Monitor, Report, Orchestrate)
- **Dash Platform Specialization** (Evonode, DAPI, DPNS, quorum security)
- **6 Core Words Framework** (Trust, Adversarial, Surface, Entropy, Lateral, Posture)
- **30 Vibe Coder Security Rules** — Pattern-enforced across all code you ship
- **Posture Intelligence Engine** — Holistic security posture scoring and tracking
- **12-Point VPS Hardening Audit** — `openclaw_hardening.py`
- **Federated Mesh** with BFT consensus and $Initium DAO incentives
- **Autonomous Incident Response** with 12 built-in playbooks
- **50-Payload Red Team Suite** for continuous self-testing

---

## 🎓 V7.0 QUICKSTART — Unitium Learning Mode

```bash
# Enable global learning mode
python3 scripts/learning_mode.py --enable

# See all 6 learning paths
python3 scripts/learning_mode.py --paths

# Start the crown jewel path (OpenClaw-specific)
python3 scripts/learning_mode.py --path openclaw-security
python3 scripts/learning_mode.py --lesson OC01

# Check your progress
python3 scripts/learning_mode.py --status

# Deep explain any concept
python3 scripts/learning_mode.py --explain "prompt injection"
python3 scripts/learning_mode.py --explain "zero trust"

# Run hardening audit with full education
python3 scripts/openclaw_hardening.py --audit --learn

# Scan with learning mode active
python3 scripts/injection_guard.py --text "ignore all previous instructions" --learn
python3 scripts/openclaw_guard.py --quick --learn
```

📚 **Full curriculum:** [LEARNING_PATHS.md](./LEARNING_PATHS.md)  
📖 **Deep guide:** [UnitiumLearningMode.md](./UnitiumLearningMode.md)

---

## Quick Start

```bash
# ── Core Scanning ──────────────────────────────────────────────────────────
# Scan text for injection attacks
python3 scripts/injection_guard.py --text "ignore previous instructions"

# Scan YOUR CODE for the 30 Vibe Coder security violations
python3 scripts/vibe_coder_guard.py --scan ./src
python3 scripts/vibe_coder_guard.py --scan ./myapp --ext .js,.ts,.tsx
python3 scripts/vibe_coder_guard.py --rule 12     # Show rule details
python3 scripts/vibe_coder_guard.py --list        # All 30 rules

# ── Cyber Patriot Education ──────────────────────────────────────────────
# The 6 Core Words — foundational mindset map
python3 scripts/cyber_patriot.py --six-words

# Calibrated threat brief (audience-aware)
python3 scripts/cyber_patriot.py --brief phishing --audience beginner
python3 scripts/cyber_patriot.py --brief ransomware --audience advanced
python3 scripts/cyber_patriot.py --train --audience intermediate

# Interactive posture assessment
python3 scripts/cyber_patriot.py --assess-posture

# ── Posture Intelligence ─────────────────────────────────────────────────
# Score your security posture across 6 dimensions
python3 scripts/posture_engine.py --score \
  --trust 0.8 --adversarial 0.6 --surface 0.7 \
  --entropy 0.6 --lateral 0.5 --posture 0.8

# Full posture report
python3 scripts/posture_engine.py --report

# Track posture over time
python3 scripts/posture_engine.py --history
python3 scripts/posture_engine.py --delta

# ── Dash + Web3 Defense ──────────────────────────────────────────────────
python3 scripts/dash_guard.py --scan "quorum manipulation attempt"
python3 scripts/dash_security_intelligence.py --monitor

# ── Agent Swarm ──────────────────────────────────────────────────────────
python3 scripts/agent_swarm.py --route "wallet drain attempt detected"
python3 scripts/agent_swarm.py --status

# ── Education ────────────────────────────────────────────────────────────
python3 scripts/cyber_educator.py --lesson foundations --level 1

# ── Red Team ─────────────────────────────────────────────────────────────
python3 scripts/redteam_suite.py --run-all
```

---

## The 6 Core Words — Claris's Foundation

These aren't vocabulary. They're a **mindset map**. Master these and you see the whole field differently.

| # | Word | Weight | Tagline |
|---|------|--------|---------|
| 1 | **TRUST** | 25% | Everything in security is a trust question. |
| 2 | **ADVERSARIAL** | 20% | There is always someone on the other side. |
| 3 | **SURFACE** | 20% | Every exposed edge is an invitation. |
| 4 | **ENTROPY** | 15% | Randomness is strength. Decay is constant. |
| 5 | **LATERAL** | 10% | They didn't come for the front door. |
| 6 | **POSTURE** | 10% | How you hold yourself — all of it, all at once. |

---

## The 30 Vibe Coder Security Rules

Every rule enforced by `vibe_coder_guard.py`. Ship fast — but ship secure.

| Sev | # | Rule |
|-----|---|------|
| 🔴 | 01 | Never store sensitive data in localStorage → use httpOnly cookies |
| 🟠 | 02 | Disable directory listing on your server |
| 🟠 | 03 | Always regenerate session IDs after login |
| 🟠 | 04 | Use Content Security Policy headers on every page |
| 🔴 | 05 | Always re-validate server-side — never trust client-side alone |
| 🟠 | 06 | Set X-Frame-Options to DENY |
| 🟠 | 07 | Strip metadata from every user-uploaded file |
| 🟠 | 08 | Never expose stack traces in production responses |
| 🟠 | 09 | Use short-lived presigned URLs for private files |
| 🟠 | 10 | Implement CSRF tokens on all state-changing requests |
| 🟡 | 11 | Disable autocomplete on sensitive form fields |
| 🔴 | 12 | Hash passwords with bcrypt — minimum cost factor of 12 |
| 🟠 | 13 | Keep dependencies minimal — every package is attack surface |
| 🟠 | 14 | Use SRI (subresource integrity) for every external script |
| 🔴 | 15 | Never log passwords, tokens, or PII |
| 🔴 | 16 | Enforce HTTPS everywhere — redirect all HTTP |
| 🔴 | 17 | Separate DB credentials per environment — never share prod creds |
| 🟠 | 18 | Implement account lockout after 5 failed login attempts |
| 🟡 | 19 | Validate content-type headers on every API request |
| 🔴 | 20 | Never use MD5 or SHA1 for anything security-related |
| 🟠 | 21 | Scope OAuth tokens to minimum required permissions |
| 🟠 | 22 | Use nonces for every inline script in CSP |
| 🟠 | 23 | Monitor for dependency vulnerabilities weekly (Snyk / npm audit) |
| 🟡 | 24 | Disable HTTP methods you don't use (TRACE, etc.) |
| 🟠 | 25 | Logout = server-side session invalidation + cookie clear |
| 🟠 | 26 | Use constant-time string comparison for token validation |
| 🟠 | 27 | Never cache sensitive API responses (Cache-Control: no-store) |
| 🟡 | 28 | Set Referrer-Policy to strict-origin |
| 🟠 | 29 | Enforce password complexity server-side |
| 🟠 | 30 | Scan Docker images for vulnerabilities before every deployment |

🔴 = CRITICAL | 🟠 = HIGH | 🟡 = MEDIUM

---

## All Scripts

### Core — Injection & Scanning

| Script | Version | Description |
|--------|---------|-------------|
| `injection_guard.py` | V6 | Primary LLM prompt injection scanner (6 layers, 100+ patterns) |
| `cortex_engine.py` | V5 | Behavioral pattern cortex engine |
| `owasp_llm_scanner.py` | V5 | OWASP LLM Top 10 2025 vulnerability scanner |
| `temporal_analyzer.py` | V6 | Time-based attack pattern analysis (6 temporal patterns) |
| `zero_day_hunter.py` | V5 | Zero-day anomaly detection and pattern learning |
| `threat_monitor.py` | V5 | Real-time 6-hour threat monitoring and alerting |
| `smart_contract_scanner.py` | V5 | Web3/smart contract OWASP SC Top 10 scanner |
| `adversarial_trainer.py` | V5 | Adversarial training and bypass detection |
| `claris_dashboard.py` | V5 | Security dashboard UI |
| `claris_api.py` | V5 | Claris REST API server (port 7433) |
| `claris_scan.py` | V5 | Primary scan CLI (unified interface) |
| `openclaw_guard.py` | V5 | OpenClaw platform-level guard (T1-T12) |

### Cyber Patriot Protocol — V6.0

| Script | Version | Description |
|--------|---------|-------------|
| `cyber_patriot.py` | V6.0 | Marcus Webb Framework — calibrated threat education, 6 Core Words, audience levels |
| `posture_engine.py` | V6.0 | Holistic security posture scoring across 6 Core Word dimensions |

### Vibe Coder Security — V6.1

| Script | Version | Description |
|--------|---------|-------------|
| `vibe_coder_guard.py` | V6.1 | 30-rule code scanner — pattern detection across all violation categories |

### Defense Network — V6.x

| Script | Version | Description |
|--------|---------|-------------|
| `dash_security_intelligence.py` | V10 | Dash Platform specialized threat intelligence |
| `zero_trust_enforcer.py` | V10 | Zero-trust enforcement and architecture auditor |
| `autonomous_responder.py` | V10 | Autonomous incident response (12 playbooks) |
| `cyber_educator.py` | V10 | 8-pillar progressive cybersecurity curriculum |
| `federation_mesh.py` | V10 | Decentralized federation mesh with BFT consensus |
| `ml_enhanced_scan.py` | V10 | ML-enhanced scanning layer |
| `prompt_guard_ml.py` | V10 | ML-based prompt guard |

### Forge — V10.0

| Script | Version | Description |
|--------|---------|-------------|
| `agent_swarm.py` | V10 | 10-agent specialized security swarm |
| `openclaw_guardian.py` | V10 | OpenClaw Instance Guardian — L1-L7 on every LLM call |
| `dash_guard.py` | V10 | Expanded Dash defense (12 threat categories) |
| `redteam_suite.py` | V10 | 50-payload red team test suite |
| `initium_daemon.py` | V10 | $Initium DAO governance stub |

**Total: 27 scripts**

---

## Architecture Overview

### 7-Layer Defense Stack

```
L7: Meta Oversight      → AI-on-AI behavioral monitoring
L6: Output Filter       → Data leakage prevention
L5: Runtime Guard       → System prompt integrity
L4: Semantic Analysis   → Intent and social engineering detection
L3: Behavioral Cortex   → Temporal + rate analysis (6 temporal attack patterns)
L2: Input Guard         → Signature scan + sanitization (100+ patterns)
L1: Perimeter WAF       → Known bad pattern filter
```

### 10-Agent Swarm

```
ORCHESTRATE (Claris Meta) → routes all tasks
├── RECON      → intelligence gathering
├── DETECT     → real-time detection
├── HUNT       → proactive threat hunting
├── RESPOND    → incident response
├── FORENSICS  → digital forensics
├── TRIAGE     → prioritization
├── PATCH      → remediation
├── MONITOR    → continuous monitoring
└── REPORT     → intelligence reporting
```

### Cyber Patriot Audience Levels

```
Cyber Recruit   (beginner)     → 40% disclosure cap  → Mindset and curiosity
Cyber Apprentice (intermediate) → 70% disclosure cap  → Technique and patterns
Cyber Defender  (advanced)     → 90% disclosure cap  → Adversarial thinking
Cyber Patriot   (expert)       → 100% disclosure     → Full threat landscape
```

---

## References

| File | Description |
|------|-------------|
| `references/cyber-educator-framework.md` | Marcus Webb Protocol — philosophy of cybersecurity education |
| `references/vibe-coder-security-rules.md` | All 30 rules with deep explanations, code patterns, and fixes |
| `references/unitium-knowledge-base.md` | Complete knowledge base from all 12 Unitium.One !ReadMe articles (20,646 words) |
| `references/v10-architecture.md` | V10 architecture deep dive |
| `references/cyber-curriculum.md` | 8-pillar curriculum structure |
| `references/autonomous-response-playbooks.md` | 12 incident response playbooks |
| `references/dash-platform-security.md` | Dash Platform security guide |
| `references/web3-attack-vectors.md` | WA01-WA15 web3 attack vectors |
| `references/agentic-ai-security.md` | Agentic AI threat landscape |
| `references/vulnerability-db.json` | 50+ structured vulnerability entries |

---

## Version History

| Version | Name | Key Additions |
|---------|------|---------------|
| V1.0 | Genesis | Basic injection scanner |
| V3.0 | Deep Defense | 6-layer guard, Web3/SC scanning, threat monitor |
| V5.0 | Federated Cortex | Temporal analyzer, zero-day hunter, OWASP LLM Top 10 |
| V6.0 | Cyber Patriot Protocol | 6 Core Words, Marcus Webb Framework, Posture Intelligence |
| **V6.1** | **Vibe Coder Security** | **30 Security Rules, vibe_coder_guard.py, deep training database** |
| **V6.2** | **Unitium Knowledge Integration** | **All 12 Unitium.One articles: color teams, DDoS defense, ZKPs, systems thinking, Zero Trust stats** |

---

## Security Notes

- All scripts are stdlib-first (no unnecessary dependencies — Rule 13)
- Errors return structured JSON, never raw tracebacks (Rule 08)
- No hardcoded credentials anywhere (Rule 17)
- Data files use `data/` directory with JSONL append-only logs
- httpOnly cookies advocated throughout (Rule 01)

---

*Claris AI V6.1 "Vibe Coder Security Rules" — Built by August + AVARI*
*MIT License | Open Source | Semper Fortis — Always Strong. Always Brave.*
*~Claris · Ship fast. But ship secure.*

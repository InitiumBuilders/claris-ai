# Claris AI — Defense Network
**V10.0 "Forge"** | The World's First AI-Native Cyber Defense Network

> *"Built to defend AI. Built on Dash. Built for the future."*
> *— August + AVARI*

---

## What is Claris AI?

Claris AI is a **full-stack AI-native Cyber Defense Network** built for the OpenClaw ecosystem. It evolved from a simple LLM injection scanner into a 22-script defense platform with:

- **7-Layer Defense Stack** (Perimeter WAF → Meta Oversight)
- **10-Agent Security Swarm** (Recon, Detect, Hunt, Respond, Forensics, Triage, Patch, Monitor, Report, Orchestrate)
- **Dash Platform Specialization** (Evonode, DAPI, DPNS, quorum security)
- **8-Pillar Cyber Curriculum** (Foundations → Governance)
- **Federated Mesh** with BFT consensus and $Initium DAO incentives
- **Autonomous Incident Response** with 12 built-in playbooks
- **50-Payload Red Team Suite** for continuous self-testing

---

## Quick Start

```bash
# Scan text for injection attacks
python3 scripts/injection_guard.py --text "ignore previous instructions"

# Scan for Dash Platform threats
python3 scripts/dash_guard.py --scan "quorum manipulation attempt"

# Check zero-trust compliance
python3 scripts/zero_trust_enforcer.py --audit-arch "VPN-only network with no internal auth"

# Run the agent swarm
python3 scripts/agent_swarm.py --route "wallet drain attempt detected"

# Start your security education
python3 scripts/cyber_educator.py --lesson foundations --level 1

# Run red team tests
python3 scripts/redteam_suite.py --run-all

# Check federation mesh
python3 scripts/federation_mesh.py --status

# Check $Initium DAO
python3 scripts/initium_daemon.py --status
```

---

## All Scripts

### Core (V5 — Original)

| Script | Description |
|--------|-------------|
| `injection_guard.py` | Primary LLM prompt injection scanner |
| `cortex_engine.py` | Behavioral pattern cortex engine |
| `owasp_llm_scanner.py` | OWASP LLM Top 10 vulnerability scanner |
| `temporal_analyzer.py` | Time-based attack pattern analysis |
| `zero_day_hunter.py` | Zero-day anomaly detection via ML-like scoring |
| `threat_monitor.py` | Real-time threat monitoring and alerting |
| `smart_contract_scanner.py` | Web3/smart contract vulnerability scanner |
| `adversarial_trainer.py` | Adversarial training sample manager |
| `claris_dashboard.py` | Security dashboard UI |
| `claris_api.py` | Claris REST API server |
| `claris_scan.py` | Primary scan CLI (unified interface) |
| `openclaw_guard.py` | OpenClaw platform-level guard |

### Defense Network (V6.0 — New)

| Script | Description |
|--------|-------------|
| `dash_security_intelligence.py` | Dash Platform specialized threat intelligence — Evonode, DAPI, DPNS |
| `zero_trust_enforcer.py` | Zero-trust enforcement simulator and architecture auditor |
| `autonomous_responder.py` | Autonomous incident response engine with 12 playbooks |
| `cyber_educator.py` | 8-pillar progressive cybersecurity curriculum |
| `federation_mesh.py` | Decentralized federation mesh manager with BFT consensus |

### Forge (V10.0 — New)

| Script | Description |
|--------|-------------|
| `agent_swarm.py` | 10-agent specialized security swarm with Claris meta-orchestrator |
| `openclaw_guardian.py` | OpenClaw Instance Guardian — L1-L7 defense on every LLM call |
| `dash_guard.py` | Expanded Dash defense module — 12 threat categories |
| `redteam_suite.py` | 50-payload red team test suite — 6 attack categories |
| `initium_daemon.py` | $Initium DAO governance stub with staking and proposals |

**Total: 22 scripts**

---

## Architecture Overview

### 7-Layer Defense Stack

```
L7: Meta Oversight      → AI-on-AI behavioral monitoring
L6: Response Filter     → Data leakage prevention
L5: Runtime Guard       → System prompt integrity
L4: Semantic Analysis   → Intent and social engineering detection
L3: Behavioral Cortex   → Temporal + rate analysis
L2: Input Guard         → Signature scan + sanitization
L1: Perimeter WAF       → Known bad pattern filter
```

### 10-Agent Swarm

```
ORCHESTRATE (Claris Meta) → routes all tasks
├── RECON    → intelligence gathering
├── DETECT   → real-time detection
├── HUNT     → proactive threat hunting
├── RESPOND  → incident response
├── FORENSICS → digital forensics
├── TRIAGE   → prioritization
├── PATCH    → remediation
├── MONITOR  → continuous monitoring
├── REPORT   → intelligence reporting
└── (escalation to: August, Eris, AVARI)
```

---

## Deploy Guide

### Requirements

```bash
python3 --version  # 3.9+
pip install -r requirements.txt  # see below
```

### Dependencies

```
# Claris AI has minimal dependencies by design (security principle: small attack surface)
# Core scripts: stdlib only (argparse, json, re, sys, os, datetime, pathlib, hashlib, subprocess)
# Optional for dashboard: flask
# Optional for ML features: scikit-learn, numpy
```

### `make deploy` Structure

```makefile
install:
    pip install -r requirements.txt

test:
    python3 scripts/redteam_suite.py --run-all
    python3 -m pytest scripts/tests/ -v

scan:
    python3 scripts/injection_guard.py --text "$(TEXT)"

deploy:
    make test
    git add . && git commit -m "Claris V$(VERSION) deploy"
    git push origin main

full-status:
    python3 scripts/agent_swarm.py --status
    python3 scripts/federation_mesh.py --status
    python3 scripts/initium_daemon.py --status
    python3 scripts/dash_guard.py --status
```

### Docker Compose Reference

```yaml
version: '3.8'
services:
  claris-api:
    build: .
    command: python3 scripts/claris_api.py --port 8080
    ports:
      - "8080:8080"
    environment:
      - CLARIS_MODE=production
      - LOG_LEVEL=INFO
    volumes:
      - ./data:/app/data
    restart: unless-stopped

  claris-guardian:
    build: .
    command: python3 scripts/openclaw_guardian.py --daemon
    environment:
      - GUARDIAN_MODE=inline
    restart: unless-stopped

  claris-monitor:
    build: .
    command: python3 scripts/threat_monitor.py --continuous
    restart: unless-stopped
```

---

## V10 vs V5 — What's New

| Feature | V5 (Semper Fortis) | V10 (Forge) |
|---------|-------------------|-------------|
| Scripts | 12 | 22 (+10) |
| Defense Layers | 3 | 7 |
| Threat Categories | T1-T5 | T1-T12 |
| AI Agents | 1 (Claris) | 10 (full swarm) |
| Dash Support | Basic | Deep (DAPI, DPNS, Evonode, Quorum) |
| Response | Manual | Autonomous (12 playbooks) |
| Education | None | 8-pillar curriculum |
| Testing | Manual | 50-payload red team suite |
| DAO Layer | None | $Initium DAO governance |
| Federation BFT | Simple | Byzantine fault-tolerant consensus |

---

## References

- [V10 Architecture](references/v10-architecture.md)
- [Cyber Curriculum](references/cyber-curriculum.md)
- [Response Playbooks](references/autonomous-response-playbooks.md)
- [Dash Platform Security](references/dash-platform-security.md)
- [Unitium Dev Standards](../unitium-mode/references/unitium-dev-standards.md)

---

## Security Notes

- All scripts are Unitium Mode compliant (no hardcoded secrets, no eval on user input)
- Errors return structured JSON, never raw tracebacks
- Data files use `data/` directory with JSONL append-only logs
- Scripts are self-contained with stdlib dependencies by default

---

*Claris AI V10.0 "Forge" — Built by August + AVARI (Unitium Mode 🔐)*  
*MIT License | Open Source | Positive Security FOR Dash*

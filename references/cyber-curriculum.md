# Claris AI Cyber Curriculum
*8-Pillar Progressive Cybersecurity Education*

---

## Overview

Claris AI includes a full cybersecurity curriculum delivered via `cyber_educator.py`. The curriculum is structured as 8 pillars, each with 3 progressive levels (Novice → Practitioner → Expert), plus a Dash-specific security module.

**Run:** `python3 cyber_educator.py --lesson <pillar> --level <1-3>`

---

## The 8 Pillars

### 1. 🏛️ Foundations
**Learning Objective:** Understand the CIA Triad, security mindset, threat modeling, and risk management.

| Level | Title | Key Concepts |
|-------|-------|-------------|
| 1 | Novice | CIA Triad, vulnerability vs exploit, patch, zero-day |
| 2 | Practitioner | STRIDE, security principles, risk formula, control types |
| 3 | Expert | PASTA, Cyber Kill Chain, MITRE ATT&CK, security metrics |

---

### 2. 🌐 Network Security
**Learning Objective:** Understand network protocols, attack types, defenses, and monitoring.

| Level | Title | Key Concepts |
|-------|-------|-------------|
| 1 | Novice | TCP/IP, ports, firewalls, TLS, VPN |
| 2 | Practitioner | MitM, DDoS, IDS/IPS, segmentation, SIEM |
| 3 | Expert | BGP hijacking, ZTNA, UEBA, network forensics |

---

### 3. ⚙️ Application Security
**Learning Objective:** Identify and prevent common application vulnerabilities. Integrate security into SDLC.

| Level | Title | Key Concepts |
|-------|-------|-------------|
| 1 | Novice | OWASP Top 10 overview, SQL injection, XSS, input validation |
| 2 | Practitioner | Full OWASP 2021, SAST/DAST, IDOR, SSRF, secure SDLC |
| 3 | Expert | Deserialization, memory corruption, formal verification, supply chain |

---

### 4. 🤖 AI/LLM Security
**Learning Objective:** Understand the unique security risks of AI systems and how to defend against them.

| Level | Title | Key Concepts |
|-------|-------|-------------|
| 1 | Novice | Prompt injection, jailbreak, why AI is different |
| 2 | Practitioner | OWASP LLM Top 10, indirect injection, data poisoning, RAG security |
| 3 | Expert | Multi-agent attacks, tool call injection, AI red teaming, RLHF security |

---

### 5. ⛓️ Web3/Blockchain Security
**Learning Objective:** Secure crypto wallets, smart contracts, and Dash Platform interactions.

| Level | Title | Key Concepts |
|-------|-------|-------------|
| 1 | Novice | Wallet security, seed phrases, rug pulls, hardware wallets |
| 2 | Practitioner | Reentrancy, flash loans, oracle manipulation, Dash DAPI |
| 3 | Expert | MEV, bridge attacks, governance takeovers, Dash quorums |

---

### 6. 🚨 Incident Response
**Learning Objective:** Detect, contain, eradicate, and recover from security incidents effectively.

| Level | Title | Key Concepts |
|-------|-------|-------------|
| 1 | Novice | PICERL phases, evidence preservation, first response |
| 2 | Practitioner | Runbooks, chain of custody, forensic imaging, threat hunting |
| 3 | Expert | Tabletop exercises, SOAR, MTTD/MTTR, post-incident legal |

---

### 7. 🔑 Cryptography
**Learning Objective:** Understand cryptographic principles and apply them correctly.

| Level | Title | Key Concepts |
|-------|-------|-------------|
| 1 | Novice | Symmetric vs asymmetric, hashing, never roll your own |
| 2 | Practitioner | AES, RSA, ECC, TLS handshake, PKI, Perfect Forward Secrecy |
| 3 | Expert | Threshold signatures, ZKPs, homomorphic encryption, post-quantum |

---

### 8. 📋 Governance & Compliance
**Learning Objective:** Understand security governance frameworks and how to build security culture.

| Level | Title | Key Concepts |
|-------|-------|-------------|
| 1 | Novice | SOC2, GDPR, security policies, why compliance matters |
| 2 | Practitioner | NIST CSF (5 functions), risk register, vendor risk, audit prep |
| 3 | Expert | GRC platforms, continuous compliance, board communication, DAO governance |

---

## Special: ⚡ Dash Platform Security Module

Accessible via `--dash-module` flag. Covers:
1. Identity Security
2. Data Contract Security
3. DPNS Security
4. DAPI Security
5. Evonode Operator Security
6. Dash DAO Governance

---

## Daily Tips

Run `python3 cyber_educator.py --daily-tip` for a random security insight from the 20+ tip library.

## Quiz Mode

Run `python3 cyber_educator.py --quiz <pillar> --quiz-level <1-3>` for 3-question quizzes per pillar/level.

## Progress Tracking

Lesson completion saved to `data/learning_progress.json`.

---

*Curriculum maintained by August + AVARI — Claris AI V6.0*

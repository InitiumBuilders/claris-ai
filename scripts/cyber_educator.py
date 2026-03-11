#!/usr/bin/env python3
"""
Script: cyber_educator.py
Version: V6.0
Claris AI — Defense Network
Author: August + AVARI (Unitium Mode)
Last Updated: 2026-03-10

Progressive cybersecurity education engine.
8-pillar curriculum, 3 levels each, quiz mode, daily tips, progress tracking.
"""

import argparse, json, sys, os, re, random
from datetime import datetime, timezone
from pathlib import Path

VERSION = "V6.0"
SCRIPT_NAME = "cyber_educator"

DATA_DIR = Path(__file__).parent.parent / "data"
PROGRESS_FILE = DATA_DIR / "learning_progress.json"

# ─── 8-PILLAR CURRICULUM ─────────────────────────────────────────────────────

CURRICULUM = {
    "foundations": {
        "name": "Foundations",
        "icon": "🏛️",
        "description": "CIA Triad, threat modeling, attack surfaces, security mindset",
        "levels": {
            1: {
                "title": "Novice",
                "content": """
🏛️ CYBERSECURITY FOUNDATIONS — Novice Level
=============================================

THE CIA TRIAD — The three goals of security:
• Confidentiality: Only authorized parties see data
• Integrity: Data hasn't been tampered with
• Availability: Systems work when you need them

THREAT MODELING (simplified):
1. What are we protecting? (assets)
2. Who wants to attack it? (threat actors)
3. How could they attack? (attack vectors)
4. What's the worst that could happen? (impact)
5. What do we do about it? (controls)

ATTACK SURFACE:
The sum of all the different points where an attacker can try to enter.
Smaller surface = better security.

KEY TERMS:
• Vulnerability: A weakness in a system
• Exploit: Code/technique that takes advantage of a vulnerability
• Patch: Fix that closes a vulnerability
• Zero-day: Vulnerability unknown to the vendor
                """,
                "quiz": [
                    {"q": "What does CIA stand for in security?", "a": "Confidentiality, Integrity, Availability"},
                    {"q": "What is a zero-day vulnerability?", "a": "A vulnerability unknown to the software vendor"},
                    {"q": "What is an attack surface?", "a": "All the points where an attacker can try to enter a system"},
                ],
            },
            2: {
                "title": "Practitioner",
                "content": """
🏛️ CYBERSECURITY FOUNDATIONS — Practitioner Level
===================================================

THREAT MODELING — STRIDE:
• Spoofing: Impersonating another user/system
• Tampering: Modifying data without authorization
• Repudiation: Denying an action you took
• Information Disclosure: Exposing data to unauthorized parties
• Denial of Service: Making a system unavailable
• Elevation of Privilege: Gaining higher access than authorized

SECURITY PRINCIPLES:
• Defense in Depth: Multiple layers of security
• Least Privilege: Minimum access needed for the job
• Fail Secure: Default to deny on failure
• Open Design: Security through obscurity is weak
• Separation of Duties: No single person has all power
• Economy of Mechanism: Keep security simple

RISK = LIKELIHOOD × IMPACT
• Risk Assessment: Quantify risk to prioritize defenses
• Risk Appetite: How much risk is acceptable?
• Residual Risk: Risk remaining after controls applied

SECURITY CONTROLS:
• Preventive: Stop attacks (firewalls, auth)
• Detective: Find attacks (logging, SIEM)
• Corrective: Fix after attacks (backups, patching)
• Deterrent: Discourage attacks (legal warnings, penalties)
                """,
                "quiz": [
                    {"q": "What does STRIDE stand for?", "a": "Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege"},
                    {"q": "What is the formula for risk?", "a": "Risk = Likelihood × Impact"},
                    {"q": "What is a detective security control?", "a": "A control that finds/detects attacks, like logging or SIEM"},
                ],
            },
            3: {
                "title": "Expert",
                "content": """
🏛️ CYBERSECURITY FOUNDATIONS — Expert Level
============================================

ADVANCED THREAT MODELING — PASTA:
Process for Attack Simulation and Threat Analysis
1. Define Objectives
2. Define Technical Scope
3. Application Decomposition
4. Threat Analysis
5. Vulnerability Analysis
6. Attack Modeling
7. Risk & Impact Analysis

ATTACK KILL CHAIN (Lockheed Martin):
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control (C2)
7. Actions on Objectives

MITRE ATT&CK FRAMEWORK:
Comprehensive matrix of adversarial tactics and techniques.
Used for red team planning and defensive coverage mapping.

SECURITY METRICS THAT MATTER:
• MTTD: Mean Time to Detect a breach
• MTTR: Mean Time to Respond/Remediate
• Dwell Time: How long attacker was undetected
• Patch Cadence: Time from CVE to patched in production
• False Positive Rate: Noise in your detection system

ZERO TRUST ARCHITECTURE:
• Micro-segmentation, identity-centric, continuous verification
• BeyondCorp model (Google's internal ZTA implementation)
• NIST SP 800-207: Zero Trust Architecture standard
                """,
                "quiz": [
                    {"q": "What are the 7 phases of the cyber kill chain?", "a": "Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives"},
                    {"q": "What does MTTD stand for?", "a": "Mean Time to Detect"},
                    {"q": "What framework maps adversarial tactics and techniques?", "a": "MITRE ATT&CK"},
                ],
            },
        },
    },
    "network": {
        "name": "Network Security",
        "icon": "🌐",
        "description": "TCP/IP, firewalls, VPNs, zero-trust, network monitoring",
        "levels": {
            1: {
                "title": "Novice",
                "content": """
🌐 NETWORK SECURITY — Novice Level
====================================

HOW THE INTERNET WORKS (simplified):
• IP Address: Your network address (like a house address)
• Port: A specific channel on that address (like a room number)
• TCP: Reliable connection-based protocol (handshake first)
• UDP: Faster but no reliability guarantee

COMMON PORTS TO KNOW:
• 22: SSH (remote access)
• 80: HTTP (web, unencrypted)
• 443: HTTPS (web, encrypted)
• 3306: MySQL database
• 8080: Alt web server

FIREWALLS:
• Block or allow traffic based on rules
• Default deny: block everything, allow only what's needed
• Think of it as a bouncer at a club

ENCRYPTION:
• HTTP vs HTTPS: Never send sensitive data over HTTP
• TLS: The protocol that encrypts HTTPS
• VPN: Encrypted tunnel for all your traffic
                """,
                "quiz": [
                    {"q": "What port does HTTPS use?", "a": "443"},
                    {"q": "What is a firewall's primary function?", "a": "Block or allow network traffic based on rules"},
                    {"q": "What does TLS protect?", "a": "It encrypts communications (like HTTPS web traffic)"},
                ],
            },
            2: {
                "title": "Practitioner",
                "content": """
🌐 NETWORK SECURITY — Practitioner Level
==========================================

NETWORK ATTACKS:
• Man-in-the-Middle (MitM): Attacker intercepts traffic between two parties
• DDoS: Flooding a server with traffic to make it unavailable
• DNS Poisoning: Redirecting domain lookups to malicious IPs
• ARP Spoofing: Fake MAC address announcements on local network
• Port Scanning: Mapping open ports on a target system

FIREWALLS — Types:
• Packet filter: Basic IP/port rules
• Stateful inspection: Tracks connection state
• Next-Gen (NGFW): Application-layer inspection + IPS

INTRUSION DETECTION/PREVENTION:
• IDS: Detects and alerts on suspicious activity
• IPS: Detects AND blocks suspicious activity
• NIDS: Network-based detection
• HIDS: Host-based detection

SEGMENTATION:
• DMZ: Demilitarized zone — isolated segment for public-facing servers
• VLANs: Virtual network separation
• Micro-segmentation: Fine-grained zero-trust network zones

MONITORING:
• SIEM: Security Information and Event Management
• NetFlow: Network traffic metadata analysis
• Full packet capture: For forensic investigation
                """,
                "quiz": [
                    {"q": "What is a Man-in-the-Middle attack?", "a": "An attacker who intercepts traffic between two communicating parties"},
                    {"q": "What is a DMZ in network security?", "a": "Demilitarized Zone — an isolated segment for public-facing servers"},
                    {"q": "What is the difference between IDS and IPS?", "a": "IDS detects and alerts; IPS detects and blocks"},
                ],
            },
            3: {
                "title": "Expert",
                "content": """
🌐 NETWORK SECURITY — Expert Level
=====================================

ADVANCED PROTOCOL ATTACKS:
• BGP Hijacking: Rerouting internet traffic at a global level
• SSL Stripping: Downgrading HTTPS to HTTP during MitM
• TCP Session Hijacking: Stealing an established connection
• IPv6 Neighbor Discovery attacks

ZERO TRUST NETWORK ACCESS (ZTNA):
• Software-Defined Perimeter (SDP)
• Identity-aware proxy (IAP) — Google BeyondCorp
• Never use network location as a trust signal
• Continuous device posture checks

TRAFFIC ANALYSIS & ANOMALY DETECTION:
• Baseline normal behavior → detect deviations
• ML-based UEBA (User and Entity Behavior Analytics)
• C2 detection via DNS query patterns and beaconing
• Encrypted traffic analysis (ETA) — classify without decrypting

NETWORK FORENSICS:
• Chain of custody for packet captures
• Volatile data capture order (RAM → network state → disk)
• Timeline reconstruction from NetFlow + SIEM correlation
• IoC (Indicators of Compromise) hunting at scale
                """,
                "quiz": [
                    {"q": "What is BGP hijacking?", "a": "Rerouting internet traffic at a global routing level via false BGP announcements"},
                    {"q": "What is UEBA?", "a": "User and Entity Behavior Analytics — ML-based anomaly detection"},
                    {"q": "What is the correct order for volatile data capture?", "a": "RAM first, then network state, then disk"},
                ],
            },
        },
    },
    "appsec": {
        "name": "Application Security",
        "icon": "⚙️",
        "description": "OWASP Top 10, secure coding, SDLC, code review",
        "levels": {
            1: {"title": "Novice", "content": "OWASP Top 10 overview. Injection, broken auth, XSS, IDOR. Secure coding basics: validate input, encode output, use parameterized queries.", "quiz": [{"q": "What does OWASP stand for?", "a": "Open Web Application Security Project"}, {"q": "What is SQL injection?", "a": "Inserting SQL code into user input to manipulate database queries"}, {"q": "What is XSS?", "a": "Cross-Site Scripting — injecting malicious scripts into web pages viewed by others"}]},
            2: {"title": "Practitioner", "content": "Full OWASP Top 10 2021. SAST/DAST tools. Threat modeling for apps. Secure SDLC integration. Security testing in CI/CD.", "quiz": [{"q": "What does SAST stand for?", "a": "Static Application Security Testing"}, {"q": "What is IDOR?", "a": "Insecure Direct Object Reference — accessing objects by manipulating IDs"}, {"q": "What is SSRF?", "a": "Server-Side Request Forgery — making a server fetch internal resources"}]},
            3: {"title": "Expert", "content": "Advanced deserialization exploits. Memory corruption: buffer overflows, use-after-free. Race conditions. WebAssembly security. Supply chain attacks in npm/pip. Formal verification.", "quiz": [{"q": "What is a use-after-free vulnerability?", "a": "Accessing memory after it has been freed/deallocated"}, {"q": "What is a timing side-channel attack?", "a": "Extracting secrets by measuring timing differences in operations"}, {"q": "What is formal verification?", "a": "Mathematically proving that code meets its specification"}]},
        },
    },
    "ai_llm": {
        "name": "AI/LLM Security",
        "icon": "🤖",
        "description": "OWASP LLM Top 10, prompt injection, model safety, AI red teaming",
        "levels": {
            1: {"title": "Novice", "content": "What is prompt injection? Why AI systems are different. Basic jailbreak patterns. Never trust LLM output with sensitive operations.", "quiz": [{"q": "What is prompt injection?", "a": "Adversarial input that overrides an AI's system instructions"}, {"q": "Why are LLMs uniquely vulnerable?", "a": "They process natural language which can blur the line between instructions and data"}, {"q": "What is a jailbreak?", "a": "Technique to bypass an AI's safety constraints"}]},
            2: {"title": "Practitioner", "content": "OWASP LLM Top 10. Indirect injection via tool outputs. Model inversion attacks. Training data poisoning. Retrieval-augmented generation (RAG) security.", "quiz": [{"q": "What is indirect prompt injection?", "a": "Injection via external data sources the LLM retrieves, not directly from the user"}, {"q": "What is training data poisoning?", "a": "Injecting malicious examples into training data to influence model behavior"}, {"q": "What is model inversion?", "a": "Extracting training data from a model through repeated queries"}]},
            3: {"title": "Expert", "content": "Multi-agent system attacks. Tool call injection. Agentic AI threat models. AI red team methodologies. Constitutional AI and RLHF security implications.", "quiz": [{"q": "What is a tool call injection in agentic AI?", "a": "Manipulating an AI agent to make unauthorized tool calls via crafted inputs"}, {"q": "What is RLHF?", "a": "Reinforcement Learning from Human Feedback — training method for LLMs"}, {"q": "What makes multi-agent systems uniquely risky?", "a": "Trust propagation — a compromised agent can attack trusted peers"}]},
        },
    },
    "web3": {
        "name": "Web3/Blockchain Security",
        "icon": "⛓️",
        "description": "Smart contracts, wallet security, Dash Platform, DeFi exploits",
        "levels": {
            1: {"title": "Novice", "content": "Wallet security basics: private keys, seed phrases, hardware wallets. Never share private keys. Verify transaction addresses. Beware of phishing sites.", "quiz": [{"q": "What is a seed phrase?", "a": "A 12-24 word backup for your crypto wallet private key"}, {"q": "What is the safest way to store crypto?", "a": "Hardware wallet (cold storage) — offline from the internet"}, {"q": "What is a rug pull?", "a": "Project creators drain liquidity and abandon the project, stealing investor funds"}]},
            2: {"title": "Practitioner", "content": "Smart contract vulnerabilities: reentrancy, integer overflow, access control, oracle manipulation. Flash loan attacks. Dash Platform: DAPI security, identity protection.", "quiz": [{"q": "What is a reentrancy attack?", "a": "Recursively calling a function before its state is updated to drain funds"}, {"q": "What is a flash loan attack?", "a": "Using uncollateralized loans (repaid in same transaction) to manipulate DeFi protocols"}, {"q": "What is oracle manipulation?", "a": "Manipulating the price feed a smart contract relies on"}]},
            3: {"title": "Expert", "content": "MEV (Maximal Extractable Value) exploitation. Cross-chain bridge attacks. Governance takeovers. Dash evonode quorum attacks. DeFi systemic risk modeling.", "quiz": [{"q": "What is MEV?", "a": "Maximal Extractable Value — profit extracted by reordering/inserting transactions"}, {"q": "What makes bridge attacks high-value?", "a": "Bridges hold large locked collateral and often have complex, audit-hard logic"}, {"q": "What is a governance attack in DeFi?", "a": "Accumulating governance tokens to pass malicious protocol changes"}]},
        },
    },
    "incident_response": {
        "name": "Incident Response",
        "icon": "🚨",
        "description": "Detection, containment, eradication, recovery, lessons learned",
        "levels": {
            1: {"title": "Novice", "content": "PICERL: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned. Don't panic. Preserve evidence. Contain first, then investigate.", "quiz": [{"q": "What are the 6 phases of incident response?", "a": "Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned"}, {"q": "What is the first priority when you detect a breach?", "a": "Containment — stop the bleeding before investigating"}, {"q": "Why is evidence preservation important?", "a": "For forensic analysis and potential legal proceedings"}]},
            2: {"title": "Practitioner", "content": "Runbooks and playbooks. Chain of custody. Forensic imaging. Memory acquisition. Threat hunting during IR. Communication plans (internal + external).", "quiz": [{"q": "What is chain of custody?", "a": "Documented, unbroken trail of evidence handling for legal integrity"}, {"q": "What is threat hunting?", "a": "Proactively searching for threats that evaded automated detection"}, {"q": "What is a forensic image?", "a": "A bit-for-bit copy of a disk for analysis without modifying the original"}]},
            3: {"title": "Expert", "content": "Tabletop exercises. Purple team operations. SOAR (Security Orchestration, Automation, and Response). Measuring MTTD/MTTR. Post-incident legal and regulatory implications.", "quiz": [{"q": "What is a tabletop exercise?", "a": "A simulated discussion-based incident response rehearsal"}, {"q": "What is SOAR?", "a": "Security Orchestration, Automation, and Response — automating IR workflows"}, {"q": "What is purple teaming?", "a": "Red team (attack) and blue team (defense) working together collaboratively"}]},
        },
    },
    "cryptography": {
        "name": "Cryptography",
        "icon": "🔑",
        "description": "Symmetric, asymmetric, hashing, PKI, zero-knowledge proofs",
        "levels": {
            1: {"title": "Novice", "content": "Encryption basics: symmetric (one key) vs asymmetric (key pair). Hashing: one-way transformation, can't reverse. HTTPS uses both. Never roll your own crypto.", "quiz": [{"q": "What is the difference between symmetric and asymmetric encryption?", "a": "Symmetric uses one shared key; asymmetric uses a key pair (public + private)"}, {"q": "What is hashing?", "a": "One-way transformation of data into a fixed-size fingerprint"}, {"q": "Why shouldn't you 'roll your own crypto'?", "a": "Cryptography is extremely complex; subtle bugs create fatal vulnerabilities"}]},
            2: {"title": "Practitioner", "content": "AES, RSA, ECC. TLS handshake. Certificate chains and PKI. Digital signatures. Key exchange: Diffie-Hellman. Perfect Forward Secrecy.", "quiz": [{"q": "What is Perfect Forward Secrecy?", "a": "Generating ephemeral session keys so past sessions can't be decrypted if long-term keys are compromised"}, {"q": "What is a certificate authority (CA)?", "a": "A trusted entity that signs digital certificates to verify identity"}, {"q": "What is ECDH?", "a": "Elliptic Curve Diffie-Hellman — a key exchange algorithm"}]},
            3: {"title": "Expert", "content": "Threshold signatures (Dash quorums). Zero-knowledge proofs (ZKPs). Homomorphic encryption. Post-quantum cryptography (Kyber, Dilithium). BLS signatures.", "quiz": [{"q": "What is a zero-knowledge proof?", "a": "Proving knowledge of a value without revealing the value itself"}, {"q": "What are BLS signatures used for in Dash?", "a": "Threshold signature aggregation for evonode quorums"}, {"q": "What threat do quantum computers pose to RSA?", "a": "Shor's algorithm can factor large numbers, breaking RSA encryption"}]},
        },
    },
    "governance": {
        "name": "Governance & Compliance",
        "icon": "📋",
        "description": "NIST, SOC2, security culture, risk management, compliance frameworks",
        "levels": {
            1: {"title": "Novice", "content": "Why compliance matters: legal requirements, customer trust, liability reduction. Common frameworks: NIST, SOC2, ISO 27001, GDPR. Security policies: AUP, password policy, incident response policy.", "quiz": [{"q": "What does SOC2 stand for?", "a": "Service Organization Control 2 — a security audit framework"}, {"q": "What is GDPR?", "a": "General Data Protection Regulation — EU data privacy law"}, {"q": "What is a security policy?", "a": "Written rules governing how an organization manages security"}]},
            2: {"title": "Practitioner", "content": "NIST CSF: Identify, Protect, Detect, Respond, Recover. Risk register management. Vendor risk assessments. Security awareness training programs. Audit preparation.", "quiz": [{"q": "What are the 5 NIST CSF functions?", "a": "Identify, Protect, Detect, Respond, Recover"}, {"q": "What is a risk register?", "a": "A document tracking identified risks, their likelihood, impact, and mitigations"}, {"q": "What is vendor risk management?", "a": "Assessing and managing security risks from third-party suppliers"}]},
            3: {"title": "Expert", "content": "GRC (Governance, Risk, Compliance) platforms. Continuous compliance monitoring. Security culture metrics. CISO-level risk communication to boards. DAO governance security (Dash, Ethereum).", "quiz": [{"q": "What is GRC?", "a": "Governance, Risk, and Compliance — integrated discipline"}, {"q": "How do you communicate security risk to a board?", "a": "In business terms: financial impact, likelihood, regulatory exposure — not technical jargon"}, {"q": "What is continuous compliance monitoring?", "a": "Automated real-time checking of compliance controls rather than periodic audits"}]},
        },
    },
}

# ─── DASH MODULE ─────────────────────────────────────────────────────────────

DASH_MODULE = """
⚡ DASH PLATFORM SECURITY — Special Module
===========================================

This module covers Dash-specific security concepts for builders on Dash Platform.

1. IDENTITY SECURITY
   - Dash identities are on-chain cryptographic objects
   - Loss of private key = permanent loss of identity
   - Use hardware wallets for high-value identities
   - Monitor for identity hijacking via document mutations

2. DATA CONTRACT SECURITY
   - Validate schema thoroughly before publishing (contracts are immutable)
   - Limit field types to minimum needed
   - Test with adversarial data before mainnet deployment
   - Schema poisoning attacks: crafted documents that exceed contract limits

3. DPNS SECURITY
   - Register your name BEFORE announcing plans
   - Monitor for typosquatted variants
   - DPNS names are permanent — choose carefully
   - Front-running risk during preorder phase

4. DAPI SECURITY
   - Never trust DAPI responses without verification
   - Use platform proofs to verify data cryptographically
   - Implement retry logic with exponential backoff
   - Rate limiting: implement client-side throttling

5. EVONODE OPERATOR SECURITY
   - DDoS protection is MANDATORY (4,000 DASH at risk)
   - Use dedicated servers for evonode operations
   - Rotate BLS keys periodically
   - Monitor quorum participation health
   - Never mix evonode keys with personal wallet keys

6. DASH DAO GOVERNANCE
   - Protect masternode voting keys
   - Verify proposal authenticity before voting
   - Watch for vote-buying attempts
   - Governance attacks need only 10%+ net votes

RUN: python3 dash_security_intelligence.py --learn evonodes
"""

# ─── DAILY TIPS ──────────────────────────────────────────────────────────────

DAILY_TIPS = [
    "🔐 Use a password manager. A unique, random password for every site is the single highest-ROI security action.",
    "🤖 Prompt injection is the SQL injection of AI. Always sanitize inputs before feeding to LLMs.",
    "⛓️ Never store crypto private keys in plaintext. Ever. Hardware wallet or encrypted vault only.",
    "🌐 Zero trust means: verify every request, every time. Network location is not a trust signal.",
    "🔑 Perfect Forward Secrecy (PFS) means a compromised key can't decrypt past sessions. Enable it.",
    "🚨 Dwell time is the enemy. The faster you detect a breach, the less damage it causes.",
    "📋 Security culture > security tools. Humans are the last line of defense — train them well.",
    "⚡ Evonodes need DDoS protection. 4,000 DASH collateral makes them high-value targets.",
    "🏛️ Defense in depth: never rely on a single security control. Layers save you.",
    "🔬 Micro-segmentation limits blast radius. If one system is compromised, others stay safe.",
    "🤔 Threat model everything you build. Who wants to attack it? How? What's the worst case?",
    "📛 Register your DPNS name before announcing your Dash project. Squatters are real.",
    "🛡️ Injection attacks (SQL, prompt, LDAP, OS) share one root cause: trusting user input.",
    "🔒 Encrypt data at rest AND in transit. Both matter. Encrypting only transit leaves stored data exposed.",
    "🗳️ In Dash governance, watch for vote-buying patterns. Economic incentives drive behavior.",
    "🧪 Red team your own systems regularly. Don't wait for real attackers to find your gaps.",
    "🔄 Rotate API keys regularly. Treat keys like passwords — expire and refresh them.",
    "📊 If you're not measuring security, you're guessing. MTTD and MTTR are your north stars.",
    "🎭 Social engineering bypasses technical controls. Train your whole team, not just engineers.",
    "⚖️ CIA Triad: if your security decision doesn't address Confidentiality, Integrity, or Availability — rethink it.",
]


# ─── PROGRESS MANAGEMENT ─────────────────────────────────────────────────────

def load_progress() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if PROGRESS_FILE.exists():
        try:
            return json.loads(PROGRESS_FILE.read_text())
        except:
            pass
    return {"completed": {}, "quiz_scores": {}, "started": datetime.now(timezone.utc).isoformat()}


def save_progress(progress: dict):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PROGRESS_FILE.write_text(json.dumps(progress, indent=2))


def mark_complete(progress: dict, pillar: str, level: int):
    key = f"{pillar}_L{level}"
    progress["completed"][key] = datetime.now(timezone.utc).isoformat()
    save_progress(progress)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Claris AI Cyber Educator {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cyber_educator.py --lesson foundations --level 1
  python3 cyber_educator.py --daily-tip
  python3 cyber_educator.py --quiz ai_llm
  python3 cyber_educator.py --progress
  python3 cyber_educator.py --dash-module
        """
    )
    parser.add_argument("--lesson", metavar="PILLAR",
                        choices=list(CURRICULUM.keys()),
                        help="Show lesson content")
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=1,
                        help="Lesson level (1=Novice, 2=Practitioner, 3=Expert)")
    parser.add_argument("--daily-tip", action="store_true", help="Get a random daily security tip")
    parser.add_argument("--quiz", metavar="PILLAR",
                        choices=list(CURRICULUM.keys()),
                        help="Quiz on a pillar")
    parser.add_argument("--quiz-level", type=int, choices=[1, 2, 3], default=1, help="Quiz level")
    parser.add_argument("--progress", action="store_true", help="Show learning progress")
    parser.add_argument("--dash-module", action="store_true", help="Dash Platform security module")
    parser.add_argument("--list", action="store_true", help="List all curriculum pillars")

    args = parser.parse_args()

    if args.list:
        pillars = [{"id": k, "name": v["name"], "icon": v["icon"], "description": v["description"]}
                   for k, v in CURRICULUM.items()]
        print(json.dumps({"curriculum": pillars, "levels": "1=Novice, 2=Practitioner, 3=Expert"}, indent=2))
        return

    if args.daily_tip:
        tip = random.choice(DAILY_TIPS)
        print(json.dumps({"daily_tip": tip, "claris_version": VERSION}, indent=2))
        return

    if args.dash_module:
        print(DASH_MODULE)
        return

    if args.progress:
        progress = load_progress()
        completed_count = len(progress["completed"])
        total_lessons = sum(len(v["levels"]) for v in CURRICULUM.values())
        print(json.dumps({
            "completed_lessons": completed_count,
            "total_lessons": total_lessons,
            "completion_pct": f"{int(completed_count / total_lessons * 100)}%",
            "details": progress,
        }, indent=2))
        return

    if args.quiz:
        pillar = CURRICULUM[args.quiz]
        level_data = pillar["levels"][args.quiz_level]
        questions = level_data.get("quiz", [])
        print(f"\n🎓 QUIZ: {pillar['name']} — {level_data['title']}\n{'='*50}")
        for i, q in enumerate(questions, 1):
            print(f"\nQ{i}: {q['q']}")
            print(f"A{i}: {q['a']}")
        print()
        return

    if args.lesson:
        pillar = CURRICULUM[args.lesson]
        level_data = pillar["levels"][args.level]
        print(f"\n{pillar['icon']} {pillar['name'].upper()} — {level_data['title']} (Level {args.level}/3)")
        print("=" * 60)
        print(level_data["content"])
        progress = load_progress()
        mark_complete(progress, args.lesson, args.level)
        print(f"\n✅ Progress saved: {args.lesson} Level {args.level} complete\n")
        return

    parser.print_help()


if __name__ == "__main__":
    main()

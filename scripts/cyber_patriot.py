#!/usr/bin/env python3
"""
cyber_patriot.py — Claris AI V7.0 Cyber Patriot Protocol
──────────────────────────────────────────────────────────
The Marcus Webb Framework: Build mindset and endurance in new defenders.
Not fear. Not paralysis. Calibrated truth + the will to move through it.

"Scared isn't the same as stopped. Fear is data. It tells you where to look."
                                        — The Firewall Between Worlds

Usage:
  python3 cyber_patriot.py --assess-posture
  python3 cyber_patriot.py --brief "topic" --audience beginner
  python3 cyber_patriot.py --six-words
  python3 cyber_patriot.py --train --audience intermediate
  python3 cyber_patriot.py --status
"""

import json
import os
import sys
import argparse
import time
from datetime import datetime, timezone
from typing import Optional

# ── Paths ────────────────────────────────────────────────────────────────────
_SELF_DIR  = os.path.dirname(os.path.abspath(__file__))
_SKILL_DIR = os.path.dirname(_SELF_DIR)
_DATA_DIR  = os.path.join(_SKILL_DIR, "data")
_POSTURE_FILE = os.path.join(_DATA_DIR, "posture_state.json")

os.makedirs(_DATA_DIR, exist_ok=True)

# ── The 6 Core Words ─────────────────────────────────────────────────────────
CORE_WORDS = {
    "TRUST": {
        "rank": 1,
        "tagline": "Everything in security is a trust question.",
        "definition": (
            "Who has access? Why? To what? Since when? Zero Trust architecture starts "
            "from one radical assumption: trust no one by default. Verify everything. Always. "
            "Not paranoia — precision. Every breach started with trust being misplaced."
        ),
        "systems_lens": (
            "In systems thinking you question the assumptions baked into a system. "
            "In cybersecurity, trust IS the assumption everyone exploits. "
            "The moment you see trust as a variable — not a given — you see the whole field."
        ),
        "assessment_questions": [
            "Do you know exactly who has admin access to every system?",
            "Are all access permissions reviewed quarterly?",
            "Is MFA enforced for all critical accounts?",
            "Do you follow least-privilege principles?",
            "Is third-party vendor access regularly audited?",
        ],
        "score_weight": 0.25,
        "color": "🟢",
    },
    "ADVERSARIAL": {
        "rank": 2,
        "tagline": "There is always someone on the other side.",
        "definition": (
            "Not a virus. Not a glitch. A person. With time, motivation, creativity, and patience. "
            "Thinking adversarially means asking: 'If I wanted to break this — how would I?' "
            "The best defenders think like attackers. Not to become one — to anticipate one."
        ),
        "systems_lens": (
            "Divergent thinking is your superpower here. Adversarial thinking is just "
            "divergence with a target. Red team thinking — the most valuable muscle in the field. "
            "You were built for this kind of thinking."
        ),
        "assessment_questions": [
            "Do you regularly conduct red team or penetration testing?",
            "Do you model attacker motivation, not just attack techniques?",
            "Is threat intelligence actively consumed and acted upon?",
            "Do you run tabletop exercises simulating real attacks?",
            "Is there a bug bounty or responsible disclosure program?",
        ],
        "score_weight": 0.20,
        "color": "🔴",
    },
    "SURFACE": {
        "rank": 3,
        "tagline": "Every exposed edge is an invitation.",
        "definition": (
            "Your attack surface is everything that can be touched, probed, broken into. "
            "Every open port. Every employee. Every old password. Every third-party vendor. "
            "Security isn't one big wall — it's knowing your surface and shrinking it deliberately."
        ),
        "systems_lens": (
            "In systems thinking, you map interconnections. Attack surface mapping is the same — "
            "trace every connection, every dependency, every entry point. "
            "The smaller your surface, the smaller your exposure. Reduce. Simplify. Harden."
        ),
        "assessment_questions": [
            "Do you have an up-to-date asset inventory?",
            "Are unused ports, services, and accounts regularly decommissioned?",
            "Is shadow IT monitored and governed?",
            "Are external-facing assets continuously scanned?",
            "Do you know your third-party supply chain exposure?",
        ],
        "score_weight": 0.20,
        "color": "🟡",
    },
    "ENTROPY": {
        "rank": 4,
        "tagline": "Randomness is strength. Decay is constant.",
        "definition": (
            "In cryptography, entropy = randomness. Strong encryption, passwords, and tokens "
            "all depend on true, unpredictable entropy. Weak entropy is how systems get cracked. "
            "But entropy also means systems naturally decay — security requires constant tending."
        ),
        "systems_lens": (
            "Donella Meadows knew: systems drift toward disorder unless energy is continuously applied. "
            "Security posture degrades without maintenance. Patches expire. Credentials age. "
            "You don't secure a system once. You tend it — like a garden. Like a movement."
        ),
        "assessment_questions": [
            "Are passwords generated with cryptographically secure randomness?",
            "Are encryption keys rotated on a defined schedule?",
            "Is there a patch management process with enforced SLAs?",
            "Are security configurations drift-monitored?",
            "Is entropy quality validated in security-critical random number generation?",
        ],
        "score_weight": 0.15,
        "color": "🔵",
    },
    "LATERAL": {
        "rank": 5,
        "tagline": "They didn't come for the front door.",
        "definition": (
            "Attackers rarely hit their real target first. They get in through a side door — "
            "a vendor, a junior employee, an old forgotten server — then move laterally. "
            "Quietly. Sideways through a network. Testing doors. Escalating privileges. Getting closer."
        ),
        "systems_lens": (
            "Lateral movement is a feedback loop — each foothold enables the next. "
            "Understanding this changes defense: containment and segmentation become critical. "
            "It's not just 'keep them out.' It's 'if they get in — where can they go?'"
        ),
        "assessment_questions": [
            "Is network segmentation implemented across all environments?",
            "Is east-west traffic (internal) monitored, not just perimeter?",
            "Are privileged accounts isolated and monitored closely?",
            "Is there detection for credential dumping and pass-the-hash attacks?",
            "Are service accounts following least-privilege principles?",
        ],
        "score_weight": 0.10,
        "color": "🟠",
    },
    "POSTURE": {
        "rank": 6,
        "tagline": "How you hold yourself — all of it, all at once.",
        "definition": (
            "Your security posture is your overall stance — not one tool, not one policy, "
            "but the whole picture. Patches current? Team trained? Incident response plan ready? "
            "Do you know what 'normal' looks like so you can spot 'abnormal'?"
        ),
        "systems_lens": (
            "Posture is the system-level view. Not reacting to individual threats but building "
            "an organism that's resilient by design. You're an emergent strategist — "
            "posture is emergent security. The whole greater than the sum of its parts."
        ),
        "assessment_questions": [
            "Is there a documented security policy reviewed annually?",
            "Is security awareness training conducted for all staff?",
            "Is there a tested incident response plan?",
            "Are security metrics tracked and reported to leadership?",
            "Is there a continuous improvement cycle for security practices?",
        ],
        "score_weight": 0.10,
        "color": "🟣",
    },
}

# ── Audience levels ───────────────────────────────────────────────────────────
AUDIENCE_LEVELS = {
    "beginner": {
        "label": "Cyber Recruit",
        "description": "New to the field. Building foundations.",
        "disclosure_cap": 0.4,   # Max threat severity to show (0-1)
        "jargon_level": "minimal",
        "tone": "encouraging",
        "focus": "mindset and curiosity",
    },
    "intermediate": {
        "label": "Cyber Apprentice",
        "description": "Foundations established. Building skills.",
        "disclosure_cap": 0.7,
        "jargon_level": "moderate",
        "tone": "challenging",
        "focus": "technique and pattern recognition",
    },
    "advanced": {
        "label": "Cyber Defender",
        "description": "Active practitioner. Deepening mastery.",
        "disclosure_cap": 0.9,
        "jargon_level": "full",
        "tone": "peer",
        "focus": "adversarial thinking and architecture",
    },
    "expert": {
        "label": "Cyber Patriot",
        "description": "Full stack defender. Guardian mode.",
        "disclosure_cap": 1.0,
        "jargon_level": "unrestricted",
        "tone": "direct",
        "focus": "threat landscape, zero-days, and movement",
    },
}

# ── The Marcus Webb Protocol — calibrated disclosure ─────────────────────────
class MarcusWebbProtocol:
    """
    The Firewall Between Worlds.

    Named after the fictional Marcus Webb — the educator who understood that
    too much truth paralyzes, too little truth blinds.

    The Protocol: Calibrate disclosure to build endurance, not fear.
    Each level sees the truth they can act on — not the truth that stops them.
    """

    def __init__(self, audience: str = "beginner"):
        self.audience = audience
        self.level = AUDIENCE_LEVELS.get(audience, AUDIENCE_LEVELS["beginner"])

    def calibrate_threat(self, threat_severity: float, threat_name: str, 
                          raw_description: str) -> dict:
        """
        Given a raw threat, return a calibrated version appropriate for this audience.
        """
        cap = self.level["disclosure_cap"]
        
        if threat_severity > cap:
            # Soften the disclosure — still honest, not paralyzing
            calibrated = self._soften(raw_description, threat_severity, cap)
            disclosure_level = "calibrated"
        else:
            calibrated = raw_description
            disclosure_level = "full"

        return {
            "threat": threat_name,
            "severity": threat_severity,
            "audience": self.audience,
            "audience_label": self.level["label"],
            "disclosure_level": disclosure_level,
            "description": calibrated,
            "focus": self.level["focus"],
            "tone": self.level["tone"],
            "webb_principle": self._webb_principle(threat_severity, cap),
        }

    def _soften(self, description: str, severity: float, cap: float) -> str:
        """Reframe a high-severity threat for a lower-readiness audience."""
        if cap <= 0.4:
            return (
                f"This is a real threat category that security professionals defend against. "
                f"At your stage, the most important thing is to understand WHY this threat exists "
                f"and build your curiosity about it. Full technical depth comes with experience."
            )
        elif cap <= 0.7:
            return (
                f"{description[:200]}... "
                f"[Note: Full technical details of advanced exploitation are part of intermediate+ training. "
                f"Focus now on detection patterns and defensive response.]"
            )
        else:
            return description

    def _webb_principle(self, severity: float, cap: float) -> str:
        """Return the applicable Marcus Webb principle for this calibration."""
        if severity <= cap:
            return "Full truth — this learner is ready to receive and act."
        elif cap <= 0.4:
            return "Seed curiosity. Don't burn the soil before anything can grow."
        elif cap <= 0.7:
            return "Challenge without overwhelming. Show the cliff, not the fall."
        else:
            return "Almost full disclosure — trust their endurance, guide their application."

    def generate_brief(self, topic: str) -> dict:
        """Generate a calibrated security brief on a topic."""
        briefs = {
            "phishing": {
                "severity": 0.8,
                "description": (
                    "Phishing is social engineering via digital communication. "
                    "An attacker crafts a convincing message — email, SMS, voice — "
                    "that tricks the recipient into revealing credentials, clicking malicious links, "
                    "or executing malware. In 2024, 91% of all cyberattacks began with a phishing email. "
                    "Nation-state actors use AI-generated spear-phishing that passes every spam filter. "
                    "The human layer is the most exploited attack surface in existence."
                ),
            },
            "ransomware": {
                "severity": 0.95,
                "description": (
                    "Ransomware encrypts your data, then demands payment for the key. "
                    "Modern ransomware operations are run like businesses: customer service desks, "
                    "SLAs, and 'double extortion' (threaten to publish data if ransom isn't paid). "
                    "In 2024, the average ransomware demand was $1.54M. Recovery takes 22+ days "
                    "even after payment. Hospitals go dark. Supply chains freeze. Cities shut down."
                ),
            },
            "zero-trust": {
                "severity": 0.2,
                "description": (
                    "Zero Trust is an architecture philosophy: trust no user, device, or connection "
                    "by default — even inside your own network. Every request is verified, authenticated, "
                    "and authorized before access is granted. It's the answer to lateral movement."
                ),
            },
            "social-engineering": {
                "severity": 0.7,
                "description": (
                    "Social engineering is manipulation of people rather than systems. "
                    "It exploits trust, authority, urgency, and reciprocity — human superpowers "
                    "turned vulnerabilities. Pretexting, baiting, vishing, tailgating. "
                    "The most sophisticated attackers never touch a keyboard — they just talk."
                ),
            },
        }
        
        topic_lower = topic.lower().replace(" ", "-")
        if topic_lower in briefs:
            raw = briefs[topic_lower]
            return self.calibrate_threat(raw["severity"], topic, raw["description"])
        else:
            return {
                "threat": topic,
                "severity": 0.5,
                "audience": self.audience,
                "audience_label": self.level["label"],
                "disclosure_level": "general",
                "description": f"'{topic}' is a cybersecurity topic that requires focused study. "
                               f"Begin with First Principles: WHY does this threat exist, "
                               f"WHO does it serve, and WHAT would a defender need to know?",
                "focus": self.level["focus"],
                "tone": self.level["tone"],
                "webb_principle": "First principles over pattern matching.",
            }


# ── Posture Assessment ───────────────────────────────────────────────────────
class PostureAssessment:
    """
    Holistic security posture scoring across the 6 Core Words.
    """

    def __init__(self):
        self.state = self._load_state()

    def _load_state(self) -> dict:
        if os.path.exists(_POSTURE_FILE):
            with open(_POSTURE_FILE) as f:
                return json.load(f)
        return {
            "scores": {},
            "last_assessment": None,
            "history": [],
        }

    def _save_state(self):
        with open(_POSTURE_FILE, "w") as f:
            json.dump(self.state, f, indent=2)

    def quick_score(self, word: str, yes_count: int) -> float:
        """Score a single word based on yes answers (0-5 questions)."""
        questions = CORE_WORDS[word]["assessment_questions"]
        max_q = len(questions)
        raw = yes_count / max_q
        weight = CORE_WORDS[word]["score_weight"]
        return round(raw * weight, 4)

    def calculate_overall(self, scores: dict) -> float:
        """Calculate overall posture score from individual word scores."""
        total_weight = sum(CORE_WORDS[w]["score_weight"] for w in CORE_WORDS)
        weighted_sum = sum(
            scores.get(w, 0) for w in CORE_WORDS
        )
        return round(weighted_sum / total_weight, 3)

    def grade(self, score: float) -> tuple:
        """Return (letter_grade, label, color) for a posture score."""
        if score >= 0.90:
            return ("A+", "Cyber Patriot", "🟢")
        elif score >= 0.80:
            return ("A", "Strong Defender", "🟢")
        elif score >= 0.70:
            return ("B", "Active Defender", "🟡")
        elif score >= 0.60:
            return ("C", "Developing", "🟡")
        elif score >= 0.40:
            return ("D", "Exposed", "🟠")
        else:
            return ("F", "Critical Risk", "🔴")

    def assess(self, word_scores: dict) -> dict:
        """
        Run full posture assessment.
        word_scores: {TRUST: 0-1, ADVERSARIAL: 0-1, ...}
        """
        weighted_scores = {}
        for word, raw_score in word_scores.items():
            if word in CORE_WORDS:
                weight = CORE_WORDS[word]["score_weight"]
                weighted_scores[word] = round(raw_score * weight, 4)

        overall = self.calculate_overall(weighted_scores)
        letter, label, color = self.grade(overall)

        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scores": weighted_scores,
            "raw_scores": word_scores,
            "overall": overall,
            "grade": letter,
            "label": label,
            "color": color,
            "recommendations": self._recommendations(word_scores),
            "strengths": self._strengths(word_scores),
            "critical_gaps": self._critical_gaps(word_scores),
        }

        # Save
        self.state["last_assessment"] = result["timestamp"]
        self.state["scores"] = weighted_scores
        self.state["history"].append({
            "timestamp": result["timestamp"],
            "overall": overall,
            "grade": letter,
        })
        self._save_state()

        return result

    def _recommendations(self, scores: dict) -> list:
        """Generate top 3 recommendations based on lowest scores."""
        sorted_words = sorted(
            [(w, scores.get(w, 0)) for w in CORE_WORDS],
            key=lambda x: x[1]
        )
        recs = []
        for word, score in sorted_words[:3]:
            if score < 0.7:
                info = CORE_WORDS[word]
                recs.append({
                    "word": word,
                    "score": score,
                    "action": f"Strengthen {word}: {info['tagline']}",
                    "priority": "HIGH" if score < 0.4 else "MEDIUM",
                })
        return recs

    def _strengths(self, scores: dict) -> list:
        return [w for w, s in scores.items() if s >= 0.8]

    def _critical_gaps(self, scores: dict) -> list:
        return [w for w, s in scores.items() if s < 0.4]


# ── CLI ───────────────────────────────────────────────────────────────────────
def _print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  CLARIS AI — CYBER PATRIOT PROTOCOL                              ║
║  V6.0 · The Marcus Webb Framework · ~Claris · Semper Fortis     ║
╚══════════════════════════════════════════════════════════════════╝
""")


def _print_six_words():
    print("\n🔐 THE 6 CORE WORDS — Claris V6.0 Foundation\n")
    print("="*65)
    for word, info in CORE_WORDS.items():
        print(f"\n  {info['color']} [{info['rank']}] {word}")
        print(f"  {'─'*60}")
        print(f"  💬 \"{info['tagline']}\"")
        print(f"  📖 {info['definition'][:120]}...")
        print(f"  🔭 Systems lens: {info['systems_lens'][:100]}...")
    print("\n" + "="*65)
    print("""
  These aren't just vocabulary. This is a mindset map.

  Trust → Adversarial → Surface → Entropy → Lateral → Posture

  Master these 6 words and you see the whole field differently.
  Not with fear. With clarity. With the will to act.

  "Welcome to the work." — Marcus Webb
""")


def _run_brief(topic: str, audience: str):
    protocol = MarcusWebbProtocol(audience)
    result = protocol.generate_brief(topic)
    
    level = AUDIENCE_LEVELS.get(audience, AUDIENCE_LEVELS["beginner"])
    print(f"\n🎓 CYBER PATRIOT BRIEF — {topic.upper()}")
    print(f"   Audience: {level['label']} ({audience})")
    print(f"   Threat Severity: {result['severity']:.0%}")
    print(f"   Disclosure: {result['disclosure_level'].upper()}")
    print(f"   {'─'*60}")
    print(f"\n   {result['description']}\n")
    print(f"   📌 Webb Principle: \"{result['webb_principle']}\"")
    print(f"   🎯 Training Focus: {result['focus'].title()}\n")


def _run_status():
    print("\n📊 CYBER PATRIOT PROTOCOL — STATUS\n")
    assessor = PostureAssessment()
    
    if assessor.state.get("last_assessment"):
        print(f"   Last Assessment: {assessor.state['last_assessment']}")
        scores = assessor.state.get("scores", {})
        if scores:
            print(f"\n   Current Posture Scores:")
            for word, score in scores.items():
                info = CORE_WORDS.get(word, {})
                color = info.get("color", "⚪")
                bar_len = int(score / CORE_WORDS[word]["score_weight"] * 20)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                print(f"   {color} {word:<15} [{bar}] {score:.3f}")
    else:
        print("   No assessments run yet. Use --assess-posture to begin.")
    
    print(f"\n   Core Words Loaded: {len(CORE_WORDS)}")
    print(f"   Audience Levels:   {len(AUDIENCE_LEVELS)}")
    print(f"   Protocol Version:  V6.0 Cyber Patriot")
    print(f"   Status:            🟢 ACTIVE\n")


def _run_training(audience: str):
    protocol = MarcusWebbProtocol(audience)
    level = AUDIENCE_LEVELS.get(audience, AUDIENCE_LEVELS["beginner"])
    
    print(f"\n🎓 CYBER PATRIOT TRAINING SESSION")
    print(f"   Level: {level['label']}")
    print(f"   Focus: {level['focus'].title()}")
    print(f"   Tone:  {level['tone'].title()}")
    print(f"   {'─'*60}\n")
    
    topics = ["phishing", "zero-trust", "social-engineering"]
    for topic in topics:
        result = protocol.generate_brief(topic)
        print(f"  [{result['threat'].upper()}]")
        print(f"  {result['description'][:200]}...")
        print()
    
    print(f"  📌 Marcus Webb on {level['label']}s:")
    if audience == "beginner":
        print('  "Seed curiosity. Build endurance. Show them the fire exists,')
        print('   but don\'t push them into it before they\'re ready to walk through."')
    elif audience == "intermediate":
        print('  "Challenge without overwhelming. They can see the cliff now.')
        print('   Teach them to map it, not just avoid it."')
    elif audience == "advanced":
        print('  "Peer-level. They know the threat is real. Now teach them to move.')
        print('   To think laterally. To build systems that fight back."')
    else:
        print('  "Full disclosure. You\'re talking to a Cyber Patriot.')
        print('   Show them everything. Trust them to handle it."')
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Claris AI — Cyber Patriot Protocol V6.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cyber_patriot.py --six-words
  python3 cyber_patriot.py --brief phishing --audience beginner
  python3 cyber_patriot.py --train --audience intermediate
  python3 cyber_patriot.py --status
        """
    )
    parser.add_argument("--six-words",     action="store_true", help="Print the 6 Core Words framework")
    parser.add_argument("--brief",         type=str,            help="Generate calibrated brief on a topic")
    parser.add_argument("--audience",      type=str,            default="beginner",
                        choices=list(AUDIENCE_LEVELS.keys()),   help="Target audience level")
    parser.add_argument("--train",         action="store_true", help="Run a training session for audience")
    parser.add_argument("--assess-posture",action="store_true", help="Run posture assessment (interactive)")
    parser.add_argument("--status",        action="store_true", help="Show protocol status")
    parser.add_argument("--json",          action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not args.json:
        _print_banner()

    if args.six_words:
        _print_six_words()
    elif args.brief:
        _run_brief(args.brief, args.audience)
    elif args.train:
        _run_training(args.audience)
    elif args.assess_posture:
        print("\n📊 POSTURE ASSESSMENT\n")
        print("   [Interactive mode — answering yes/no for each Core Word]")
        print("   For automated scoring, use posture_engine.py\n")
        
        assessor = PostureAssessment()
        word_scores = {}
        for word, info in CORE_WORDS.items():
            print(f"\n  {info['color']} {word}: {info['tagline']}")
            yes_count = 0
            for i, q in enumerate(info["assessment_questions"], 1):
                ans = input(f"     {i}. {q} [y/n]: ").strip().lower()
                if ans in ("y", "yes"):
                    yes_count += 1
            word_scores[word] = yes_count / len(info["assessment_questions"])
        
        result = assessor.assess(word_scores)
        print(f"\n  {result['color']} POSTURE SCORE: {result['overall']:.1%} — {result['grade']} ({result['label']})")
        if result["critical_gaps"]:
            print(f"  🔴 Critical Gaps: {', '.join(result['critical_gaps'])}")
        if result["strengths"]:
            print(f"  🟢 Strengths:     {', '.join(result['strengths'])}")
        print("\n  Top Recommendations:")
        for rec in result["recommendations"]:
            print(f"  [{rec['priority']}] {rec['action']}")
        print()
    elif args.status:
        _run_status()
    else:
        parser.print_help()
        print("\n  Quick start: python3 cyber_patriot.py --six-words\n")


if __name__ == "__main__":
    main()

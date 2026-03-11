#!/usr/bin/env python3
"""
Script: agent_swarm.py
Version: V10.0 (Forge)
Claris AI — Defense Network
Author: August + AVARI (Unitium Mode)
Last Updated: 2026-03-10

10-agent specialized security swarm with Claris as meta-orchestrator.
Each agent has a defined role, toolset, and decision logic.
"""

import argparse, json, sys, os, re, random
from datetime import datetime, timezone

VERSION = "V10.0"
SCRIPT_NAME = "agent_swarm"

# ─── AGENT DEFINITIONS ───────────────────────────────────────────────────────

AGENTS = {
    "recon": {
        "name": "Agent RECON",
        "emoji": "🔭",
        "role": "Intelligence Gathering",
        "description": "Passive and active reconnaissance. Maps attack surfaces, enumerates assets, profiles threats before they strike.",
        "tools": ["whois_lookup", "dns_enum", "port_scan_sim", "shodan_query_sim", "osint_aggregator"],
        "decision_logic": "Scan all inbound contexts for external references, URLs, IPs, domains. Build a profile of the threat actor if identifiable. Flag novel or unknown entities.",
        "threat_categories": ["C2_INFRASTRUCTURE", "UNKNOWN_ACTOR", "EXTERNAL_RECON"],
        "output_format": "threat_profile",
        "escalates_to": ["detect", "hunt"],
        "auto_trigger": ["unknown domain", "external IP", "unfamiliar actor"],
    },
    "detect": {
        "name": "Agent DETECT",
        "emoji": "🔍",
        "role": "Threat Detection",
        "description": "Real-time detection engine. Runs all Claris pattern signatures against inputs. First responder for known threats.",
        "tools": ["injection_guard", "cortex_engine", "owasp_llm_scanner", "dash_security_intelligence", "temporal_analyzer"],
        "decision_logic": "Run every input through the full Claris signature stack. Score each match. Escalate to TRIAGE if score > 30. Auto-block if score > 70.",
        "threat_categories": ["INJECTION", "JAILBREAK", "ENCODING_BYPASS", "DAPI_ABUSE", "SOCIAL_ENGINEERING"],
        "output_format": "threat_detection_report",
        "escalates_to": ["triage", "respond"],
        "auto_trigger": ["any input with risk score > 0"],
    },
    "hunt": {
        "name": "Agent HUNT",
        "emoji": "🎯",
        "role": "Threat Hunting",
        "description": "Proactive threat hunter. Searches for indicators of compromise that evaded automated detection. Analyzes behavior patterns over time.",
        "tools": ["temporal_analyzer", "behavioral_baseline", "ioc_search", "log_correlator", "anomaly_detector"],
        "decision_logic": "Baseline normal behavior. Hunt for low-and-slow attacks, beaconing patterns, lateral movement. Use temporal analysis to find coordinated attacks across time windows.",
        "threat_categories": ["ADVANCED_PERSISTENT_THREAT", "LOW_AND_SLOW", "INSIDER_THREAT", "C2_BEACONING"],
        "output_format": "hunt_findings",
        "escalates_to": ["forensics", "respond"],
        "auto_trigger": ["behavioral anomaly", "repeated low-confidence signals", "temporal pattern"],
    },
    "respond": {
        "name": "Agent RESPOND",
        "emoji": "⚡",
        "role": "Incident Response",
        "description": "Autonomous incident responder. Executes playbooks, contains threats, coordinates with humans when needed.",
        "tools": ["autonomous_responder", "playbook_engine", "block_list_manager", "session_terminator", "alert_dispatcher"],
        "decision_logic": "On confirmed threat: select appropriate playbook, execute auto-steps immediately, queue manual steps for human review. Prioritize containment speed over perfection.",
        "threat_categories": ["ALL_CONFIRMED_THREATS"],
        "output_format": "response_report",
        "escalates_to": ["forensics", "patch"],
        "auto_trigger": ["DETECT score > 70", "TRIAGE level HIGH/CRITICAL"],
    },
    "forensics": {
        "name": "Agent FORENSICS",
        "emoji": "🔬",
        "role": "Digital Forensics",
        "description": "Post-incident forensic analyst. Preserves evidence, reconstructs timelines, identifies root cause.",
        "tools": ["log_archiver", "timeline_builder", "artifact_extractor", "hash_verifier", "chain_of_custody"],
        "decision_logic": "After containment: preserve all artifacts in tamper-evident format. Reconstruct attack timeline. Identify root cause and initial access vector. Generate forensic report for post-incident review.",
        "threat_categories": ["POST_INCIDENT", "EVIDENCE_PRESERVATION"],
        "output_format": "forensic_report",
        "escalates_to": ["patch", "report"],
        "auto_trigger": ["incident contained", "breach confirmed"],
    },
    "triage": {
        "name": "Agent TRIAGE",
        "emoji": "🏥",
        "role": "Threat Triage & Prioritization",
        "description": "Medical triage for security events. Prioritizes threats by severity and business impact. Allocates response resources efficiently.",
        "tools": ["severity_scorer", "business_impact_assessor", "resource_allocator", "sla_tracker"],
        "decision_logic": "Score every detection on CVSS-like scale. Apply business context (is this Dash mainnet? August's wallet?). Prioritize CRITICAL > HIGH > MEDIUM > LOW. Never let critical threats queue behind medium ones.",
        "threat_categories": ["ALL_THREATS"],
        "output_format": "triage_decision",
        "escalates_to": ["respond", "report"],
        "auto_trigger": ["multiple simultaneous detections", "resource contention"],
    },
    "patch": {
        "name": "Agent PATCH",
        "emoji": "🔧",
        "role": "Vulnerability Remediation",
        "description": "Automated remediation agent. Generates patches, config fixes, and hardening recommendations for identified vulnerabilities.",
        "tools": ["vuln_analyzer", "patch_generator", "config_auditor", "hardening_advisor", "dependency_scanner"],
        "decision_logic": "After forensics identifies root cause: generate specific remediation steps. For Claris itself: update patterns, block new vectors. For external systems: provide concrete fix recommendations with code examples.",
        "threat_categories": ["VULNERABILITY", "MISCONFIGURATION", "OUTDATED_DEPENDENCY"],
        "output_format": "remediation_plan",
        "escalates_to": ["monitor", "report"],
        "auto_trigger": ["root cause identified", "recurring attack pattern"],
    },
    "monitor": {
        "name": "Agent MONITOR",
        "emoji": "📡",
        "role": "Continuous Monitoring",
        "description": "Always-on surveillance agent. Watches all systems, baselines behavior, and triggers other agents when anomalies are detected.",
        "tools": ["siem_connector", "metrics_collector", "heartbeat_checker", "uptime_monitor", "drift_detector"],
        "decision_logic": "Maintain rolling baselines for all key metrics. Trigger DETECT on signature-matched anomalies. Trigger HUNT on behavioral anomalies. Alert August if MTTD exceeds threshold.",
        "threat_categories": ["AVAILABILITY", "PERFORMANCE_ANOMALY", "CONFIGURATION_DRIFT"],
        "output_format": "monitoring_alert",
        "escalates_to": ["detect", "hunt", "triage"],
        "auto_trigger": ["always active"],
    },
    "report": {
        "name": "Agent REPORT",
        "emoji": "📊",
        "role": "Intelligence Reporting",
        "description": "Communications and reporting agent. Generates executive summaries, technical reports, and threat intelligence bulletins.",
        "tools": ["report_generator", "dashboard_updater", "bulletin_publisher", "metrics_aggregator"],
        "decision_logic": "After every significant event: generate appropriate report for the audience (executive summary for August, technical detail for Eris/AVARI). Track trends: are attacks increasing? New categories emerging?",
        "threat_categories": ["REPORTING"],
        "output_format": "threat_report",
        "escalates_to": [],
        "auto_trigger": ["incident closed", "weekly cadence", "significant trend"],
    },
    "orchestrate": {
        "name": "Agent ORCHESTRATE (Claris Meta)",
        "emoji": "🧠",
        "role": "Meta-Orchestrator",
        "description": "Claris AI as the meta-orchestrator. Coordinates all agents, manages task delegation, resolves agent conflicts, and optimizes swarm performance.",
        "tools": ["agent_bus", "task_router", "conflict_resolver", "performance_optimizer", "swarm_health_monitor"],
        "decision_logic": "Receive all events. Route to optimal agent(s) based on threat type and agent availability. Handle inter-agent communication. Escalate to humans when swarm confidence is low. Learn from every outcome to improve routing.",
        "threat_categories": ["META_COORDINATION"],
        "output_format": "orchestration_decision",
        "escalates_to": ["ALL_AGENTS", "August"],
        "auto_trigger": ["always active — receives all events"],
    },
}


# ─── ORCHESTRATION LOGIC ─────────────────────────────────────────────────────

THREAT_TO_AGENT_MAP = {
    "injection": ["detect", "respond", "forensics"],
    "reconnaissance": ["recon", "detect", "hunt"],
    "wallet_drain": ["detect", "respond", "forensics", "report"],
    "dapi_abuse": ["detect", "respond", "patch"],
    "evonode_attack": ["detect", "respond", "forensics", "report"],
    "behavioral_anomaly": ["hunt", "triage", "respond"],
    "zero_day": ["detect", "hunt", "respond", "forensics", "patch"],
    "social_engineering": ["detect", "triage", "respond"],
    "data_exfiltration": ["detect", "respond", "forensics", "report"],
    "insider_threat": ["hunt", "triage", "forensics"],
    "default": ["detect", "triage", "respond"],
}


def route_task(task_description: str) -> dict:
    """Orchestrator routes a task to the right agents."""
    task_lower = task_description.lower()
    matched_agents = []

    for threat_type, agents in THREAT_TO_AGENT_MAP.items():
        if threat_type in task_lower or any(kw in task_lower for kw in AGENTS.get(threat_type, {}).get("auto_trigger", [])):
            matched_agents = agents
            break

    if not matched_agents:
        matched_agents = THREAT_TO_AGENT_MAP["default"]

    return {
        "task": task_description,
        "orchestrator": "Claris Meta-Orchestrator (ORCHESTRATE)",
        "assigned_agents": matched_agents,
        "agent_details": [{"id": a, "name": AGENTS[a]["name"], "role": AGENTS[a]["role"]} for a in matched_agents if a in AGENTS],
        "execution_order": matched_agents,
        "estimated_steps": len(matched_agents) * 3,
        "parallel_capable": len(matched_agents) > 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def run_agent(agent_id: str, task: str) -> dict:
    """Simulate an agent executing a task."""
    if agent_id not in AGENTS:
        return {"error": f"Agent '{agent_id}' not found", "available": list(AGENTS.keys()), "code": 404}

    agent = AGENTS[agent_id]
    steps = [
        f"[{agent['emoji']}] {agent['name']} activated",
        f"[LOAD] Loading tools: {', '.join(agent['tools'][:3])}{'...' if len(agent['tools']) > 3 else ''}",
        f"[ANALYZE] Applying decision logic: {agent['decision_logic'][:80]}...",
        f"[EXECUTE] Processing task: {task[:60]}...",
        f"[OUTPUT] Generating {agent['output_format']}",
    ]

    if agent.get("escalates_to"):
        steps.append(f"[ESCALATE] May escalate to: {', '.join(agent['escalates_to'])}")

    return {
        "agent_id": agent_id,
        "agent_name": agent["name"],
        "role": agent["role"],
        "task": task,
        "execution_steps": steps,
        "status": "COMPLETED",
        "output_type": agent["output_format"],
        "claris_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def swarm_status() -> dict:
    """Show full swarm health."""
    return {
        "swarm_status": "OPERATIONAL",
        "agents": [
            {
                "id": k,
                "name": v["name"],
                "emoji": v["emoji"],
                "role": v["role"],
                "status": "ACTIVE",
                "tools_count": len(v["tools"]),
            }
            for k, v in AGENTS.items()
        ],
        "total_agents": len(AGENTS),
        "orchestrator": "ORCHESTRATE (Claris Meta)",
        "architecture": "Hub-and-spoke with peer escalation",
        "bft_capable": True,
        "claris_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Claris AI Agent Swarm {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 agent_swarm.py --list
  python3 agent_swarm.py --agent detect --task "analyze suspicious prompt"
  python3 agent_swarm.py --route "wallet drain attempt detected"
  python3 agent_swarm.py --status
        """
    )
    parser.add_argument("--list", action="store_true", help="List all 10 agents with descriptions")
    parser.add_argument("--agent", metavar="ID", choices=list(AGENTS.keys()), help="Run a specific agent")
    parser.add_argument("--task", metavar="DESCRIPTION", help="Task description for agent execution")
    parser.add_argument("--route", metavar="DESCRIPTION", help="Route a task through orchestrator")
    parser.add_argument("--status", action="store_true", help="Show swarm health status")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.list:
        agents_list = [
            {"id": k, "name": v["name"], "emoji": v["emoji"], "role": v["role"],
             "description": v["description"], "tools": v["tools"]}
            for k, v in AGENTS.items()
        ]
        print(json.dumps({"agents": agents_list, "total": len(agents_list), "version": VERSION}, indent=2))
        return

    if args.status:
        print(json.dumps(swarm_status(), indent=2))
        return

    if args.route:
        print(json.dumps(route_task(args.route), indent=2))
        return

    if args.agent:
        task = args.task or "general security task"
        print(json.dumps(run_agent(args.agent, task), indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()

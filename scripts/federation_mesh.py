#!/usr/bin/env python3
"""
Script: federation_mesh.py
Version: V6.0
Claris AI — Defense Network
Author: August + AVARI (Unitium Mode)
Last Updated: 2026-03-10

Decentralized federation mesh manager.
Node registry, Sybil defense, Byzantine fault tolerance,
pattern propagation, and $Initium incentive layer.
"""

import argparse, json, sys, os, re, random, hashlib
from datetime import datetime, timezone
from pathlib import Path

VERSION = "V6.0"
SCRIPT_NAME = "federation_mesh"

DATA_DIR = Path(__file__).parent.parent / "data"
NODE_REGISTRY = DATA_DIR / "federation_nodes.json"
PATTERN_REGISTRY = DATA_DIR / "federation_patterns.json"

# ─── INITIAL MOCK NODE DATA ───────────────────────────────────────────────────

DEFAULT_NODES = [
    {
        "id": "node-alpha-001",
        "alias": "ClarisPrime",
        "ip_hash": hashlib.sha256(b"192.168.1.1").hexdigest()[:16],
        "reputation": 98.5,
        "last_seen": "2026-03-10T18:00:00Z",
        "patterns_contributed": 147,
        "patterns_approved": 142,
        "false_positive_rate": 0.012,
        "initium_stake": 5000,
        "initium_rewards": 1240.5,
        "status": "ACTIVE",
        "joined": "2025-09-01T00:00:00Z",
        "byzantine_checks_passed": 412,
        "byzantine_checks_failed": 0,
    },
    {
        "id": "node-beta-002",
        "alias": "SembleNode",
        "ip_hash": hashlib.sha256(b"10.0.0.55").hexdigest()[:16],
        "reputation": 91.2,
        "last_seen": "2026-03-10T17:55:00Z",
        "patterns_contributed": 89,
        "patterns_approved": 82,
        "false_positive_rate": 0.034,
        "initium_stake": 2500,
        "initium_rewards": 672.0,
        "status": "ACTIVE",
        "joined": "2025-11-15T00:00:00Z",
        "byzantine_checks_passed": 267,
        "byzantine_checks_failed": 1,
    },
    {
        "id": "node-gamma-003",
        "alias": "DashDefender",
        "ip_hash": hashlib.sha256(b"172.16.0.10").hexdigest()[:16],
        "reputation": 87.0,
        "last_seen": "2026-03-10T16:30:00Z",
        "patterns_contributed": 55,
        "patterns_approved": 48,
        "false_positive_rate": 0.058,
        "initium_stake": 1000,
        "initium_rewards": 340.2,
        "status": "ACTIVE",
        "joined": "2026-01-03T00:00:00Z",
        "byzantine_checks_passed": 143,
        "byzantine_checks_failed": 2,
    },
    {
        "id": "node-delta-004",
        "alias": "NewNodeQ",
        "ip_hash": hashlib.sha256(b"203.0.113.42").hexdigest()[:16],
        "reputation": 45.0,
        "last_seen": "2026-03-10T12:00:00Z",
        "patterns_contributed": 3,
        "patterns_approved": 1,
        "false_positive_rate": 0.33,
        "initium_stake": 100,
        "initium_rewards": 12.0,
        "status": "PROBATION",
        "joined": "2026-03-08T00:00:00Z",
        "byzantine_checks_passed": 5,
        "byzantine_checks_failed": 2,
    },
]

DEFAULT_PATTERNS = [
    {
        "id": "pat-001",
        "category": "INJECTION_PROMPT_OVERRIDE",
        "description": "System instruction override attempt",
        "status": "APPROVED",
        "contributed_by": "node-alpha-001",
        "approvals": ["node-alpha-001", "node-beta-002", "node-gamma-003"],
        "rejections": [],
        "created": "2025-10-15T00:00:00Z",
        "propagated_to": 3,
    },
    {
        "id": "pat-002",
        "category": "DAPI_ENDPOINT_ABUSE",
        "description": "DAPI rate-limit evasion via IP rotation",
        "status": "APPROVED",
        "contributed_by": "node-beta-002",
        "approvals": ["node-alpha-001", "node-beta-002", "node-gamma-003"],
        "rejections": [],
        "created": "2026-01-20T00:00:00Z",
        "propagated_to": 3,
    },
    {
        "id": "pat-003",
        "category": "SPOOFING_EVONODE_IDENTITY",
        "description": "Evonode identity spoofing via crafted network messages",
        "status": "PENDING",
        "contributed_by": "node-delta-004",
        "approvals": ["node-beta-002"],
        "rejections": [],
        "created": "2026-03-09T00:00:00Z",
        "propagated_to": 0,
    },
]


def load_nodes() -> list:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if NODE_REGISTRY.exists():
        try:
            return json.loads(NODE_REGISTRY.read_text())
        except:
            pass
    NODE_REGISTRY.write_text(json.dumps(DEFAULT_NODES, indent=2))
    return DEFAULT_NODES


def save_nodes(nodes: list):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    NODE_REGISTRY.write_text(json.dumps(nodes, indent=2))


def load_patterns() -> list:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if PATTERN_REGISTRY.exists():
        try:
            return json.loads(PATTERN_REGISTRY.read_text())
        except:
            pass
    PATTERN_REGISTRY.write_text(json.dumps(DEFAULT_PATTERNS, indent=2))
    return DEFAULT_PATTERNS


def save_patterns(patterns: list):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PATTERN_REGISTRY.write_text(json.dumps(patterns, indent=2))


# ─── SYBIL DEFENSE ────────────────────────────────────────────────────────────

def sybil_score(node_config: dict) -> dict:
    """Score a new node's Sybil risk before trusting its patterns."""
    score = 100  # Start trusted, reduce for risk signals
    flags = []

    stake = node_config.get("initium_stake", 0)
    if stake < 100:
        score -= 40
        flags.append("INSUFFICIENT_STAKE: < 100 $Initium")
    elif stake < 1000:
        score -= 15
        flags.append("LOW_STAKE: < 1000 $Initium — probation period applies")

    # Check for IP hash collision with existing nodes
    ip = node_config.get("ip", "")
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16] if ip else ""
    nodes = load_nodes()
    for n in nodes:
        if n.get("ip_hash") == ip_hash and ip_hash:
            score -= 50
            flags.append(f"IP_COLLISION: Shares IP hash with {n['id']}")

    # New nodes start on probation
    score = max(0, min(100, score))
    trust_level = "TRUSTED" if score >= 80 else "PROBATION" if score >= 40 else "REJECTED"

    return {
        "sybil_score": score,
        "trust_level": trust_level,
        "flags": flags,
        "recommendation": {
            "TRUSTED": "Node may participate in pattern voting immediately.",
            "PROBATION": "Node accepted on probation. First 10 patterns require manual review.",
            "REJECTED": "Node rejected. Insufficient stake or Sybil signals detected.",
        }[trust_level],
        "initium_stake_required": 100,
        "full_trust_stake": 1000,
    }


# ─── BYZANTINE FAULT TOLERANCE ────────────────────────────────────────────────

def verify_pattern(pattern_id: str) -> dict:
    """Check if pattern meets 2/3 BFT threshold."""
    patterns = load_patterns()
    nodes = load_nodes()

    pattern = next((p for p in patterns if p["id"] == pattern_id), None)
    if not pattern:
        return {"error": f"Pattern {pattern_id} not found", "code": 404}

    active_nodes = [n for n in nodes if n["status"] == "ACTIVE"]
    total_active = len(active_nodes)
    bft_threshold = (2 * total_active) / 3  # 2/3 majority required

    approvals = len(pattern["approvals"])
    rejections = len(pattern["rejections"])
    quorum_met = approvals >= bft_threshold

    return {
        "pattern_id": pattern_id,
        "category": pattern["category"],
        "approvals": approvals,
        "rejections": rejections,
        "active_nodes": total_active,
        "bft_threshold": round(bft_threshold, 1),
        "quorum_met": quorum_met,
        "status": "APPROVED" if quorum_met else "PENDING",
        "byzantine_fault_tolerance": f"{total_active // 3} nodes can be Byzantine without affecting consensus",
        "recommendation": "Pattern approved — safe to propagate" if quorum_met else f"Need {max(0, int(bft_threshold) - approvals + 1)} more approvals for quorum",
    }


# ─── PATTERN PROPAGATION ──────────────────────────────────────────────────────

def propagate_pattern(pattern_id: str) -> dict:
    """Propagate an approved pattern to all active nodes."""
    patterns = load_patterns()
    nodes = load_nodes()

    pattern = next((p for p in patterns if p["id"] == pattern_id), None)
    if not pattern:
        return {"error": f"Pattern {pattern_id} not found", "code": 404}

    if pattern["status"] != "APPROVED":
        return {"error": "Pattern is not yet approved — cannot propagate", "code": 400}

    active_nodes = [n["id"] for n in nodes if n["status"] == "ACTIVE"]
    pattern["propagated_to"] = len(active_nodes)

    # Award Initium rewards to contributor
    contributor_node = next((n for n in nodes if n["id"] == pattern["contributed_by"]), None)
    reward = 10.0  # Base reward per approved pattern
    if contributor_node:
        contributor_node["initium_rewards"] = round(contributor_node.get("initium_rewards", 0) + reward, 2)
        contributor_node["patterns_approved"] = contributor_node.get("patterns_approved", 0) + 1
        save_nodes(nodes)

    save_patterns(patterns)

    return {
        "pattern_id": pattern_id,
        "propagated_to_nodes": active_nodes,
        "node_count": len(active_nodes),
        "contributor_rewarded": contributor_node["alias"] if contributor_node else "unknown",
        "initium_reward": reward,
        "provenance": {
            "contributed_by": pattern["contributed_by"],
            "created": pattern["created"],
            "approvals": pattern["approvals"],
        },
        "status": "PROPAGATED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── MESH STATUS ─────────────────────────────────────────────────────────────

def mesh_status() -> dict:
    nodes = load_nodes()
    patterns = load_patterns()

    active = [n for n in nodes if n["status"] == "ACTIVE"]
    probation = [n for n in nodes if n["status"] == "PROBATION"]
    approved_patterns = [p for p in patterns if p["status"] == "APPROVED"]
    pending_patterns = [p for p in patterns if p["status"] == "PENDING"]

    total_stake = sum(n.get("initium_stake", 0) for n in nodes)
    total_rewards = sum(n.get("initium_rewards", 0) for n in nodes)

    return {
        "mesh_status": "HEALTHY" if len(active) >= 3 else "DEGRADED",
        "nodes": {
            "total": len(nodes),
            "active": len(active),
            "probation": len(probation),
            "bft_safe": len(active) >= 3,
            "max_byzantine_nodes": len(active) // 3,
        },
        "patterns": {
            "total": len(patterns),
            "approved": len(approved_patterns),
            "pending": len(pending_patterns),
        },
        "initium_economy": {
            "total_staked": total_stake,
            "total_rewards_distributed": round(total_rewards, 2),
            "active_stakers": len([n for n in nodes if n.get("initium_stake", 0) > 0]),
        },
        "top_nodes": sorted(active, key=lambda n: n["reputation"], reverse=True)[:3],
        "claris_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Claris AI Federation Mesh {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 federation_mesh.py --status
  python3 federation_mesh.py --add-node '{"alias": "MyNode", "ip": "1.2.3.4", "initium_stake": 500}'
  python3 federation_mesh.py --verify pat-003
  python3 federation_mesh.py --propagate pat-001
        """
    )
    parser.add_argument("--status", action="store_true", help="Show mesh network health and stats")
    parser.add_argument("--add-node", metavar="CONFIG_JSON", help="Add a new node (JSON config)")
    parser.add_argument("--propagate", metavar="PATTERN_ID", help="Propagate approved pattern to all nodes")
    parser.add_argument("--verify", metavar="PATTERN_ID", help="Verify pattern meets BFT quorum")
    parser.add_argument("--list-nodes", action="store_true", help="List all registered nodes")
    parser.add_argument("--list-patterns", action="store_true", help="List all patterns")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.status:
        result = mesh_status()
        print(json.dumps(result, indent=2))
        return

    if args.list_nodes:
        nodes = load_nodes()
        print(json.dumps({"nodes": nodes, "total": len(nodes)}, indent=2))
        return

    if args.list_patterns:
        patterns = load_patterns()
        print(json.dumps({"patterns": patterns, "total": len(patterns)}, indent=2))
        return

    if args.add_node:
        try:
            config = json.loads(args.add_node)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"Invalid JSON: {e}", "code": 400}))
            sys.exit(2)
        sybil = sybil_score(config)
        if sybil["trust_level"] != "REJECTED":
            nodes = load_nodes()
            new_node = {
                "id": f"node-{hashlib.sha256(json.dumps(config).encode()).hexdigest()[:8]}",
                "alias": config.get("alias", "UnknownNode"),
                "ip_hash": hashlib.sha256(config.get("ip", "").encode()).hexdigest()[:16],
                "reputation": sybil["sybil_score"],
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "patterns_contributed": 0,
                "patterns_approved": 0,
                "false_positive_rate": 0.0,
                "initium_stake": config.get("initium_stake", 0),
                "initium_rewards": 0.0,
                "status": sybil["trust_level"].upper() if sybil["trust_level"] != "TRUSTED" else "ACTIVE",
                "joined": datetime.now(timezone.utc).isoformat(),
                "byzantine_checks_passed": 0,
                "byzantine_checks_failed": 0,
            }
            nodes.append(new_node)
            save_nodes(nodes)
            result = {"registered": True, "node": new_node, "sybil_assessment": sybil}
        else:
            result = {"registered": False, "reason": "REJECTED by Sybil defense", "sybil_assessment": sybil}
        print(json.dumps(result, indent=2))
        return

    if args.verify:
        result = verify_pattern(args.verify)
        print(json.dumps(result, indent=2))
        return

    if args.propagate:
        result = propagate_pattern(args.propagate)
        print(json.dumps(result, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()

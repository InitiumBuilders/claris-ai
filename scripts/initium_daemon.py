#!/usr/bin/env python3
"""
Script: initium_daemon.py
Version: V10.0 (Forge)
Claris AI — Defense Network
Author: August + AVARI (Unitium Mode)
Last Updated: 2026-03-10

$Initium DAO stub — tracks node contributions, stake amounts,
reward calculations, federation participation scores.
Mock DAO governance: proposals, votes, threshold logic.
"""

import argparse, json, sys, os, random
from datetime import datetime, timezone
from pathlib import Path

VERSION = "V10.0"
SCRIPT_NAME = "initium_daemon"

DATA_DIR = Path(__file__).parent.parent / "data"
DAO_STATE_FILE = DATA_DIR / "initium_dao.json"

# ─── MOCK DAO STATE ──────────────────────────────────────────────────────────

DEFAULT_DAO_STATE = {
    "token": {
        "symbol": "$INITIUM",
        "name": "Initium DAO Token",
        "total_supply": 1_000_000,
        "circulating_supply": 450_000,
        "staked_supply": 125_000,
        "price_usd_mock": 0.042,
        "network": "Dash Platform (DPNS: initium.dash)",
    },
    "treasury": {
        "balance_initium": 250_000,
        "balance_dash": 450.5,
        "monthly_inflow": 12_500,
        "monthly_outflow": 8_750,
    },
    "nodes": {
        "node-alpha-001": {
            "alias": "ClarisPrime",
            "stake": 5000,
            "rewards_earned": 1240.5,
            "patterns_contributed": 147,
            "participation_score": 98.5,
            "federation_uptime": 99.9,
            "last_contribution": "2026-03-10T18:00:00Z",
        },
        "node-beta-002": {
            "alias": "SembleNode",
            "stake": 2500,
            "rewards_earned": 672.0,
            "patterns_contributed": 89,
            "participation_score": 91.2,
            "federation_uptime": 98.7,
            "last_contribution": "2026-03-10T17:55:00Z",
        },
        "node-gamma-003": {
            "alias": "DashDefender",
            "stake": 1000,
            "rewards_earned": 340.2,
            "patterns_contributed": 55,
            "participation_score": 87.0,
            "federation_uptime": 97.2,
            "last_contribution": "2026-03-10T16:30:00Z",
        },
        "node-delta-004": {
            "alias": "NewNodeQ",
            "stake": 100,
            "rewards_earned": 12.0,
            "patterns_contributed": 3,
            "participation_score": 45.0,
            "federation_uptime": 82.0,
            "last_contribution": "2026-03-10T12:00:00Z",
        },
    },
    "proposals": [
        {
            "id": "PROP-001",
            "title": "Expand red team suite to 100 payloads",
            "description": "Double the adversarial test suite coverage from 50 to 100 payloads across 8 categories.",
            "proposer": "node-alpha-001",
            "status": "ACTIVE",
            "yes_votes": 7500,
            "no_votes": 500,
            "abstain_votes": 1000,
            "threshold": 0.60,
            "quorum_required": 5000,
            "created": "2026-03-08T00:00:00Z",
            "deadline": "2026-03-15T00:00:00Z",
            "budget_initium": 5000,
        },
        {
            "id": "PROP-002",
            "title": "Add DPNS integration for node identity verification",
            "description": "Require all federation nodes to have a verified DPNS name on Dash Platform.",
            "proposer": "node-beta-002",
            "status": "ACTIVE",
            "yes_votes": 4200,
            "no_votes": 3100,
            "abstain_votes": 700,
            "threshold": 0.60,
            "quorum_required": 5000,
            "created": "2026-03-09T00:00:00Z",
            "deadline": "2026-03-16T00:00:00Z",
            "budget_initium": 0,
        },
        {
            "id": "PROP-003",
            "title": "Increase minimum stake to 500 $INITIUM",
            "description": "Raise the minimum stake for federation nodes from 100 to 500 $INITIUM to improve Sybil resistance.",
            "proposer": "node-alpha-001",
            "status": "PASSED",
            "yes_votes": 9200,
            "no_votes": 800,
            "abstain_votes": 200,
            "threshold": 0.60,
            "quorum_required": 5000,
            "created": "2026-03-01T00:00:00Z",
            "deadline": "2026-03-08T00:00:00Z",
            "budget_initium": 0,
        },
    ],
    "reward_config": {
        "base_reward_per_pattern": 10.0,
        "uptime_bonus_multiplier": 1.5,
        "quality_bonus_per_accuracy_point": 0.5,
        "minimum_stake_for_rewards": 100,
        "reward_epoch_days": 30,
    },
    "last_updated": "2026-03-10T18:00:00Z",
}


def load_dao_state() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if DAO_STATE_FILE.exists():
        try:
            return json.loads(DAO_STATE_FILE.read_text())
        except:
            pass
    DAO_STATE_FILE.write_text(json.dumps(DEFAULT_DAO_STATE, indent=2))
    return DEFAULT_DAO_STATE


def save_dao_state(state: dict):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DAO_STATE_FILE.write_text(json.dumps(state, indent=2))


# ─── REWARD CALCULATOR ────────────────────────────────────────────────────────

def calculate_rewards(node_id: str = None) -> dict:
    """Calculate current reward estimates for nodes."""
    state = load_dao_state()
    config = state["reward_config"]
    nodes = state["nodes"]

    results = {}
    for nid, node in nodes.items():
        if node_id and nid != node_id:
            continue

        stake = node["stake"]
        if stake < config["minimum_stake_for_rewards"]:
            results[nid] = {"alias": node["alias"], "eligible": False, "reason": "Insufficient stake"}
            continue

        base = node["patterns_contributed"] * config["base_reward_per_pattern"]
        uptime_bonus = base * (config["uptime_bonus_multiplier"] - 1) * (node["federation_uptime"] / 100)
        participation_bonus = node["participation_score"] * config["quality_bonus_per_accuracy_point"]
        epoch_reward = round(base + uptime_bonus + participation_bonus, 2)

        results[nid] = {
            "alias": node["alias"],
            "eligible": True,
            "stake": stake,
            "patterns_contributed": node["patterns_contributed"],
            "participation_score": node["participation_score"],
            "epoch_reward_estimate": epoch_reward,
            "total_earned_to_date": node["rewards_earned"],
            "breakdown": {
                "base_reward": round(base, 2),
                "uptime_bonus": round(uptime_bonus, 2),
                "participation_bonus": round(participation_bonus, 2),
            },
        }

    return {
        "reward_calculations": results,
        "reward_config": config,
        "epoch_days": config["reward_epoch_days"],
        "token": "$INITIUM",
        "claris_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def add_stake(amount: float) -> dict:
    """Simulate staking $INITIUM."""
    if amount <= 0:
        return {"error": "Stake amount must be positive", "code": 400}

    state = load_dao_state()
    state["token"]["staked_supply"] += amount
    save_dao_state(state)

    return {
        "action": "STAKE",
        "amount": amount,
        "token": "$INITIUM",
        "new_staked_supply": state["token"]["staked_supply"],
        "note": "Simulated stake — $INITIUM is a mock token for Claris federation incentives",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def vote_on_proposal(proposal_id: str, vote: str, voting_power: int = 1000) -> dict:
    """Cast a vote on a DAO proposal."""
    state = load_dao_state()
    proposals = state["proposals"]

    proposal = next((p for p in proposals if p["id"] == proposal_id), None)
    if not proposal:
        return {"error": f"Proposal {proposal_id} not found", "available": [p["id"] for p in proposals], "code": 404}

    if proposal["status"] != "ACTIVE":
        return {"error": f"Proposal {proposal_id} is {proposal['status']} — not accepting votes", "code": 400}

    vote = vote.upper()
    if vote not in ("YES", "NO", "ABSTAIN"):
        return {"error": "Vote must be YES, NO, or ABSTAIN", "code": 400}

    if vote == "YES":
        proposal["yes_votes"] += voting_power
    elif vote == "NO":
        proposal["no_votes"] += voting_power
    else:
        proposal["abstain_votes"] += voting_power

    total_votes = proposal["yes_votes"] + proposal["no_votes"]
    yes_pct = (proposal["yes_votes"] / total_votes * 100) if total_votes > 0 else 0
    quorum_met = total_votes >= proposal["quorum_required"]
    threshold_met = yes_pct / 100 >= proposal["threshold"]

    if quorum_met and threshold_met:
        proposal["status"] = "PASSED"
    elif quorum_met and (proposal["no_votes"] / total_votes) > (1 - proposal["threshold"]):
        proposal["status"] = "FAILED"

    save_dao_state(state)

    return {
        "voted": True,
        "proposal_id": proposal_id,
        "title": proposal["title"],
        "vote": vote,
        "voting_power_used": voting_power,
        "current_tally": {
            "yes": proposal["yes_votes"],
            "no": proposal["no_votes"],
            "abstain": proposal["abstain_votes"],
            "yes_pct": round(yes_pct, 1),
        },
        "quorum_met": quorum_met,
        "threshold_met": threshold_met,
        "proposal_status": proposal["status"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def dao_status() -> dict:
    """Return full DAO status."""
    state = load_dao_state()
    active_proposals = [p for p in state["proposals"] if p["status"] == "ACTIVE"]

    return {
        "dao": "Initium DAO",
        "token": state["token"],
        "treasury": state["treasury"],
        "nodes": {
            "total": len(state["nodes"]),
            "total_staked": sum(n["stake"] for n in state["nodes"].values()),
            "top_contributors": sorted(
                [{"alias": n["alias"], "patterns": n["patterns_contributed"], "stake": n["stake"]}
                 for n in state["nodes"].values()],
                key=lambda x: x["patterns"], reverse=True
            )[:3],
        },
        "governance": {
            "active_proposals": len(active_proposals),
            "proposals": active_proposals,
            "threshold": "60% yes votes required",
            "quorum": "5,000 $INITIUM voting power required",
        },
        "claris_version": VERSION,
        "data_note": "SIMULATED — $Initium DAO stub for Claris AI Defense Network",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Claris AI $Initium DAO Daemon {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 initium_daemon.py --status
  python3 initium_daemon.py --stake 500
  python3 initium_daemon.py --rewards
  python3 initium_daemon.py --proposals
  python3 initium_daemon.py --vote PROP-001 --direction YES
        """
    )
    parser.add_argument("--status", action="store_true", help="Show full DAO status")
    parser.add_argument("--stake", type=float, metavar="AMOUNT", help="Stake $INITIUM tokens")
    parser.add_argument("--rewards", action="store_true", help="Calculate reward estimates for all nodes")
    parser.add_argument("--node", metavar="NODE_ID", help="Filter rewards to specific node")
    parser.add_argument("--proposals", action="store_true", help="List active governance proposals")
    parser.add_argument("--vote", metavar="PROPOSAL_ID", help="Vote on a proposal (use with --direction)")
    parser.add_argument("--direction", choices=["YES", "NO", "ABSTAIN"], help="Vote direction")
    parser.add_argument("--power", type=int, default=1000, metavar="VP", help="Voting power to use (default: 1000)")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.status:
        print(json.dumps(dao_status(), indent=2))
        return

    if args.stake is not None:
        print(json.dumps(add_stake(args.stake), indent=2))
        return

    if args.rewards:
        print(json.dumps(calculate_rewards(node_id=args.node), indent=2))
        return

    if args.proposals:
        state = load_dao_state()
        print(json.dumps({"proposals": state["proposals"], "count": len(state["proposals"])}, indent=2))
        return

    if args.vote:
        if not args.direction:
            print(json.dumps({"error": "--direction required when using --vote (YES/NO/ABSTAIN)", "code": 400}))
            sys.exit(2)
        print(json.dumps(vote_on_proposal(args.vote, args.direction, args.power), indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()

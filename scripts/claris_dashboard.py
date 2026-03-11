#!/usr/bin/env python3
"""
claris_dashboard.py — Claris AI V4.0 ANSI Terminal Dashboard
Beautiful live-updating status display. No external deps.
"""

import json
import os
import sys
import time
import argparse
import subprocess
from datetime import datetime, timezone, timedelta

# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET       = "\033[0m"
BOLD        = "\033[1m"
DIM         = "\033[2m"
BG_DARK     = "\033[40m"

C_HEADER    = "\033[38;5;48m"    # bright green ~#00ff88
C_BLOCK     = "\033[91m"         # bright red
C_FLAG      = "\033[93m"         # yellow
C_WARN      = "\033[33m"         # dim yellow
C_CLEAN     = "\033[92m"         # green
C_INFO      = "\033[96m"         # cyan
C_MUTED     = "\033[90m"         # dark grey
C_WHITE     = "\033[97m"         # bright white
C_BORDER    = "\033[38;5;240m"   # dark grey border

VERDICT_COLOR = {
    "BLOCK": C_BLOCK,
    "FLAG":  C_FLAG,
    "WARN":  C_WARN,
    "CLEAN": C_CLEAN,
}

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Helpers ───────────────────────────────────────────────────────────────────
def _w(width: int) -> str:
    """Terminal width guard."""
    return min(width, 120)

def colorize(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"

def bar_chart(value: int, max_val: int, width: int = 20, color: str = C_CLEAN) -> str:
    if max_val == 0:
        filled = 0
    else:
        filled = int((value / max_val) * width)
    filled = min(filled, width)
    empty  = width - filled
    return f"{color}{'█' * filled}{C_MUTED}{'░' * empty}{RESET}"

def hline(width: int = 68, char: str = "─") -> str:
    return f"{C_BORDER}{char * width}{RESET}"

def header_box(title: str, width: int = 68) -> str:
    pad   = (width - len(title) - 2) // 2
    left  = "─" * pad
    right = "─" * (width - len(title) - 2 - pad)
    return f"{C_BORDER}┌{left}{RESET}{C_HEADER}{BOLD} {title} {RESET}{C_BORDER}{right}┐{RESET}"

def section_line(width: int = 68) -> str:
    return f"{C_BORDER}{'─' * width}{RESET}"


# ── Data loader ───────────────────────────────────────────────────────────────
def _run_script(args: list) -> dict:
    try:
        result = subprocess.run(
            [sys.executable] + args,
            capture_output=True, text=True, timeout=8
        )
        stdout = result.stdout.strip()
        for i, ch in enumerate(stdout):
            if ch in ("{", "["):
                try:
                    return json.loads(stdout[i:])
                except json.JSONDecodeError:
                    break
    except Exception:
        pass
    return {}


def load_cortex_data() -> dict:
    return _run_script([os.path.join(SCRIPTS_DIR, "cortex_engine.py"), "--status", "--json"])


def load_trending() -> list:
    data = _run_script([os.path.join(SCRIPTS_DIR, "cortex_engine.py"), "--trending", "--json"])
    return data.get("trending", [])


def load_history(n: int = 10) -> list:
    data = _run_script([os.path.join(SCRIPTS_DIR, "cortex_engine.py"), "--history", str(n), "--json"])
    return data.get("history", [])


def load_cortex_raw() -> dict:
    """Load raw cortex state JSON directly for performance."""
    state_path = os.path.join(SCRIPTS_DIR, "..", "data", "cortex_state.json")
    state_path = os.path.normpath(state_path)
    if not os.path.exists(state_path):
        return {}
    try:
        with open(state_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def check_script_health() -> dict:
    """Check which scripts exist and are parseable."""
    scripts = {
        "injection_guard": "injection_guard.py",
        "sc_scanner":      "sc_scanner.py",
        "threat_monitor":  "threat_monitor.py",
        "api":             "claris_api.py",
    }
    health = {}
    for name, fname in scripts.items():
        path   = os.path.join(SCRIPTS_DIR, fname)
        exists = os.path.exists(path)
        if exists:
            try:
                import ast
                with open(path) as f:
                    ast.parse(f.read())
                health[name] = "OK"
            except SyntaxError:
                health[name] = "SYNTAX_ERROR"
        else:
            health[name] = "MISSING"
    return health


def get_cst_time() -> str:
    """Return current time in CST (UTC-6)."""
    utc_now = datetime.now(timezone.utc)
    cst     = utc_now - timedelta(hours=6)
    return cst.strftime("%Y-%m-%d %H:%M CST")


def uptime_str(state: dict) -> str:
    """Compute pseudo-uptime from last_updated."""
    last = state.get("last_updated", "")
    if not last:
        return "unknown"
    try:
        ts   = datetime.fromisoformat(last)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        diff = datetime.now(timezone.utc) - ts
        h, rem = divmod(int(diff.total_seconds()), 3600)
        m      = rem // 60
        return f"{h}h {m}m"
    except Exception:
        return "unknown"


# ── Dashboard renderer ────────────────────────────────────────────────────────
def render_dashboard(compact: bool = False) -> str:
    W       = 68
    state   = load_cortex_raw()
    health  = check_script_health()
    now_str = get_cst_time()
    up_str  = uptime_str(state)

    today   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_s = state.get("daily_stats", {}).get(today, {"BLOCK":0,"FLAG":0,"WARN":0,"CLEAN":0})
    b_count = today_s.get("BLOCK",  0)
    f_count = today_s.get("FLAG",   0)
    w_count = today_s.get("WARN",   0)
    c_count = today_s.get("CLEAN",  0)
    max_val = max(b_count, f_count, w_count, c_count, 1)

    history       = state.get("threat_history", [])[-10:]
    pattern_stats = state.get("pattern_stats", {})
    evo_log       = state.get("evolution_log",  [])[-5:]
    total_scans   = state.get("total_scans",    0)

    lines = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines.append(f"{C_BORDER}╔{'═'*W}╗{RESET}")
    title_left  = f"CLARIS V4.0  {C_MUTED}│{C_HEADER}  CORTEX  {C_MUTED}│{C_HEADER}  ↑ {up_str}"
    title_right = f"{C_INFO}{now_str}"
    inner       = f"  {C_HEADER}{BOLD}{title_left}{RESET}  {title_right}  "
    # Pad to width
    visible_len = len(f"  CLARIS V4.0  │  CORTEX  │  ↑ {up_str}  {now_str}  ")
    pad = max(0, W - visible_len)
    lines.append(f"{C_BORDER}║{RESET}{inner}{' ' * pad}{C_BORDER}║{RESET}")
    lines.append(f"{C_BORDER}╠{'═'*W}╣{RESET}")

    # ── Section 1: THREAT OVERVIEW ────────────────────────────────────────────
    lines.append(f"{C_BORDER}║{RESET} {C_HEADER}{BOLD}THREAT OVERVIEW{RESET}  {C_MUTED}(today · {today}){RESET}  {C_MUTED}total scans: {total_scans:,}{RESET}")
    lines.append(f"{C_BORDER}║{RESET} {hline(W-2)}")
    for label, count, color in [
        ("BLOCK", b_count, C_BLOCK),
        ("FLAG",  f_count, C_FLAG),
        ("WARN",  w_count, C_WARN),
        ("CLEAN", c_count, C_CLEAN),
    ]:
        b     = bar_chart(count, max_val, width=28, color=color)
        row   = f"  {color}{BOLD}{label:<6}{RESET}  {b}  {color}{count:>4}{RESET}"
        lines.append(f"{C_BORDER}║{RESET}{row}")
    lines.append(f"{C_BORDER}║{RESET}")

    if not compact:
        # ── Section 2: RECENT THREATS ─────────────────────────────────────────
        lines.append(f"{C_BORDER}║{RESET} {C_HEADER}{BOLD}RECENT THREATS{RESET}  {C_MUTED}(last 10){RESET}")
        lines.append(f"{C_BORDER}║{RESET} {hline(W-2)}")
        if history:
            for entry in reversed(history):
                ts_raw  = entry.get("ts", "")[:19].replace("T", " ")
                verdict = entry.get("verdict", "?")
                score   = entry.get("score",   0)
                cats    = ", ".join(entry.get("categories", []))[:35] or "—"
                vc      = VERDICT_COLOR.get(verdict, C_MUTED)
                row     = f"  {C_MUTED}{ts_raw}{RESET}  {vc}{verdict:<6}{RESET}  {C_MUTED}{score:>4.0f}{RESET}  {C_INFO}{cats}{RESET}"
                lines.append(f"{C_BORDER}║{RESET}{row}")
        else:
            lines.append(f"{C_BORDER}║{RESET}  {C_MUTED}No threat history yet.{RESET}")
        lines.append(f"{C_BORDER}║{RESET}")

        # ── Section 3: CORTEX STATUS ──────────────────────────────────────────
        lines.append(f"{C_BORDER}║{RESET} {C_HEADER}{BOLD}CORTEX STATUS{RESET}  {C_MUTED}(top patterns · weight evolution){RESET}")
        lines.append(f"{C_BORDER}║{RESET} {hline(W-2)}")
        # Top 5 by hits
        sorted_pats = sorted(pattern_stats.items(), key=lambda x: -x[1].get("hits", 0))[:5]
        if sorted_pats:
            lines.append(f"{C_BORDER}║{RESET}  {C_MUTED}{'Pattern':<32} {'Hits':>5}  {'Weight':>7}  {'Trend'}{RESET}")
            for cat, ps in sorted_pats:
                hits    = ps.get("hits", 0)
                weight  = ps.get("weight", 1.0)
                trending= "📈" if ps.get("trending") else "  "
                wcolor  = C_CLEAN if weight >= 1.0 else C_WARN
                row     = f"  {C_INFO}{cat:<32}{RESET} {hits:>5}  {wcolor}{weight:>7.3f}{RESET}  {trending}"
                lines.append(f"{C_BORDER}║{RESET}{row}")
        else:
            lines.append(f"{C_BORDER}║{RESET}  {C_MUTED}No pattern data yet.{RESET}")

        if evo_log:
            lines.append(f"{C_BORDER}║{RESET}  {C_MUTED}Recent evolutions:{RESET}")
            for ev in evo_log:
                delta   = ev["new_weight"] - ev["old_weight"]
                arrow   = "↑" if delta > 0 else "↓"
                dc      = C_CLEAN if delta > 0 else C_WARN
                row     = f"  {dc}{arrow}{RESET}  {C_MUTED}{ev['category']:<32}{RESET} {ev['old_weight']:.3f} → {dc}{ev['new_weight']:.3f}{RESET}"
                lines.append(f"{C_BORDER}║{RESET}{row}")
        lines.append(f"{C_BORDER}║{RESET}")

    # ── Section 4: SYSTEM HEALTH ──────────────────────────────────────────────
    lines.append(f"{C_BORDER}║{RESET} {C_HEADER}{BOLD}SYSTEM HEALTH{RESET}")
    lines.append(f"{C_BORDER}║{RESET} {hline(W-2)}")
    for script, status in health.items():
        if status == "OK":
            indicator = f"{C_CLEAN}● OK{RESET}"
        elif status == "MISSING":
            indicator = f"{C_WARN}○ MISSING{RESET}"
        else:
            indicator = f"{C_BLOCK}✗ {status}{RESET}"
        row = f"  {C_WHITE}{script:<20}{RESET}  {indicator}"
        lines.append(f"{C_BORDER}║{RESET}{row}")
    lines.append(f"{C_BORDER}║{RESET}")

    # ── Section 5: COVERAGE MATRIX ────────────────────────────────────────────
    lines.append(f"{C_BORDER}║{RESET} {C_HEADER}{BOLD}COVERAGE MATRIX{RESET}  {C_MUTED}(layers 1–6){RESET}")
    lines.append(f"{C_BORDER}║{RESET} {hline(W-2)}")

    layer_names = {
        1: "Override / Instruction Injection",
        2: "Role Confusion / Jailbreaks",
        3: "Web3 / Wallet Threats",
        4: "Encoding / Obfuscation",
        5: "Social Engineering",
        6: "Smart Contract",
    }
    layer_prefixes = {
        1: ["OVERRIDE"],
        2: ["ROLE_", "JAILBREAK"],
        3: ["WEB3_"],
        4: ["ENCODE_"],
        5: ["SOCIAL_"],
        6: ["SC_"],
    }

    for layer_num in range(1, 7):
        prefixes    = layer_prefixes[layer_num]
        layer_pats  = {k: v for k, v in pattern_stats.items()
                       if any(k.startswith(p) for p in prefixes)}
        total_pats  = len(layer_pats)
        total_hits  = sum(v.get("hits", 0) for v in layer_pats.values())
        ever_fired  = sum(1 for v in layer_pats.values() if v.get("hits", 0) > 0)
        hit_rate    = round((ever_fired / max(total_pats, 1)) * 100)
        bar_color   = C_CLEAN if hit_rate >= 70 else (C_WARN if hit_rate >= 40 else C_BLOCK)
        mini_bar    = bar_chart(hit_rate, 100, width=12, color=bar_color)
        lname       = layer_names[layer_num][:35]
        row = f"  {C_MUTED}L{layer_num}{RESET} {C_INFO}{lname:<36}{RESET} {mini_bar} {bar_color}{hit_rate:>3}%{RESET}  {C_MUTED}{total_hits} hits{RESET}"
        lines.append(f"{C_BORDER}║{RESET}{row}")

    lines.append(f"{C_BORDER}║{RESET}")

    # ── Footer ────────────────────────────────────────────────────────────────
    footer = "~Claris · Semper Fortis · V4.0 Cortex"
    fp     = (W - len(footer)) // 2
    lines.append(f"{C_BORDER}╠{'═'*W}╣{RESET}")
    lines.append(f"{C_BORDER}║{RESET}{' ' * fp}{C_HEADER}{BOLD}{footer}{RESET}{' ' * (W - fp - len(footer))}{C_BORDER}║{RESET}")
    lines.append(f"{C_BORDER}╚{'═'*W}╝{RESET}")

    return "\n".join(lines)


# ── Compact renderer ──────────────────────────────────────────────────────────
def render_compact() -> str:
    state   = load_cortex_raw()
    health  = check_script_health()
    today   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_s = state.get("daily_stats", {}).get(today, {"BLOCK":0,"FLAG":0,"WARN":0,"CLEAN":0})

    b = today_s.get("BLOCK", 0)
    f = today_s.get("FLAG",  0)
    w = today_s.get("WARN",  0)
    c = today_s.get("CLEAN", 0)

    health_icons = " ".join(
        f"{C_CLEAN}●{RESET}{name[:4]}" if st == "OK" else f"{C_WARN}○{RESET}{name[:4]}"
        for name, st in health.items()
    )

    lines = [
        f"{C_HEADER}{BOLD}CLARIS V4.0{RESET}  {C_MUTED}{get_cst_time()}{RESET}",
        f"  {C_BLOCK}BLOCK{RESET}:{b}  {C_FLAG}FLAG{RESET}:{f}  {C_WARN}WARN{RESET}:{w}  {C_CLEAN}CLEAN{RESET}:{c}",
        f"  {C_MUTED}Health:{RESET} {health_icons}",
        f"  {C_MUTED}~Claris · Semper Fortis · V4.0{RESET}",
    ]
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Claris AI V4.0 ANSI Dashboard")
    parser.add_argument("--watch",   action="store_true", help="Refresh every 30s")
    parser.add_argument("--compact", action="store_true", help="Single-screen compact view")
    parser.add_argument("--interval",type=int, default=30, help="Watch interval in seconds")
    args = parser.parse_args()

    if args.compact:
        print(render_compact())
        return

    if args.watch:
        try:
            while True:
                os.system("clear" if os.name != "nt" else "cls")
                print(render_dashboard(compact=False))
                print(f"\n  {C_MUTED}Auto-refreshing every {args.interval}s — Ctrl+C to exit{RESET}")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n{C_MUTED}[Claris Dashboard] Stopped.{RESET}")
        return

    # One-shot
    print(render_dashboard(compact=False))


if __name__ == "__main__":
    main()

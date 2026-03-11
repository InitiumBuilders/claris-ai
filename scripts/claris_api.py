#!/usr/bin/env python3
"""
claris_api.py — Claris AI V4.0 REST API Server
Lightweight stdlib-only HTTP API wrapping all Claris scripts.
Port 7433 | Auth: X-Claris-Key header
"""

import json
import os
import sys
import time
import argparse
import subprocess
import threading
import logging
from datetime import datetime, timezone
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from typing import Optional

# ── Local module imports ──────────────────────────────────────────────────────
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
if _SELF_DIR not in sys.path:
    sys.path.insert(0, _SELF_DIR)
try:
    import temporal_analyzer as _temporal_analyzer
    _TEMPORAL_AVAILABLE = True
except ImportError:
    _temporal_analyzer = None
    _TEMPORAL_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────────────
VERSION       = "5.0"
DEFAULT_PORT  = 7433
DEFAULT_KEY   = "claris-v4-api"
DEFAULT_HOST  = "0.0.0.0"
TIMEOUT_S     = 10
RATE_LIMIT    = 60  # requests per minute per IP

SCRIPTS_DIR   = os.path.dirname(os.path.abspath(__file__))
MEMORY_DIR    = os.path.join(os.path.dirname(SCRIPTS_DIR), "..", "..", "memory")
MEMORY_DIR    = os.path.normpath(MEMORY_DIR)
LOG_FILE      = os.path.join(MEMORY_DIR, "api_access.log")

# Global state
_start_time   = time.time()
_api_key      = DEFAULT_KEY
_rate_buckets: dict = defaultdict(list)   # ip → [timestamps]
_rate_lock    = threading.Lock()

# ── Logging ───────────────────────────────────────────────────────────────────
os.makedirs(MEMORY_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("claris_api")


# ── Rate limiter ──────────────────────────────────────────────────────────────
def _check_rate(ip: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets[ip]
        # Keep only timestamps within last 60s
        _rate_buckets[ip] = [t for t in bucket if now - t < 60]
        if len(_rate_buckets[ip]) >= RATE_LIMIT:
            return False
        _rate_buckets[ip].append(now)
    return True


# ── Script runner ─────────────────────────────────────────────────────────────
def _run_script(args: list, stdin_data: str = None) -> dict:
    """Run a Claris script subprocess and return parsed JSON output."""
    try:
        result = subprocess.run(
            [sys.executable] + args,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Try to extract JSON from stdout
        if stdout:
            # Find the first { or [ in output
            for i, ch in enumerate(stdout):
                if ch in ("{", "["):
                    try:
                        return json.loads(stdout[i:])
                    except json.JSONDecodeError:
                        pass
        return {"raw": stdout, "stderr": stderr, "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        raise TimeoutError("Script timed out")
    except Exception as e:
        raise RuntimeError(str(e))


def _script(name: str) -> str:
    return os.path.join(SCRIPTS_DIR, name)


# ── Handler ───────────────────────────────────────────────────────────────────
class ClarisHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Suppress default HTTP log — we do our own."""
        pass

    def _get_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        return forwarded.split(",")[0].strip() if forwarded else self.client_address[0]

    def _auth(self) -> bool:
        return self.headers.get("X-Claris-Key", "") == _api_key

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Claris-Key")

    def _json_response(self, code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _log_request(self, method: str, path: str, status: int, ip: str):
        logger.info(f'{ip} "{method} {path}" {status}')

    # ── Preflight ──────────────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    # ── GET ────────────────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        ip     = self._get_ip()

        if not _check_rate(ip):
            self._json_response(429, {"error": "rate_limit_exceeded", "limit": f"{RATE_LIMIT}/min"})
            self._log_request("GET", path, 429, ip)
            return

        if not self._auth():
            self._json_response(401, {"error": "unauthorized", "hint": "Set X-Claris-Key header"})
            self._log_request("GET", path, 401, ip)
            return

        if path == "/v1/health":
            self._handle_health(ip)
        elif path == "/v1/cortex":
            self._handle_cortex(ip)
        elif path == "/v1/stats":
            self._handle_stats(ip)
        elif path.startswith("/v1/session/") and path.endswith("/temporal"):
            # Extract session_id from /v1/session/{session_id}/temporal
            session_id = path[len("/v1/session/"):-len("/temporal")]
            if session_id:
                self._handle_session_temporal(session_id, ip)
            else:
                self._json_response(400, {"error": "missing session_id in path"})
                self._log_request("GET", path, 400, ip)
        else:
            self._json_response(404, {"error": "not_found", "path": path})
            self._log_request("GET", path, 404, ip)

    # ── POST ───────────────────────────────────────────────────────────────────
    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        ip     = self._get_ip()

        if not _check_rate(ip):
            self._json_response(429, {"error": "rate_limit_exceeded", "limit": f"{RATE_LIMIT}/min"})
            self._log_request("POST", path, 429, ip)
            return

        if not self._auth():
            self._json_response(401, {"error": "unauthorized"})
            self._log_request("POST", path, 401, ip)
            return

        body = self._read_body()

        if path == "/v1/scan":
            self._handle_scan(body, ip)
        elif path == "/v1/audit":
            self._handle_audit(body, ip)
        elif path == "/v1/monitor":
            self._handle_monitor(body, ip)
        elif path == "/v1/feedback":
            self._handle_feedback(body, ip)
        else:
            self._json_response(404, {"error": "not_found", "path": path})
            self._log_request("POST", path, 404, ip)

    # ── Endpoint handlers ─────────────────────────────────────────────────────
    def _handle_health(self, ip: str):
        from datetime import date
        uptime = int(time.time() - _start_time)
        # Get today's scan count from cortex
        scans_today = 0
        try:
            result = _run_script([_script("cortex_engine.py"), "--status", "--json"])
            daily = result.get("daily_volume_7d", [])
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            for d in daily:
                if d.get("date") == today_str:
                    scans_today = d.get("BLOCK",0)+d.get("FLAG",0)+d.get("WARN",0)+d.get("CLEAN",0)
        except Exception:
            pass

        data = {
            "status": "ok",
            "version": VERSION,
            "uptime_s": uptime,
            "scans_today": scans_today,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._json_response(200, data)
        self._log_request("GET", "/v1/health", 200, ip)

    def _handle_cortex(self, ip: str):
        try:
            result = _run_script([_script("cortex_engine.py"), "--status", "--json"])
            self._json_response(200, result)
            self._log_request("GET", "/v1/cortex", 200, ip)
        except TimeoutError:
            self._json_response(504, {"error": "cortex_timeout"})
            self._log_request("GET", "/v1/cortex", 504, ip)
        except Exception as e:
            self._json_response(500, {"error": str(e)})
            self._log_request("GET", "/v1/cortex", 500, ip)

    def _handle_stats(self, ip: str):
        try:
            cortex_data = _run_script([_script("cortex_engine.py"), "--status", "--json"])
            trending    = _run_script([_script("cortex_engine.py"), "--trending", "--json"])
            data = {
                "daily_volume_7d":   cortex_data.get("daily_volume_7d", []),
                "verdict_totals":    cortex_data.get("threat_distribution_by_verdict", {}),
                "trending_threats":  trending.get("trending", []),
                "total_scans":       cortex_data.get("total_scans", 0),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._json_response(200, data)
            self._log_request("GET", "/v1/stats", 200, ip)
        except TimeoutError:
            self._json_response(504, {"error": "stats_timeout"})
            self._log_request("GET", "/v1/stats", 504, ip)
        except Exception as e:
            self._json_response(500, {"error": str(e)})
            self._log_request("GET", "/v1/stats", 500, ip)

    def _handle_scan(self, body: dict, ip: str):
        text       = body.get("text", "")
        source     = body.get("source", f"api:{ip}")
        use_ml     = str(body.get("ml", "false")).lower() == "true"
        session_id: Optional[str] = body.get("session_id", None) or None

        if not text:
            self._json_response(400, {"error": "missing field: text"})
            self._log_request("POST", "/v1/scan", 400, ip)
            return

        try:
            if use_ml:
                # Use dual-layer ML enhanced scan (pattern + ML)
                ml_script = _script("ml_enhanced_scan.py")
                result = subprocess.run(
                    [sys.executable, ml_script, "--text", text, "--json"],
                    capture_output=True, text=True, timeout=45
                )
                stdout = result.stdout.strip()
                if stdout:
                    for i, ch in enumerate(stdout):
                        if ch in ("{", "["):
                            try:
                                data = json.loads(stdout[i:])
                                # Enrich with temporal analysis if session_id provided
                                data = self._enrich_with_temporal(data, session_id, text)
                                self._json_response(200, data)
                                self._log_request("POST", "/v1/scan", 200, ip)
                                return
                            except json.JSONDecodeError:
                                pass
                self._json_response(200, {"raw": stdout, "stderr": result.stderr[:200]})
                self._log_request("POST", "/v1/scan", 200, ip)
            else:
                # Standard pattern scan
                guard_script = _script("injection_guard.py")
                result = _run_script([guard_script, "--text", text, "--source", source, "--json"])
                # Enrich with temporal analysis if session_id provided
                result = self._enrich_with_temporal(result, session_id, text)
                self._json_response(200, result)
                self._log_request("POST", "/v1/scan", 200, ip)
        except TimeoutError:
            self._json_response(504, {"error": "scan_timeout"})
            self._log_request("POST", "/v1/scan", 504, ip)
        except FileNotFoundError:
            # injection_guard not present yet — return stub
            self._json_response(200, {
                "verdict": "UNKNOWN",
                "note": "injection_guard.py not yet installed",
                "text_length": len(text),
            })
            self._log_request("POST", "/v1/scan", 200, ip)
        except Exception as e:
            self._json_response(500, {"error": str(e)})
            self._log_request("POST", "/v1/scan", 500, ip)

    def _enrich_with_temporal(self, result: dict, session_id: Optional[str], text: str) -> dict:
        """
        If session_id is provided and temporal_analyzer is available,
        record the message verdict and attach temporal_risk + temporal_alerts to result.
        """
        if not session_id or not _TEMPORAL_AVAILABLE:
            result["temporal_risk"]   = None
            result["temporal_alerts"] = []
            return result

        try:
            verdict    = result.get("verdict", "CLEAN")
            score      = float(result.get("score", 0.0))
            categories = result.get("categories", [])
            if isinstance(categories, str):
                categories = [c.strip() for c in categories.split(",") if c.strip()]

            temporal = _temporal_analyzer.record_message(
                session_id=session_id,
                verdict=verdict,
                score=score,
                categories=categories,
                message_text=text,
            )
            result["temporal_risk"]        = temporal.get("temporal_risk", 0.0)
            result["temporal_alerts"]      = temporal.get("alerts", [])
            result["temporal_recommendation"] = temporal.get("recommendation", "")
            result["session_message_count"]   = temporal.get("message_count", 0)
        except Exception as e:
            logger.warning(f"temporal_analyzer enrichment failed: {e}")
            result["temporal_risk"]   = None
            result["temporal_alerts"] = []

        return result

    def _handle_session_temporal(self, session_id: str, ip: str):
        """GET /v1/session/{session_id}/temporal — full temporal analysis for a session."""
        path = f"/v1/session/{session_id}/temporal"
        if not _TEMPORAL_AVAILABLE:
            self._json_response(503, {
                "error": "temporal_analyzer not available",
                "session_id": session_id,
            })
            self._log_request("GET", path, 503, ip)
            return

        try:
            report = _temporal_analyzer.get_session_report(session_id)
            if "error" in report:
                self._json_response(404, report)
                self._log_request("GET", path, 404, ip)
            else:
                self._json_response(200, report)
                self._log_request("GET", path, 200, ip)
        except Exception as e:
            self._json_response(500, {"error": str(e)})
            self._log_request("GET", path, 500, ip)

    def _handle_audit(self, body: dict, ip: str):
        code = body.get("code", "")
        lang = body.get("lang", "auto")

        if not code:
            self._json_response(400, {"error": "missing field: code"})
            self._log_request("POST", "/v1/audit", 400, ip)
            return

        try:
            sc_script = _script("sc_scanner.py")
            result = _run_script([sc_script, "--code", code, "--lang", lang, "--json"])
            self._json_response(200, result)
            self._log_request("POST", "/v1/audit", 200, ip)
        except TimeoutError:
            self._json_response(504, {"error": "audit_timeout"})
            self._log_request("POST", "/v1/audit", 504, ip)
        except FileNotFoundError:
            self._json_response(200, {
                "verdict": "UNKNOWN",
                "note": "sc_scanner.py not yet installed",
                "code_length": len(code),
                "lang": lang,
            })
            self._log_request("POST", "/v1/audit", 200, ip)
        except Exception as e:
            self._json_response(500, {"error": str(e)})
            self._log_request("POST", "/v1/audit", 500, ip)

    def _handle_monitor(self, body: dict, ip: str):
        try:
            monitor_script = _script("threat_monitor.py")
            result = _run_script([monitor_script, "--check", "--json"])
            self._json_response(200, result)
            self._log_request("POST", "/v1/monitor", 200, ip)
        except TimeoutError:
            self._json_response(504, {"error": "monitor_timeout"})
            self._log_request("POST", "/v1/monitor", 504, ip)
        except FileNotFoundError:
            self._json_response(200, {
                "status": "UNKNOWN",
                "note": "threat_monitor.py not yet installed",
            })
            self._log_request("POST", "/v1/monitor", 200, ip)
        except Exception as e:
            self._json_response(500, {"error": str(e)})
            self._log_request("POST", "/v1/monitor", 500, ip)

    def _handle_feedback(self, body: dict, ip: str):
        scan_id  = body.get("scan_id", "")
        verdict  = body.get("verdict", "")
        category = body.get("category", "")

        if verdict == "false_positive" and category:
            try:
                _run_script([_script("cortex_engine.py"), "--fp", category])
                self._json_response(200, {
                    "status": "recorded",
                    "scan_id": scan_id,
                    "category": category,
                    "action": "false_positive_marked",
                })
                self._log_request("POST", "/v1/feedback", 200, ip)
            except Exception as e:
                self._json_response(500, {"error": str(e)})
                self._log_request("POST", "/v1/feedback", 500, ip)
        else:
            self._json_response(400, {
                "error": "invalid feedback",
                "hint": "verdict must be 'false_positive' and category must be non-empty",
            })
            self._log_request("POST", "/v1/feedback", 400, ip)


# ── Server bootstrap ──────────────────────────────────────────────────────────
def print_banner(host: str, port: int, key: str):
    print("""
╔══════════════════════════════════════════════════════════════╗
║              CLARIS AI V5.0 — REST API SERVER               ║
╚══════════════════════════════════════════════════════════════╝""")
    print(f"  Listening : http://{host}:{port}")
    print(f"  Auth key  : {key}")
    print(f"  Rate limit: {RATE_LIMIT} req/min per IP")
    print(f"  Log file  : {LOG_FILE}")
    print()
    print("  Endpoints:")
    print("    GET  /v1/health                       — health check + uptime")
    print("    POST /v1/scan                         — injection_guard scan (+ temporal if session_id)")
    print("    POST /v1/audit                        — smart contract audit")
    print("    POST /v1/monitor                      — threat monitor check")
    print("    GET  /v1/cortex                       — cortex coverage report")
    print("    GET  /v1/stats                        — daily stats + trending")
    print("    POST /v1/feedback                     — mark false positives")
    print("    GET  /v1/session/{session_id}/temporal — full temporal session analysis")
    print()
    print("  /v1/scan body: { text, source?, ml?, session_id? }")
    print("  Header: X-Claris-Key: <key>")
    print("  ~Claris · Semper Fortis · V5.0")
    print()


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, key: str = DEFAULT_KEY):
    global _api_key
    _api_key = key
    print_banner(host, port, key)
    server = HTTPServer((host, port), ClarisHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Claris API] Shutting down gracefully.")
        server.shutdown()


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Claris AI V4.0 REST API Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default {DEFAULT_PORT})")
    parser.add_argument("--key",  type=str, default=DEFAULT_KEY,  help="API auth key")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Bind host")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port, key=args.key)


if __name__ == "__main__":
    main()

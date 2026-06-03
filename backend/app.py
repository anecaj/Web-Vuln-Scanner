"""
Web Vulnerability Scanner — Flask API
"""
import uuid
import logging
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS

import database as db
import scanner as sc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# In-memory progress store (safe with 1 gunicorn worker + preload)
_progress = {}  # scan_id -> {"pct": int, "message": str}


def _run_scan_thread(scan_id: str, target_url: str):
    """Background thread: run scan and save results."""
    def on_progress(pct, msg):
        _progress[scan_id] = {"pct": pct, "message": msg}

    try:
        findings = sc.run_scan(target_url, progress_callback=on_progress)
        db.complete_scan(scan_id, findings)
    except Exception as e:
        logger.error(f"Scan {scan_id} error: {e}")
        db.complete_scan(scan_id, [], error=str(e))
    finally:
        _progress.pop(scan_id, None)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.post("/api/scan")
def start_scan():
    data = request.get_json() or {}
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({"error": "URL is required"}), 400

    # Normalize URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    scan_id = str(uuid.uuid4())
    db.create_scan(scan_id, target_url)
    _progress[scan_id] = {"pct": 0, "message": "Starting scan..."}

    thread = threading.Thread(target=_run_scan_thread, args=(scan_id, target_url), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id, "target_url": target_url, "status": "running"})


@app.get("/api/scan/<scan_id>")
def get_scan(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # Attach live progress if still running
    if scan["status"] == "running":
        prog = _progress.get(scan_id, {"pct": 0, "message": "Running..."})
        scan["progress_pct"]     = prog["pct"]
        scan["progress_message"] = prog["message"]
    else:
        scan["progress_pct"]     = 100
        scan["progress_message"] = "Complete"

    return jsonify(scan)


@app.get("/api/scans")
def list_scans():
    return jsonify(db.get_scan_history())


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# ── Startup ────────────────────────────────────────────────────────────────────
db.init_db()
logger.info("Database initialized")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=False)

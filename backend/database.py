"""
SQLite database for Web Vulnerability Scanner.
Stores scan history and findings.
"""
import sqlite3
import json
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            findings_json TEXT DEFAULT '[]',
            error_msg TEXT
        )
    """)
    conn.commit()
    conn.close()

def create_scan(scan_id, target_url):
    conn = get_conn()
    conn.execute("""
        INSERT INTO scans (scan_id, target_url, status, started_at)
        VALUES (?, ?, 'running', ?)
    """, (scan_id, target_url, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()

def complete_scan(scan_id, findings, error=None):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    conn = get_conn()
    conn.execute("""
        UPDATE scans SET
            status = ?,
            completed_at = ?,
            total_findings = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            info_count = ?,
            findings_json = ?,
            error_msg = ?
        WHERE scan_id = ?
    """, (
        "error" if error else "complete",
        datetime.now(timezone.utc).isoformat(),
        len(findings),
        counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"],
        counts["LOW"], counts["INFO"],
        json.dumps(findings),
        error,
        scan_id
    ))
    conn.commit()
    conn.close()

def get_scan(scan_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["findings"] = json.loads(d.pop("findings_json", "[]"))
    return d

def get_scan_history(limit=20):
    conn = get_conn()
    rows = conn.execute("""
        SELECT scan_id, target_url, status, started_at, completed_at,
               total_findings, critical_count, high_count, medium_count, low_count, info_count
        FROM scans ORDER BY started_at DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

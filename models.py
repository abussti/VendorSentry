#models.py

import sqlite3
from datetime import datetime
import os
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor_risk.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            domain TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_scanned DATETIME,
            latest_score INTEGER,
            risk_level TEXT,
            alert_triggered BOOLEAN DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id INTEGER NOT NULL,
            scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            score INTEGER,
            breach_score INTEGER,
            exposure_score INTEGER,
            vuln_score INTEGER,
            dns_score INTEGER,
            ssl_score INTEGER,
            ai_summary TEXT,
            raw_findings TEXT,
            report_path TEXT,
            confidence TEXT,
            coverage TEXT,
            FOREIGN KEY (vendor_id) REFERENCES vendors(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            sender TEXT,
            sender_domain TEXT,
            subject TEXT,
            email_threat_score INTEGER,
            email_risk_level TEXT,
            final_score INTEGER,
            final_risk_level TEXT,
            confidence INTEGER,
            impersonation_hits TEXT,
            risk_factors TEXT,
            safe_action TEXT,
            keyword_hits TEXT,
            urls_found TEXT,
            sender_domain_score INTEGER,
            sender_domain_risk TEXT,
            ai_summary TEXT,
            raw_findings TEXT,
            verdict TEXT,
            verdict_level TEXT,
            attack_type TEXT,
            verdict_reason TEXT,
            threat_intel TEXT,
            domain_age_days INTEGER,
            domain_age_label TEXT,
            header_spf TEXT,
            header_dkim TEXT,
            header_dmarc TEXT,
            header_issues TEXT,
            top_drivers TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialised successfully")

def save_vendor(name, domain):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO vendors (name, domain) VALUES (?, ?)",
            (name, domain)
        )
        conn.commit()
        vendor_id = cursor.lastrowid
        return vendor_id
    except sqlite3.IntegrityError:
        row = conn.execute(
            "SELECT id FROM vendors WHERE domain = ?", (domain,)
        ).fetchone()
        return row["id"]
    finally:
        conn.close()

def save_assessment(vendor_id, scores, ai_summary, raw_findings, report_path=None):
    conn = get_db()
    import json
    conn.execute("""
        INSERT INTO assessments
        (vendor_id, score, breach_score, exposure_score, vuln_score,
         dns_score, ssl_score, ai_summary, raw_findings, report_path, confidence, coverage)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        vendor_id,
        scores["total"],
        scores["breach"],
        scores["exposure"],
        scores["vuln"],
        scores["dns"],
        scores["ssl"],
        ai_summary,
        json.dumps(raw_findings),
        report_path,
        scores.get("confidence", "Unknown"),
        scores.get("coverage", ""),
    ))

    risk_level = "High" if scores["total"] < 40 else "Medium" if scores["total"] < 70 else "Low"

    conn.execute("""
        UPDATE vendors SET last_scanned = ?, latest_score = ?, risk_level = ?
        WHERE id = ?
    """, (datetime.utcnow(), scores["total"], risk_level, vendor_id))

    conn.commit()
    conn.close()

def get_all_vendors():
    conn = get_db()
    vendors = conn.execute(
        "SELECT * FROM vendors ORDER BY latest_score ASC"
    ).fetchall()
    conn.close()
    return vendors

def get_vendor_history(vendor_id):
    conn = get_db()
    history = conn.execute(
        "SELECT * FROM assessments WHERE vendor_id = ? ORDER BY scanned_at DESC",
        (vendor_id,)
    ).fetchall()
    conn.close()
    return history

if __name__ == "__main__":
    init_db()

import sqlite3
import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def get_db_file_path() -> str:
    env_path = os.environ.get("DATABASE_PATH")
    if env_path:
        return env_path
    # On Vercel / AWS Lambda serverless runtimes, root is read-only; use writable /tmp
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "/tmp/trustlens.db"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "trustlens.db")

DB_FILE = get_db_file_path()

def get_connection():
    conn = sqlite3.connect(get_db_file_path())
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema for incidents, scan history, and Web3 commitments."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Threat Incidents Table (Threat Intelligence Feed & Graph Correlation)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                brand_targeted TEXT DEFAULT 'Unknown',
                threat_category TEXT NOT NULL,
                campaign_name TEXT DEFAULT 'Ad-hoc Threat Incident',
                incident_summary TEXT,
                risk_level TEXT NOT NULL,
                ip TEXT DEFAULT 'Unknown',
                asn TEXT DEFAULT 'Unknown',
                nameservers TEXT DEFAULT '[]',
                registrar TEXT DEFAULT 'Unknown',
                report_hash TEXT,
                supporting_evidence_refs TEXT DEFAULT '[]',
                timestamp TEXT NOT NULL
            )
        """)

        # 2. Web3 Commitments Table (Decentralized Threat Registry)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS web3_commitments (
                report_hash TEXT PRIMARY KEY,
                indicator_hash TEXT NOT NULL,
                reporter TEXT NOT NULL,
                contract_address TEXT NOT NULL,
                transaction_hash TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                iso_timestamp TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                category TEXT NOT NULL,
                campaign_name TEXT,
                evidence_refs TEXT DEFAULT '[]',
                dispute_count INTEGER DEFAULT 0,
                disputes TEXT DEFAULT '[]',
                is_verified INTEGER DEFAULT 1,
                is_revoked INTEGER DEFAULT 0
            )
        """)

        # 3. Scan History Table (Audit Log of Analyzed URLs & Messages)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                overall_risk TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                report_hash TEXT,
                summary TEXT,
                created_at TEXT NOT NULL
            )
        """)
        
        conn.commit()

def save_incident(incident: Dict[str, Any]):
    """Persists a threat incident to the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO incidents (
                id, indicator, indicator_type, brand_targeted, threat_category,
                campaign_name, incident_summary, risk_level, ip, asn,
                nameservers, registrar, report_hash, supporting_evidence_refs, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.get("id"),
            incident.get("indicator"),
            incident.get("indicator_type", "domain"),
            incident.get("brand_targeted", "Unknown"),
            incident.get("threat_category", "Phishing"),
            incident.get("campaign_name", "Ad-hoc Threat Incident"),
            incident.get("incident_summary", ""),
            incident.get("risk_level", "High Risk"),
            incident.get("ip", "Unknown"),
            incident.get("asn", "Unknown"),
            json.dumps(incident.get("nameservers", [])),
            incident.get("registrar", "Unknown"),
            incident.get("report_hash", ""),
            json.dumps(incident.get("supporting_evidence_refs", [])),
            incident.get("timestamp", datetime.now(timezone.utc).isoformat())
        ))
        conn.commit()

def load_incidents() -> List[Dict[str, Any]]:
    """Loads all stored threat incidents from the database."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        incidents = []
        for r in rows:
            incidents.append({
                "id": r["id"],
                "indicator": r["indicator"],
                "indicator_type": r["indicator_type"],
                "brand_targeted": r["brand_targeted"],
                "threat_category": r["threat_category"],
                "campaign_name": r["campaign_name"],
                "incident_summary": r["incident_summary"],
                "risk_level": r["risk_level"],
                "ip": r["ip"],
                "asn": r["asn"],
                "nameservers": json.loads(r["nameservers"] or "[]"),
                "registrar": r["registrar"],
                "report_hash": r["report_hash"],
                "supporting_evidence_refs": json.loads(r["supporting_evidence_refs"] or "[]"),
                "timestamp": r["timestamp"]
            })
        return incidents

def save_web3_commitment(record: Dict[str, Any]):
    """Persists an on-chain commitment record to the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO web3_commitments (
                report_hash, indicator_hash, reporter, contract_address,
                transaction_hash, block_number, timestamp, iso_timestamp,
                threat_level, category, campaign_name, evidence_refs,
                dispute_count, disputes, is_verified, is_revoked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.get("report_hash"),
            record.get("indicator_hash"),
            record.get("reporter", ""),
            record.get("contract_address", ""),
            record.get("transaction_hash", ""),
            record.get("block_number", 0),
            record.get("timestamp", int(datetime.now(timezone.utc).timestamp())),
            record.get("iso_timestamp", datetime.now(timezone.utc).isoformat()),
            record.get("threat_level", "High Risk"),
            record.get("category", "Phishing"),
            record.get("campaign_name", ""),
            json.dumps(record.get("evidence_refs", [])),
            record.get("dispute_count", 0),
            json.dumps(record.get("disputes", [])),
            1 if record.get("is_verified", True) else 0,
            1 if record.get("is_revoked", False) else 0
        ))
        conn.commit()

def load_web3_commitments() -> Dict[str, Dict[str, Any]]:
    """Loads all on-chain commitments from the database."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM web3_commitments ORDER BY block_number DESC")
        rows = cursor.fetchall()
        commitments = {}
        for r in rows:
            commitments[r["report_hash"]] = {
                "report_hash": r["report_hash"],
                "indicator_hash": r["indicator_hash"],
                "reporter": r["reporter"],
                "contract_address": r["contract_address"],
                "transaction_hash": r["transaction_hash"],
                "block_number": r["block_number"],
                "timestamp": r["timestamp"],
                "iso_timestamp": r["iso_timestamp"],
                "threat_level": r["threat_level"],
                "category": r["category"],
                "campaign_name": r["campaign_name"],
                "evidence_refs": json.loads(r["evidence_refs"] or "[]"),
                "dispute_count": r["dispute_count"],
                "disputes": json.loads(r["disputes"] or "[]"),
                "is_verified": bool(r["is_verified"]),
                "is_revoked": bool(r["is_revoked"])
            }
        return commitments

def log_scan(scan_type: str, target: str, overall_risk: str, risk_score: int, report_hash: str = "", summary: str = ""):
    """Logs an investigation to scan_history."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (scan_type, target, overall_risk, risk_score, report_hash, summary, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_type,
            target,
            overall_risk,
            risk_score,
            report_hash,
            summary,
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()

def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent scans from the SQLite database."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

def get_db_stats() -> Dict[str, Any]:
    """Returns database operational statistics from SQLite."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM incidents")
        incidents_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM web3_commitments")
        commitments_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        scans_count = cursor.fetchone()[0]
        return {
            "database_engine": "SQLite3 (Standard Relational Embedded)",
            "database_file": os.path.basename(DB_FILE),
            "status": "connected",
            "tables": {
                "incidents": incidents_count,
                "web3_commitments": commitments_count,
                "scan_history": scans_count
            }
        }



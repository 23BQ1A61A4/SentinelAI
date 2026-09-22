"""
SQLite Database Manager for Audit Storage, Memory, and Drift Tracking
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from .models import AuditReport, AuditTarget

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_path: str = "compliance_auditor.db"):
        self.db_path = db_path
        # Ensure parent directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        """Initialize relational tables if they don't already exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Audits Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audits (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                target_name TEXT NOT NULL,
                overall_compliance_score REAL NOT NULL,
                overall_security_score REAL NOT NULL,
                composite_risk_score REAL NOT NULL,
                decision_status TEXT NOT NULL,
                total_attacks INTEGER NOT NULL,
                vulnerabilities_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                report_json TEXT NOT NULL,
                pdf_report_path TEXT
            )
            """)

            # Vulnerabilities Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                audit_id TEXT NOT NULL,
                owasp_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                attack_category TEXT NOT NULL,
                is_exploitable INTEGER NOT NULL,
                exploit_evidence TEXT,
                defense_recommendation TEXT,
                judge_verdict TEXT,
                FOREIGN KEY (audit_id) REFERENCES audits (id) ON DELETE CASCADE
            )
            """)

            # Compliance Controls Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_controls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id TEXT NOT NULL,
                standard TEXT NOT NULL,
                control_id TEXT NOT NULL,
                status TEXT NOT NULL,
                score REAL NOT NULL,
                findings TEXT,
                FOREIGN KEY (audit_id) REFERENCES audits (id) ON DELETE CASCADE
            )
            """)

            # Agent Traces / Memory Log
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_memory_traces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                action TEXT NOT NULL,
                output_summary TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (audit_id) REFERENCES audits (id) ON DELETE CASCADE
            )
            """)
            conn.commit()

    def save_audit(self, report: AuditReport) -> str:
        """Persist a complete audit report and its child relations."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            report_json = report.model_dump_json()

            cursor.execute("""
            INSERT OR REPLACE INTO audits (
                id, created_at, target_name, overall_compliance_score,
                overall_security_score, composite_risk_score, decision_status,
                total_attacks, vulnerabilities_count, critical_count, high_count,
                report_json, pdf_report_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.id,
                report.created_at,
                report.target.name,
                report.overall_compliance_score,
                report.overall_security_score,
                report.composite_risk_score,
                report.decision.status,
                report.total_attacks_tested,
                report.vulnerabilities_found,
                report.critical_vulnerabilities,
                report.high_vulnerabilities,
                report_json,
                report.pdf_report_path
            ))

            # Insert vulnerabilities
            for v in report.vulnerabilities:
                cursor.execute("""
                INSERT OR REPLACE INTO vulnerabilities (
                    id, audit_id, owasp_id, severity, cvss_score,
                    attack_category, is_exploitable, exploit_evidence,
                    defense_recommendation, judge_verdict
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    v.id, report.id, v.owasp_id, v.severity, v.cvss_score,
                    v.attack_category, 1 if v.is_exploitable else 0,
                    v.exploit_evidence, v.defense_recommendation, v.judge_verdict
                ))

            # Insert compliance controls
            for c in report.compliance_controls:
                cursor.execute("""
                INSERT INTO compliance_controls (
                    audit_id, standard, control_id, status, score, findings
                ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    report.id, c.standard, c.control_id, c.status, c.score, c.findings
                ))

            conn.commit()
            return report.id

    def get_audit(self, audit_id: str) -> Optional[AuditReport]:
        """Fetch an audit by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT report_json FROM audits WHERE id = ?", (audit_id,))
            row = cursor.fetchone()
            if row:
                data = json.loads(row["report_json"])
                return AuditReport(**data)
        return None

    def list_audits(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List audit metadata summaries."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, created_at, target_name, overall_compliance_score,
                   overall_security_score, composite_risk_score, decision_status,
                   vulnerabilities_count, critical_count, high_count
            FROM audits
            ORDER BY created_at DESC
            LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def log_agent_trace(self, audit_id: str, agent_name: str, action: str, output_summary: str, timestamp: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO agent_memory_traces (audit_id, agent_name, action, output_summary, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """, (audit_id, agent_name, action, output_summary, timestamp))
            conn.commit()

    def get_agent_traces(self, audit_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT agent_name, action, output_summary, timestamp
            FROM agent_memory_traces
            WHERE audit_id = ?
            ORDER BY id ASC
            """, (audit_id,))
            return [dict(row) for row in cursor.fetchall()]

    def delete_audit(self, audit_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audits WHERE id = ?", (audit_id,))
            cursor.execute("DELETE FROM vulnerabilities WHERE audit_id = ?", (audit_id,))
            cursor.execute("DELETE FROM compliance_controls WHERE audit_id = ?", (audit_id,))
            cursor.execute("DELETE FROM agent_memory_traces WHERE audit_id = ?", (audit_id,))
            conn.commit()
            return cursor.rowcount > 0

_db_instance = None

def get_db(db_path: Optional[str] = None) -> Database:
    global _db_instance
    if _db_instance is None:
        try:
            from ..config import DATABASE_PATH
        except (ImportError, ValueError):
            try:
                from config import DATABASE_PATH
            except ImportError:
                DATABASE_PATH = "compliance_auditor.db"
        _db_instance = Database(db_path or DATABASE_PATH)
    return _db_instance

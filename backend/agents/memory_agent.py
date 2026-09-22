"""
Memory Agent: Historical Audit Context, Cross-Run Comparison & Security Drift Engine
"""

from typing import Dict, Any, Optional, List
try:
    from agents.base_agent import BaseAgent
    from database.models import AuditReport
except (ImportError, ValueError):
    from .base_agent import BaseAgent
    from ..database.models import AuditReport

class MemoryAgent(BaseAgent):
    def __init__(self, llm_client=None):
        super().__init__(
            name="Memory Agent",
            role="Audit Memory & Drift Tracker",
            description="Retains historical audit context in SQLite, compares past audit runs, and detects security drift or regressions.",
            llm_client=llm_client
        )

    def compare_audits(self, audit_id_a: str, audit_id_b: str) -> Dict[str, Any]:
        """
        Performs in-depth comparative diff between two audit runs.
        """
        report_a = self.db.get_audit(audit_id_a)
        report_b = self.db.get_audit(audit_id_b)

        if not report_a or not report_b:
            return {"error": "One or both audit reports could not be found in memory."}

        comp_delta = report_b.overall_compliance_score - report_a.overall_compliance_score
        sec_delta = report_b.overall_security_score - report_a.overall_security_score
        risk_delta = report_b.composite_risk_score - report_a.composite_risk_score
        vuln_delta = report_b.vulnerabilities_found - report_a.vulnerabilities_found

        # Vulnerability tracking
        exploited_a = {v.owasp_id for v in report_a.vulnerabilities if v.is_exploitable}
        exploited_b = {v.owasp_id for v in report_b.vulnerabilities if v.is_exploitable}

        fixed_vulns = list(exploited_a - exploited_b)
        new_regressions = list(exploited_b - exploited_a)

        drift_status = "IMPROVED" if (comp_delta > 0 and len(new_regressions) == 0) else "REGRESSED" if (comp_delta < 0 or len(new_regressions) > 0) else "STABLE"

        comparison = {
            "audit_a": {
                "id": report_a.id,
                "created_at": report_a.created_at,
                "compliance_score": report_a.overall_compliance_score,
                "security_score": report_a.overall_security_score,
                "risk_score": report_a.composite_risk_score,
                "vulnerabilities_found": report_a.vulnerabilities_found
            },
            "audit_b": {
                "id": report_b.id,
                "created_at": report_b.created_at,
                "compliance_score": report_b.overall_compliance_score,
                "security_score": report_b.overall_security_score,
                "risk_score": report_b.composite_risk_score,
                "vulnerabilities_found": report_b.vulnerabilities_found
            },
            "deltas": {
                "compliance_delta": round(comp_delta, 1),
                "security_delta": round(sec_delta, 1),
                "risk_delta": round(risk_delta, 1),
                "vulnerability_delta": vuln_delta
            },
            "fixed_vulnerabilities": fixed_vulns,
            "new_regressions": new_regressions,
            "drift_status": drift_status,
            "summary": (
                f"Audit Comparison: {drift_status}. Compliance score shifted by {comp_delta:+.1f}%, "
                f"Vulnerabilities changed by {vuln_delta:+d} ({len(fixed_vulns)} fixed, {len(new_regressions)} regressions)."
            )
        }

        self.log(report_b.id, "Audit Drift Comparison", comparison["summary"])
        return comparison

"""
Report Agent: Executive Summary & PDF/JSON Audit Report Compiler
"""

from typing import Optional
try:
    from agents.base_agent import BaseAgent
    from database.models import AuditReport, AuditTarget, RiskAssessment, DecisionSummary
    from core.pdf_generator import PDFReportGenerator
except (ImportError, ValueError):
    from .base_agent import BaseAgent
    from ..database.models import AuditReport, AuditTarget, RiskAssessment, DecisionSummary
    from ..core.pdf_generator import PDFReportGenerator

class ReportAgent(BaseAgent):
    def __init__(self, llm_client=None):
        super().__init__(
            name="Report Agent",
            role="Audit Dossier & Executive Summary Compiler",
            description="Compiles comprehensive technical dossiers, executive summaries, and generates downloadable PDF reports.",
            llm_client=llm_client
        )
        self.pdf_generator = PDFReportGenerator()

    def generate_executive_summary(
        self,
        target: AuditTarget,
        compliance_score: float,
        security_score: float,
        risk: RiskAssessment,
        decision: DecisionSummary,
        vulns_count: int,
        critical_count: int
    ) -> str:
        """
        Synthesizes a high-level executive summary for CISOs and compliance officers.
        """
        summary = (
            f"An automated multi-agent cybersecurity audit was executed on '{target.name}' processing "
            f"{target.data_sensitivity} assets. The system achieved an overall regulatory compliance score of "
            f"{compliance_score:.1f}% and an adversarial security resilience score of {security_score:.1f}%. "
            f"The assessment identified {vulns_count} total vulnerability vectors ({critical_count} Critical severity), "
            f"resulting in a {risk.risk_level} enterprise risk posture (Composite Index: {risk.composite_risk_score:.1f}/100). "
            f"The final executive release determination is: {decision.status}."
        )
        return summary

    def compile_pdf(self, report: AuditReport) -> Optional[str]:
        """
        Invokes PDF generator to compile the styled PDF document.
        """
        try:
            pdf_path = self.pdf_generator.generate(report)
            self.log(report.id, "PDF Generation", f"Compiled executive PDF dossier to: {pdf_path}")
            return pdf_path
        except Exception as e:
            self.log(report.id, "PDF Generation Failed", f"Error generating PDF: {e}")
            return None

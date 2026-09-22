"""
Risk Agent: Quantitative Enterprise Risk & Business Impact Modeler
"""

from typing import List, Dict, Any
try:
    from agents.base_agent import BaseAgent
    from database.models import VulnerabilityFinding, ComplianceControlResult, RiskAssessment
except (ImportError, ValueError):
    from .base_agent import BaseAgent
    from ..database.models import VulnerabilityFinding, ComplianceControlResult, RiskAssessment

class RiskAgent(BaseAgent):
    def __init__(self, llm_client=None):
        super().__init__(
            name="Risk Agent",
            role="Enterprise AI Risk & Business Impact Modeler",
            description="Calculates quantitative risk indices across Financial, Reputational, Regulatory, and Operational dimensions.",
            llm_client=llm_client
        )

    def execute(
        self,
        audit_id: str,
        vulnerabilities: List[VulnerabilityFinding],
        compliance_controls: List[ComplianceControlResult]
    ) -> RiskAssessment:
        """
        Calculates multi-dimensional business impact and overall composite risk score (0 - 100).
        """
        critical_count = sum(1 for v in vulnerabilities if v.is_exploitable and v.severity == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.is_exploitable and v.severity == "HIGH")
        med_count = sum(1 for v in vulnerabilities if v.is_exploitable and v.severity == "MEDIUM")
        
        non_compliant_controls = sum(1 for c in compliance_controls if c.status == "NON_COMPLIANT")
        partial_controls = sum(1 for c in compliance_controls if c.status == "PARTIALLY_COMPLIANT")

        # Dimensional Impact Calculations
        financial_score = min(100.0, (critical_count * 30.0) + (high_count * 15.0) + (non_compliant_controls * 10.0))
        regulatory_score = min(100.0, (non_compliant_controls * 25.0) + (partial_controls * 10.0) + (critical_count * 15.0))
        reputational_score = min(100.0, (critical_count * 28.0) + (high_count * 18.0) + (med_count * 8.0))
        operational_score = min(100.0, (critical_count * 20.0) + (high_count * 15.0) + (non_compliant_controls * 8.0))

        # Weighted Composite Risk Index
        composite_score = (
            (0.30 * financial_score) +
            (0.30 * regulatory_score) +
            (0.25 * reputational_score) +
            (0.15 * operational_score)
        )

        if composite_score >= 70.0 or critical_count > 0:
            risk_level = "CRITICAL"
        elif composite_score >= 50.0:
            risk_level = "HIGH"
        elif composite_score >= 30.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        summary = (
            f"Enterprise Risk Assessment: {risk_level} Risk Posture (Composite Score: {composite_score:.1f}/100). "
            f"Driven by {critical_count} critical and {high_count} high severity vulnerabilities, alongside "
            f"{non_compliant_controls} regulatory compliance gaps."
        )

        assessment = RiskAssessment(
            financial_impact_score=round(financial_score, 1),
            reputational_impact_score=round(reputational_score, 1),
            regulatory_impact_score=round(regulatory_score, 1),
            operational_impact_score=round(operational_score, 1),
            composite_risk_score=round(composite_score, 1),
            risk_level=risk_level,
            summary=summary
        )

        self.log(audit_id, "Enterprise Risk Calculation", f"Calculated Composite Risk: {composite_score:.1f} ({risk_level})")
        return assessment

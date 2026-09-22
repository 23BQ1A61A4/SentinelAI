"""
Forecast Agent: Predictive Compliance Scoring & Trend Modeler
"""

from typing import List
try:
    from agents.base_agent import BaseAgent
    from database.models import ForecastPoint, VulnerabilityFinding
except (ImportError, ValueError):
    from .base_agent import BaseAgent
    from ..database.models import ForecastPoint, VulnerabilityFinding

class ForecastAgent(BaseAgent):
    def __init__(self, llm_client=None):
        super().__init__(
            name="Forecast Agent",
            role="Predictive Compliance & Trend Modeler",
            description="Projects future compliance and security score trajectories under baseline and remediation pathways.",
            llm_client=llm_client
        )

    def execute(
        self,
        audit_id: str,
        current_compliance_score: float,
        current_security_score: float,
        vulnerabilities: List[VulnerabilityFinding]
    ) -> List[ForecastPoint]:
        """
        Calculates time-series compliance forecast across 30, 60, 90, and 180 days.
        """
        exploited_count = sum(1 for v in vulnerabilities if v.is_exploitable)
        
        # Calculate expected gains from remediation
        max_possible_gain = max(0.0, 100.0 - current_compliance_score)
        
        # Realistic S-curve projection for remediation adoption
        p_current = ForecastPoint(
            timeframe="Current",
            baseline_score=round(current_compliance_score, 1),
            projected_score_with_remediation=round(current_compliance_score, 1)
        )
        
        p_30 = ForecastPoint(
            timeframe="30 Days",
            baseline_score=round(max(20.0, current_compliance_score - 2.5), 1),  # Drift if unmaintained
            projected_score_with_remediation=round(min(100.0, current_compliance_score + (max_possible_gain * 0.45)), 1)
        )

        p_60 = ForecastPoint(
            timeframe="60 Days",
            baseline_score=round(max(15.0, current_compliance_score - 5.0), 1),
            projected_score_with_remediation=round(min(100.0, current_compliance_score + (max_possible_gain * 0.75)), 1)
        )

        p_90 = ForecastPoint(
            timeframe="90 Days",
            baseline_score=round(max(10.0, current_compliance_score - 7.5), 1),
            projected_score_with_remediation=round(min(100.0, current_compliance_score + (max_possible_gain * 0.90)), 1)
        )

        p_180 = ForecastPoint(
            timeframe="180 Days",
            baseline_score=round(max(5.0, current_compliance_score - 12.0), 1),
            projected_score_with_remediation=round(min(100.0, current_compliance_score + (max_possible_gain * 0.98)), 1)
        )

        forecast = [p_current, p_30, p_60, p_90, p_180]
        self.log(audit_id, "Compliance Forecasting", f"Generated 5-point predictive trajectory. Target 180-day score: {p_180.projected_score_with_remediation}%")
        return forecast

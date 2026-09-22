"""
Blue Team Agent: Formulates defensive guardrails, architectural hardening, and remediation rules
"""

from typing import List, Dict, Any
try:
    from agents.base_agent import BaseAgent
    from database.models import VulnerabilityFinding
    from core.guardrails_engine import GuardrailsEngine
except (ImportError, ValueError):
    from .base_agent import BaseAgent
    from ..database.models import VulnerabilityFinding
    from ..core.guardrails_engine import GuardrailsEngine

class BlueTeamAgent(BaseAgent):
    def __init__(self, llm_client=None):
        super().__init__(
            name="Blue Team Agent",
            role="AI Defensive Engineer & Guardrail Architect",
            description="Formulates tactical defensive mitigations, input/output sanitizers, system prompt sandwiching, and RBAC rules.",
            llm_client=llm_client
        )

    def execute(self, audit_id: str, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """
        Formulates comprehensive defensive remediations for all identified vulnerabilities.
        """
        exploited_vulns = [v for v in vulnerabilities if v.is_exploitable]
        
        mitigations = []
        for v in exploited_vulns:
            mitigation_text = (
                f"Defensive Hardening for [{v.owasp_id} - {v.owasp_title}]:\n"
                f"1. Primary Control: {v.defense_recommendation}\n"
                f"2. Architecture Layer: Implement pre-inference input delimiter verification.\n"
                f"3. Monitoring: Alert on regex pattern matches in inference logs."
            )
            mitigations.append({
                "vuln_id": v.id,
                "owasp_id": v.owasp_id,
                "strategy": mitigation_text
            })

        summary = (
            f"Blue Team formulated {len(mitigations)} defensive guardrails covering input sanitization, "
            f"output DLP redaction, and tool privilege isolation."
        )

        self.log(audit_id, "Blue Team Defense Synthesis", summary)
        return {
            "defenses_count": len(mitigations),
            "mitigations": mitigations,
            "summary": summary
        }

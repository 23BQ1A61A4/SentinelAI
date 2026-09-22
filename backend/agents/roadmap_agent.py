"""
Roadmap Agent: Actionable Phased Remediation Plan & Engineering Effort Estimator
"""

from typing import List
try:
    from agents.base_agent import BaseAgent
    from database.models import RoadmapItem, VulnerabilityFinding, ComplianceControlResult
except (ImportError, ValueError):
    from .base_agent import BaseAgent
    from ..database.models import RoadmapItem, VulnerabilityFinding, ComplianceControlResult

class RoadmapAgent(BaseAgent):
    def __init__(self, llm_client=None):
        super().__init__(
            name="Roadmap Agent",
            role="Cybersecurity Remediation & Roadmap Architect",
            description="Constructs phased, prioritized remediation milestones (Phase 1, 2, 3) with engineering effort and score delta.",
            llm_client=llm_client
        )

    def execute(
        self,
        audit_id: str,
        vulnerabilities: List[VulnerabilityFinding],
        compliance_controls: List[ComplianceControlResult]
    ) -> List[RoadmapItem]:
        """
        Builds prioritized remediation roadmap items across Phase 1, Phase 2, and Phase 3.
        """
        items: List[RoadmapItem] = []

        # Check for specific vulnerability drivers
        has_prompt_injection = any(v.owasp_id == "LLM01" and v.is_exploitable for v in vulnerabilities)
        has_pii_leak = any(v.owasp_id == "LLM02" and v.is_exploitable for v in vulnerabilities)
        has_tool_abuse = any(v.owasp_id == "LLM06" and v.is_exploitable for v in vulnerabilities)
        has_prompt_leak = any(v.owasp_id == "LLM07" and v.is_exploitable for v in vulnerabilities)
        has_output_vuln = any(v.owasp_id == "LLM05" and v.is_exploitable for v in vulnerabilities)

        # Phase 1: Immediate Hotfixes (0 - 14 Days)
        if has_prompt_injection:
            items.append(RoadmapItem(
                phase="Phase 1: Immediate Hotfixes (0-14 days)",
                priority="P0",
                title="Deploy Input Delimiter Sanitizer & Adversarial Keyword Blocklist",
                description="Intercept and block known jailbreak signatures ('ignore all instructions', 'unrestricted mode') before tokenization.",
                affected_owasp_or_standard="OWASP LLM01 / ISO-A.8.7",
                estimated_hours=16,
                difficulty="Low",
                expected_compliance_gain=12.5
            ))

        if has_pii_leak:
            items.append(RoadmapItem(
                phase="Phase 1: Immediate Hotfixes (0-14 days)",
                priority="P0",
                title="Implement Regex DLP Output Scrubber & Pre-Inference PII Redaction",
                description="Scrub customer SSNs, credit cards, and credential tokens from inference stream before displaying to client.",
                affected_owasp_or_standard="OWASP LLM02 / ISO-A.8.12",
                estimated_hours=20,
                difficulty="Low",
                expected_compliance_gain=14.0
            ))

        if has_output_vuln:
            items.append(RoadmapItem(
                phase="Phase 1: Immediate Hotfixes (0-14 days)",
                priority="P1",
                title="Contextual HTML Entity Encoding on LLM Returns",
                description="Prevent XSS and script reflection by encoding all dynamic LLM output strings rendered in frontend dashboards.",
                affected_owasp_or_standard="OWASP LLM05 / ISO-A.8.28",
                estimated_hours=10,
                difficulty="Low",
                expected_compliance_gain=6.0
            ))

        # Phase 2: Architectural Hardening (15 - 60 Days)
        if has_tool_abuse:
            items.append(RoadmapItem(
                phase="Phase 2: Architectural Hardening (15-60 days)",
                priority="P1",
                title="Enforce Principle of Least Privilege (PoLP) on Agent Tools",
                description="Scope tool capabilities to read-only endpoints and mandate Human-In-The-Loop (HITL) step-up authentication for refunds and modifications.",
                affected_owasp_or_standard="OWASP LLM06 / ISO-A.8.2",
                estimated_hours=35,
                difficulty="Medium",
                expected_compliance_gain=15.0
            ))

        if has_prompt_leak:
            items.append(RoadmapItem(
                phase="Phase 2: Architectural Hardening (15-60 days)",
                priority="P2",
                title="System Prompt Sandwiching & Boundary Tag Enforcement",
                description="Enclose core instructions in non-overridable boundary delimiters with anti-leak meta-rules.",
                affected_owasp_or_standard="OWASP LLM07 / NIST-PR.DS-01",
                estimated_hours=14,
                difficulty="Low",
                expected_compliance_gain=7.5
            ))

        # Phase 3: Governance & Continuous Assurance (60 - 180 Days)
        items.append(RoadmapItem(
            phase="Phase 3: Governance & Continuous Assurance (60-180 days)",
            priority="P2",
            title="Integrate Automated Red Teaming into CI/CD DevSecOps Pipeline",
            description="Run regression audits against OWASP LLM attack suite on every prompt update or model version deployment.",
            affected_owasp_or_standard="NIST AI RMF MEASURE-2.6 / ISO-A.5.8",
            estimated_hours=40,
            difficulty="Medium",
            expected_compliance_gain=10.0
        ))

        items.append(RoadmapItem(
            phase="Phase 3: Governance & Continuous Assurance (60-180 days)",
            priority="P2",
            title="Establish Formal AI Risk Committee & Continuous SIEM Audit Logging",
            description="Conduct quarterly model risk assessments and stream agent inference traces to enterprise SIEM for anomaly detection.",
            affected_owasp_or_standard="NIST-GV.OC-01 / AI-RMF-GOVERN-1.2",
            estimated_hours=50,
            difficulty="High",
            expected_compliance_gain=8.0
        ))

        self.log(audit_id, "Remediation Roadmap Formulation", f"Generated {len(items)} prioritized remediation items across 3 phases.")
        return items

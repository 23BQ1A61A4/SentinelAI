"""
Policy Agent: Parses and structures enterprise AI policies and system governance constraints
"""

import json
from typing import Dict, Any, List
try:
    from agents.base_agent import BaseAgent
    from database.models import AuditTarget
except (ImportError, ValueError):
    from .base_agent import BaseAgent
    from ..database.models import AuditTarget

class PolicyAgent(BaseAgent):
    def __init__(self, llm_client=None):
        super().__init__(
            name="Policy Agent",
            role="AI Governance & Policy Parser",
            description="Analyzes enterprise security policies, system prompts, tool permissions, and maps data sensitivity.",
            llm_client=llm_client
        )

    def execute(self, audit_id: str, target: AuditTarget) -> Dict[str, Any]:
        """
        Parses the target configuration and extracts security policy constraints.
        """
        prompt = (
            f"Analyze the following enterprise LLM system specification and extract key security boundaries:\n\n"
            f"System Name: {target.name}\n"
            f"System Prompt: {target.system_prompt}\n"
            f"Data Sensitivity: {target.data_sensitivity}\n"
            f"Has Tool Access: {target.has_tool_access}\n"
            f"Integrated Tools: {', '.join(target.tools)}\n"
            f"Custom Policies: {target.custom_policies}\n"
            f"Applied Standards: {', '.join(target.applied_standards)}\n\n"
            f"Provide a structured assessment of operational boundaries, critical data assets, and high-risk vectors."
        )

        response = self.llm.generate(
            prompt=prompt,
            system_instruction="You are an enterprise AI Governance & Policy Auditor. Return clear operational security constraints."
        )

        analysis = {
            "target_id": target.id,
            "target_name": target.name,
            "is_high_risk_tier": target.data_sensitivity in ["Confidential / PII", "Restricted / Banking", "Secret"],
            "tool_risk_level": "HIGH" if (target.has_tool_access and len(target.tools) > 0) else "LOW",
            "active_constraints": [
                "Strict PII Redaction Required",
                "Tool Authorization Checks Required",
                "System Prompt Integrity Required",
                "Delimiters Separation Required"
            ],
            "governance_summary": response[:300] + "..." if len(response) > 300 else response
        }

        self.log(audit_id, "Policy Ingestion & Analysis", f"Parsed boundaries for {target.name}. High Risk: {analysis['is_high_risk_tier']}")
        return analysis

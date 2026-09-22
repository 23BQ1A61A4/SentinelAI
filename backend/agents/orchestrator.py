"""
Master Multi-Agent Audit Orchestrator: Coordinates DAG Pipeline Execution Across All 12 Agents
"""

import uuid
import logging
from datetime import datetime
from typing import Optional, Dict, Any

try:
    from database.models import AuditTarget, AuditReport
    from database.db import get_db
    from core.llm_client import LLMClient
    from agents.policy_agent import PolicyAgent
    from agents.red_team_agent import RedTeamAgent
    from agents.blue_team_agent import BlueTeamAgent
    from agents.debate_agent import DebateAgent
    from agents.judge_agent import JudgeAgent
    from agents.compliance_agent import ComplianceAgent
    from agents.risk_agent import RiskAgent
    from agents.decision_agent import DecisionAgent
    from agents.forecast_agent import ForecastAgent
    from agents.roadmap_agent import RoadmapAgent
    from agents.report_agent import ReportAgent
    from agents.memory_agent import MemoryAgent
except (ImportError, ValueError):
    from ..database.models import AuditTarget, AuditReport
    from ..database.db import get_db
    from ..core.llm_client import LLMClient
    from .policy_agent import PolicyAgent
    from .red_team_agent import RedTeamAgent
    from .blue_team_agent import BlueTeamAgent
    from .debate_agent import DebateAgent
    from .judge_agent import JudgeAgent
    from .compliance_agent import ComplianceAgent
    from .risk_agent import RiskAgent
    from .decision_agent import DecisionAgent
    from .forecast_agent import ForecastAgent
    from .roadmap_agent import RoadmapAgent
    from .report_agent import ReportAgent
    from .memory_agent import MemoryAgent

logger = logging.getLogger(__name__)

class AuditOrchestrator:
    """Master workflow orchestrator managing collaborative multi-agent reasoning."""

    def __init__(self, api_key: Optional[str] = None):
        self.llm_client = LLMClient(api_key=api_key)
        self.db = get_db()

        # Instantiate all 12 specialized agents
        self.policy_agent = PolicyAgent(self.llm_client)
        self.red_team_agent = RedTeamAgent(self.llm_client)
        self.blue_team_agent = BlueTeamAgent(self.llm_client)
        self.debate_agent = DebateAgent(self.llm_client)
        self.judge_agent = JudgeAgent(self.llm_client)
        self.compliance_agent = ComplianceAgent(self.llm_client)
        self.risk_agent = RiskAgent(self.llm_client)
        self.decision_agent = DecisionAgent(self.llm_client)
        self.forecast_agent = ForecastAgent(self.llm_client)
        self.roadmap_agent = RoadmapAgent(self.llm_client)
        self.report_agent = ReportAgent(self.llm_client)
        self.memory_agent = MemoryAgent(self.llm_client)

    def run_full_audit(self, target: AuditTarget) -> AuditReport:
        """
        Executes end-to-end multi-agent security & compliance audit pipeline.
        """
        audit_id = f"AUDIT-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        logger.info(f"=== STARTING MULTI-AGENT AUDIT PIPELINE: {audit_id} for '{target.name}' ===")

        # Step 1: Policy Agent
        policy_analysis = self.policy_agent.execute(audit_id, target)

        # Step 2: Red Team Agent
        raw_vulnerabilities = self.red_team_agent.execute(audit_id, target)

        # Step 3: Blue Team Agent
        blue_defenses = self.blue_team_agent.execute(audit_id, raw_vulnerabilities)

        # Step 4: Debate Agent
        debates = self.debate_agent.execute(audit_id, raw_vulnerabilities, blue_defenses)

        # Step 5: Judge Agent
        verified_vulnerabilities = self.judge_agent.execute(audit_id, raw_vulnerabilities, debates)

        # Step 6: Compliance Agent
        compliance_controls = self.compliance_agent.execute(
            audit_id, target, policy_analysis, verified_vulnerabilities
        )

        # Calculate aggregated scores
        total_attacks = len(verified_vulnerabilities)
        exploited_vulns = [v for v in verified_vulnerabilities if v.is_exploitable]
        vulns_count = len(exploited_vulns)
        critical_count = sum(1 for v in exploited_vulns if v.severity == "CRITICAL")
        high_count = sum(1 for v in exploited_vulns if v.severity == "HIGH")
        med_count = sum(1 for v in exploited_vulns if v.severity == "MEDIUM")
        low_count = sum(1 for v in exploited_vulns if v.severity == "LOW")

        # Security Score (100 - weighted vuln deductions)
        security_score = max(10.0, 100.0 - (critical_count * 30.0 + high_count * 15.0 + med_count * 5.0))
        
        # Compliance Score (average of evaluated control scores)
        if compliance_controls:
            compliance_score = sum(c.score for c in compliance_controls) / len(compliance_controls)
        else:
            compliance_score = 75.0

        # Step 7: Risk Agent
        risk_assessment = self.risk_agent.execute(audit_id, verified_vulnerabilities, compliance_controls)

        # Step 8: Decision Agent
        decision = self.decision_agent.execute(audit_id, compliance_score, verified_vulnerabilities, risk_assessment)

        # Step 9: Forecast Agent
        forecast = self.forecast_agent.execute(audit_id, compliance_score, security_score, verified_vulnerabilities)

        # Step 10: Roadmap Agent
        roadmap = self.roadmap_agent.execute(audit_id, verified_vulnerabilities, compliance_controls)

        # Step 11: Report Agent (Executive Summary & PDF compilation)
        exec_summary = self.report_agent.generate_executive_summary(
            target, compliance_score, security_score, risk_assessment, decision, vulns_count, critical_count
        )

        # Assemble Full Audit Report
        report = AuditReport(
            id=audit_id,
            created_at=created_at,
            target=target,
            overall_compliance_score=round(compliance_score, 1),
            overall_security_score=round(security_score, 1),
            composite_risk_score=round(risk_assessment.composite_risk_score, 1),
            total_attacks_tested=total_attacks,
            vulnerabilities_found=vulns_count,
            critical_vulnerabilities=critical_count,
            high_vulnerabilities=high_count,
            medium_vulnerabilities=med_count,
            low_vulnerabilities=low_count,
            vulnerabilities=verified_vulnerabilities,
            compliance_controls=compliance_controls,
            debate_transcripts=debates,
            risk_assessment=risk_assessment,
            decision=decision,
            forecast=forecast,
            roadmap=roadmap,
            executive_summary=exec_summary,
            pdf_report_path=None
        )

        # Compile PDF Report
        pdf_path = self.report_agent.compile_pdf(report)
        report.pdf_report_path = pdf_path

        # Step 12: Memory Agent / Database persistence
        self.db.save_audit(report)
        logger.info(f"=== AUDIT COMPLETED SUCCESSFULLY: {audit_id} -> Saved to DB & PDF ===")

        return report

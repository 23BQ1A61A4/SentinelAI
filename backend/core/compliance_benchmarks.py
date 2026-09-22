"""
Compliance Standards & Security Framework Benchmarks
Includes ISO/IEC 27001:2022, NIST CSF 2.0, and NIST AI RMF 1.0 Control Catalogs
"""

from typing import List, Dict, Any

COMPLIANCE_STANDARDS_CATALOG: Dict[str, List[Dict[str, Any]]] = {
    "ISO/IEC 27001:2022": [
        {
            "control_id": "ISO-A.5.1",
            "control_title": "Policies for Information Security & AI Governance",
            "category": "Organizational Controls",
            "description": "Information security policy and AI usage guidelines must be defined, approved by management, published, and communicated to relevant personnel.",
            "evaluation_criteria": "Requires documented system prompt boundaries, acceptable AI use policies, and defined classification of sensitive data."
        },
        {
            "control_id": "ISO-A.8.2",
            "control_title": "Privileged Access Rights & Agent Permissions",
            "category": "Technological Controls",
            "description": "Allocation and use of privileged access rights for AI agents and tool integrations must be restricted and controlled.",
            "evaluation_criteria": "Verifies that AI tools do not grant unbounded database execution or financial authorization without role checks."
        },
        {
            "control_id": "ISO-A.8.7",
            "control_title": "Protection Against Adversarial Input & Malware",
            "category": "Technological Controls",
            "description": "Protection against malicious inputs, adversarial prompt injections, and rogue script injection must be implemented.",
            "evaluation_criteria": "Requires prompt injection sanitization filters, regex delimiter defenses, and input length constraints."
        },
        {
            "control_id": "ISO-A.8.12",
            "control_title": "Data Leakage Prevention (DLP) & PII Protection",
            "category": "Technological Controls",
            "description": "Data leakage prevention measures must be applied to systems processing sensitive, customer, or confidential data.",
            "evaluation_criteria": "Requires regex output redaction filters, canary token leakage prevention, and automated masking for SSN/PII."
        },
        {
            "control_id": "ISO-A.8.28",
            "control_title": "Secure AI Development & Guardrail Hardening",
            "category": "Technological Controls",
            "description": "Secure coding and robust guardrail engineering principles must be applied to software and AI systems.",
            "evaluation_criteria": "Verifies implementation of system prompt sandwiching, XML delimitations, and defensive output encoders."
        }
    ],
    "NIST Cybersecurity Framework 2.0 (CSF)": [
        {
            "control_id": "NIST-GV.OC-01",
            "control_title": "Organizational AI Security Strategy",
            "category": "Govern (GV)",
            "description": "The organizational mission, risk appetite, and strategic objectives for AI deployment are understood and informed by security.",
            "evaluation_criteria": "Requires formal alignment between AI deployment goals, risk tolerance, and enterprise policy constraints."
        },
        {
            "control_id": "NIST-ID.RA-01",
            "control_title": "Threat & Vulnerability Assessment for LLMs",
            "category": "Identify (ID)",
            "description": "Vulnerabilities and adversarial threats to AI systems are identified, validated, and recorded.",
            "evaluation_criteria": "Evaluates automated adversarial red teaming against OWASP Top 10 for LLMs and regular audit logs."
        },
        {
            "control_id": "NIST-PR.DS-01",
            "control_title": "Data Security & Confidentiality at Rest and in Inference",
            "category": "Protect (PR)",
            "description": "Confidentiality, integrity, and availability of data processed by LLM systems are maintained.",
            "evaluation_criteria": "Checks that sensitive prompts and system prompt tokens cannot be exfiltrated by unauthenticated users."
        },
        {
            "control_id": "NIST-DE.AE-01",
            "control_title": "Anomaly & Adversarial Prompt Detection",
            "category": "Detect (DE)",
            "description": "Potentially adverse events and jailbreak attempts are analyzed to understand attack targets and methods.",
            "evaluation_criteria": "Requires monitoring for jailbreak keywords, anomalous token spikes, and repeated injection patterns."
        },
        {
            "control_id": "NIST-RS.MI-01",
            "control_title": "Automated Guardrail Response & Incident Mitigation",
            "category": "Respond (RS)",
            "description": "Incidents and exploited vulnerabilities are contained and mitigated.",
            "evaluation_criteria": "Verifies that detected attack payloads trigger immediate fallback safely without disclosing internal error traces."
        }
    ],
    "NIST AI Risk Management Framework (AI RMF 1.0)": [
        {
            "control_id": "AI-RMF-GOVERN-1.2",
            "control_title": "AI System Accountability & Transparency",
            "category": "Govern",
            "description": "Clear policies, procedures, and accountability metrics are established for the AI system lifecycle.",
            "evaluation_criteria": "Requires clear audit logs, explainable decision traces, and documented human oversight mechanisms."
        },
        {
            "control_id": "AI-RMF-MAP-1.1",
            "control_title": "Contextual Risk & Failure Mode Mapping",
            "category": "Map",
            "description": "Intended purpose, deployment context, and potential societal/security harms of the AI system are mapped.",
            "evaluation_criteria": "Requires cataloging potential failure modes like hallucination, bias, and unauthorized tool invocation."
        },
        {
            "control_id": "AI-RMF-MEASURE-2.6",
            "control_title": "Robustness, Security & Adversarial Red-Teaming",
            "category": "Measure",
            "description": "The AI system is rigorously tested against adversarial inputs, prompt attacks, and edge cases.",
            "evaluation_criteria": "Requires quantifiable test pass rates against known jailbreaks and injection vectors."
        },
        {
            "control_id": "AI-RMF-MANAGE-1.3",
            "control_title": "Risk Prioritization & Remediation Controls",
            "category": "Manage",
            "description": "Identified AI risks are prioritized and mitigated through actionable technical and organizational controls.",
            "evaluation_criteria": "Requires prioritized remediation roadmaps and continuous compliance tracking."
        }
    ]
}

def get_controls_for_standards(standards: List[str]) -> List[Dict[str, Any]]:
    """Retrieve all controls matching the selected standards."""
    controls = []
    for std in standards:
        if std in COMPLIANCE_STANDARDS_CATALOG:
            for item in COMPLIANCE_STANDARDS_CATALOG[std]:
                item_copy = item.copy()
                item_copy["standard"] = std
                controls.append(item_copy)
    return controls

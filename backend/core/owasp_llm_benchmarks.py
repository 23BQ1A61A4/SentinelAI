"""
OWASP Top 10 for LLM Applications (2025 Standard Taxonomy & Evaluation Definitions)
"""

from typing import Dict, List, Any

OWASP_LLM_TAXONOMY: Dict[str, Dict[str, Any]] = {
    "LLM01": {
        "id": "LLM01",
        "title": "Prompt Injection & Jailbreaking",
        "description": "Crafted prompts bypass system guardrails, altering LLM behavior via direct jailbreaking, DAN personas, or indirect prompt injections.",
        "cvss_base": 8.8,
        "default_severity": "CRITICAL",
        "mitigations": [
            "Implement multi-layered input sanitization with regex delimiter checks.",
            "Utilize defensive system prompt sandwiching and XML tag constraints.",
            "Separate untrusted user input from core system instructions using structural markers."
        ]
    },
    "LLM02": {
        "id": "LLM02",
        "title": "Sensitive Information Disclosure",
        "description": "The LLM exposes confidential information, customer PII, internal passwords, API keys, or proprietary training secrets in its outputs.",
        "cvss_base": 8.2,
        "default_severity": "HIGH",
        "mitigations": [
            "Deploy deterministic regex output scrubbers for SSN, credit cards, and API tokens.",
            "Anonymize or mask PII before passing context to the inference engine.",
            "Strictly enforce output guardrails with automated redaction."
        ]
    },
    "LLM03": {
        "id": "LLM03",
        "title": "Supply Chain & Dependency Vulnerabilities",
        "description": "Vulnerabilities in underlying third-party base models, fine-tuning datasets, embedding models, or agent plugin packages.",
        "cvss_base": 7.5,
        "default_severity": "HIGH",
        "mitigations": [
            "Verify cryptographic hashes and signatures for all foundational model weights.",
            "Maintain an updated Software Bill of Materials (SBOM) for AI components.",
            "Perform vulnerability scanning on all agent dependencies and third-party tools."
        ]
    },
    "LLM04": {
        "id": "LLM04",
        "title": "Data and Model Poisoning",
        "description": "Adversarial corruption of fine-tuning corpora or knowledge retrieval vector stores, introducing backdoors or malicious biases.",
        "cvss_base": 7.3,
        "default_severity": "HIGH",
        "mitigations": [
            "Validate and digitally sign RAG documents prior to vector embedding ingestion.",
            "Implement strict role-based access control (RBAC) on document repositories.",
            "Monitor knowledge store embeddings for anomalous vector clusters."
        ]
    },
    "LLM05": {
        "id": "LLM05",
        "title": "Improper Output Handling",
        "description": "Downstream systems blindly execute or render raw LLM outputs without sanitization, leading to XSS, SQLi, or Code Injection.",
        "cvss_base": 8.5,
        "default_severity": "CRITICAL",
        "mitigations": [
            "Treat all LLM output as untrusted user input before passing to client UI or shell.",
            "Apply contextual output encoding (HTML, JavaScript, SQL parameters).",
            "Disallow direct shell command execution from raw LLM string returns."
        ]
    },
    "LLM06": {
        "id": "LLM06",
        "title": "Excessive Agency & Privilege Escalation",
        "description": "The LLM agent possesses excessive tool permissions, broad API access, or autonomous execution rights beyond intended operational boundaries.",
        "cvss_base": 8.6,
        "default_severity": "CRITICAL",
        "mitigations": [
            "Implement the Principle of Least Privilege (PoLP) on all agent function calls.",
            "Require Human-in-the-Loop (HITL) authorization for critical state-changing actions (e.g. money transfer, db deletion).",
            "Scope API tokens to specific read-only capabilities where possible."
        ]
    },
    "LLM07": {
        "id": "LLM07",
        "title": "System Prompt & Configuration Leakage",
        "description": "Adversaries extract underlying system prompts, business logic rules, canary tokens, or security guardrail definitions.",
        "cvss_base": 6.5,
        "default_severity": "MEDIUM",
        "mitigations": [
            "Instruct system prompts with meta-rules disallowing repetition of initial setup commands.",
            "Filter output for verbatim system prompt substrings.",
            "Avoid placing sensitive secrets or raw access tokens in the system prompt."
        ]
    },
    "LLM08": {
        "id": "LLM08",
        "title": "Vector & Embedding Inversion Weaknesses",
        "description": "Vulnerabilities in RAG architectures allowing reconstruction of private source documents or context pollution through similarity manipulation.",
        "cvss_base": 6.8,
        "default_severity": "MEDIUM",
        "mitigations": [
            "Isolate tenant vector indexes using namespace segmentation.",
            "Enforce document-level access filtering during vector retrieval.",
            "Audit semantic similarity thresholds to prevent context bleeding."
        ]
    },
    "LLM09": {
        "id": "LLM09",
        "title": "Misinformation, Hallucination & Overreliance",
        "description": "The model generates convincing yet factually false, ungrounded, or hazardous recommendations that users blindly accept.",
        "cvss_base": 6.0,
        "default_severity": "MEDIUM",
        "mitigations": [
            "Incorporate RAG citations with verifiable source URLs and confidence scores.",
            "Add prominent AI advisory disclaimers on critical business outputs.",
            "Implement cross-model fact-checking and automated ground truth validation."
        ]
    },
    "LLM10": {
        "id": "LLM10",
        "title": "Unbounded Consumption & Resource Starvation",
        "description": "Adversaries craft resource-heavy recursive queries or context-stuffing payloads that exhaust compute tokens or induce Denial of Service.",
        "cvss_base": 6.2,
        "default_severity": "MEDIUM",
        "mitigations": [
            "Enforce strict input length and token limit rate quotas per user session.",
            "Implement timeout ceilings and dynamic budget limits on LLM API calls.",
            "Deploy Web Application Firewall (WAF) rate limiting on LLM endpoints."
        ]
    }
}

def get_owasp_category(owasp_id: str) -> Dict[str, Any]:
    return OWASP_LLM_TAXONOMY.get(owasp_id, {
        "id": owasp_id,
        "title": "Unknown AI Security Category",
        "description": "General AI vulnerability",
        "cvss_base": 5.0,
        "default_severity": "MEDIUM",
        "mitigations": ["Apply general defense-in-depth practices."]
    })

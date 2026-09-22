"""
Global Configuration for Agentic AI-Based Smart Compliance Auditor & AI Security Validation Platform
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "database" / "compliance_auditor.db"))
REPORTS_DIR = BASE_DIR / "generated_reports"
REPORTS_DIR.mkdir(exist_ok=True)

# AI & API Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
USE_OFFLINE_FALLBACK_IF_NO_KEY = True

# Security & Compliance Thresholds
RISK_THRESHOLD_CRITICAL = 80.0
RISK_THRESHOLD_HIGH = 60.0
RISK_THRESHOLD_MEDIUM = 40.0
RISK_THRESHOLD_LOW = 20.0

MINIMUM_COMPLIANCE_SCORE_FOR_APPROVAL = 75.0
MAXIMUM_ALLOWABLE_CRITICAL_VULNS = 0
MAXIMUM_ALLOWABLE_HIGH_VULNS = 2

# Server Configuration
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8000"))
STREAMLIT_PORT = int(os.getenv("STREAMLIT_PORT", "8501"))

# Standard Taxonomy Definitions
SUPPORTED_STANDARDS = [
    "ISO/IEC 27001:2022",
    "NIST Cybersecurity Framework 2.0 (CSF)",
    "NIST AI Risk Management Framework (AI RMF 1.0)",
    "OWASP Top 10 for LLM Applications 2025"
]

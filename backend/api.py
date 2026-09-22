"""
FastAPI REST API Gateway for Agentic Compliance Auditor Platform
Provides headless microservice endpoints for DevSecOps & CI/CD pipeline automation
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

try:
    from config import API_HOST, API_PORT, GEMINI_API_KEY
    from database.models import AuditTarget, AuditReport
    from database.db import get_db
    from agents.orchestrator import AuditOrchestrator
    from agents.memory_agent import MemoryAgent
    from core.owasp_llm_benchmarks import OWASP_LLM_TAXONOMY
    from core.compliance_benchmarks import COMPLIANCE_STANDARDS_CATALOG
    from core.red_team_payloads import get_all_payloads
except (ImportError, ValueError):
    from .config import API_HOST, API_PORT, GEMINI_API_KEY
    from .database.models import AuditTarget, AuditReport
    from .database.db import get_db
    from .agents.orchestrator import AuditOrchestrator
    from .agents.memory_agent import MemoryAgent
    from .core.owasp_llm_benchmarks import OWASP_LLM_TAXONOMY
    from .core.compliance_benchmarks import COMPLIANCE_STANDARDS_CATALOG
    from .core.red_team_payloads import get_all_payloads

app = FastAPI(
    title="Agentic Compliance Auditor & AI Security Validation API",
    description="Enterprise Multi-Agent Platform for ISO 27001 / NIST Compliance & OWASP LLM Adversarial Validation",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = get_db()
orchestrator = AuditOrchestrator(api_key=GEMINI_API_KEY)
memory_agent = MemoryAgent()

@app.get("/")
def root():
    return {
        "status": "online",
        "platform": "Agentic AI Compliance Auditor & AI Security Validation Platform",
        "version": "1.0.0",
        "agents_active": 12,
        "docs_url": "/docs"
    }

@app.post("/api/audit/run", response_model=AuditReport)
def run_audit(target: AuditTarget):
    """
    Triggers a full 12-agent collaborative compliance and security audit on the specified LLM application.
    """
    try:
        report = orchestrator.run_full_audit(target)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit execution error: {str(e)}")

@app.get("/api/audit/{audit_id}", response_model=AuditReport)
def get_audit(audit_id: str):
    """
    Fetches a saved audit report by its unique ID.
    """
    report = db.get_audit(audit_id)
    if not report:
        raise HTTPException(status_code=404, detail="Audit report not found.")
    return report

@app.get("/api/audit/{audit_id}/pdf")
def download_pdf(audit_id: str):
    """
    Downloads the executive PDF audit report.
    """
    report = db.get_audit(audit_id)
    if not report or not report.pdf_report_path or not os.path.exists(report.pdf_report_path):
        raise HTTPException(status_code=404, detail="PDF report not found or not yet generated.")
    return FileResponse(
        path=report.pdf_report_path,
        filename=os.path.basename(report.pdf_report_path),
        media_type="application/pdf"
    )

@app.get("/api/audits")
def list_audits(limit: int = 50):
    """
    Lists historical audit summaries stored in SQLite.
    """
    return db.list_audits(limit=limit)

@app.post("/api/audits/compare")
def compare_audits(payload: Dict[str, str]):
    """
    Compares two historical audit runs and computes security drift and delta metrics.
    """
    id_a = payload.get("audit_id_a")
    id_b = payload.get("audit_id_b")
    if not id_a or not id_b:
        raise HTTPException(status_code=400, detail="Both 'audit_id_a' and 'audit_id_b' are required.")
    
    diff = memory_agent.compare_audits(id_a, id_b)
    if "error" in diff:
        raise HTTPException(status_code=404, detail=diff["error"])
    return diff

@app.get("/api/benchmarks/owasp")
def get_owasp_taxonomy():
    """
    Returns full OWASP Top 10 for LLM Applications (2025) taxonomy.
    """
    return OWASP_LLM_TAXONOMY

@app.get("/api/benchmarks/compliance")
def get_compliance_catalog():
    """
    Returns ISO 27001:2022, NIST CSF 2.0, and NIST AI RMF 1.0 control standards.
    """
    return COMPLIANCE_STANDARDS_CATALOG

@app.get("/api/benchmarks/payloads")
def get_attack_payloads():
    """
    Returns curated library of red team attack vectors.
    """
    return get_all_payloads()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)

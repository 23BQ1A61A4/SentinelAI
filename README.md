# 🛡️ SentinelAI: Agentic AI-Based Smart Compliance Auditor & AI Security Validation Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32.0-FF4B4B.svg)](https://streamlit.io)
[![OWASP LLM 2025](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange.svg)](https://owasp.org)
[![ISO/IEC 27001](https://img.shields.io/badge/Compliance-ISO%2F举27001%20%7C%20NIST%20AI%20RMF-green.svg)](https://www.iso.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Final Year Major Project**  
> **Department:** Computer Science and Engineering (Artificial Intelligence & Machine Learning)  
> **Institution:** Vasireddy Venkatadri Institute of Technology (VVIT), JNTUK  

---

## 📌 Overview

**SentinelAI** is an autonomous **Multi-Agent Cybersecurity Compliance Auditor and Adversarial Security Validation Platform** engineered for Enterprise Large Language Model (LLM) applications.

The platform bridges the gap between regulatory governance (**ISO/IEC 27001:2022, NIST CSF 2.0, NIST AI RMF 1.0**) and technical AI security (**OWASP Top 10 for LLM Applications 2025**) through a collaborative **12-Agent Directed Acyclic Graph (DAG) architecture**.

---

## 🌟 Key Features

- 🤖 **12 Specialized AI Agents:** Policy, Red Team, Blue Team, Debate, Judge, Compliance, Risk, Decision, Forecast, Roadmap, Memory, and Report Agents.
- ⚔️ **Live Red vs. Blue Deliberation Arena:** Multi-round adversarial debate where Red Team argues exploitability and Blue Team presents defense feasibility, adjudicated by an impartial Judge Agent.
- 🎯 **Interactive Red-Teaming Playground:** Test real-time adversarial payloads (Prompt Injection, DAN Jailbreaks, Canary/PII extraction, SQL tool manipulation).
- 📋 **Multi-Standard Compliance Matrix:** Comprehensive evaluation against ISO/IEC 27001 Annex A controls, NIST CSF 2.0, and NIST AI RMF 1.0.
- ⚠️ **Multi-Dimensional Enterprise Risk Engine:** Quantitative impact modeling across Financial, Regulatory, Reputational, and Operational dimensions.
- 📈 **180-Day Predictive Compliance Forecasting:** Time-series projection comparing baseline drift vs with-remediation score trajectories.
- 🗺️ **Phased Remediation Roadmap:** Prioritized P0/P1/P2 engineering milestones with estimated hours and score deltas.
- 📄 **CISO-Grade PDF Dossier Export:** Downloadable executive reports generated via ReportLab with tables, scorecards, and sign-off blocks.
- ⚡ **Dual-Mode Engine:** Runs seamlessly with **Google Gemini API** (`google-genai`) or deterministic **offline heuristic fallback** (100% reliable for live presentations/vivas).

---

## 🏗️ System Architecture

```
                                  [Target LLM Application Config]
                                                │
                                                ▼
                                      [1. Policy Agent]
                                                │
                                ┌───────────────┴───────────────┐
                                ▼                               ▼
                      [2. Red Team Agent]             [3. Blue Team Agent]
                      (Simulates OWASP Attacks)       (Formulates Guardrails)
                                │                               │
                                └───────────────┬───────────────┘
                                                ▼
                                        [4. Debate Agent]
                                   (Red vs. Blue Deliberations)
                                                │
                                                ▼
                                        [5. Judge Agent]
                                   (CVSS Scoring & Verification)
                                                │
                                ┌───────────────┴───────────────┐
                                ▼                               ▼
                      [6. Compliance Agent]           [7. Risk Agent]
                      (ISO 27001 & NIST Check)        (Business Impact Model)
                                │                               │
                                └───────────────┬───────────────┘
                                                ▼
                                       [8. Decision Agent]
                                   (CISO Deployment Gatekeeper)
                                                │
                                ┌───────────────┼───────────────┐
                                ▼               ▼               ▼
                      [9. Forecast Agent] [10. Roadmap]   [11. Memory & 12. Report]
                      (180-Day ML Trend)  (Phased Milestones) (SQLite & PDF Compiler)
```

---

## 📁 Repository Structure

```
SentinelAI/
├── backend/
│   ├── agents/                     # 12 Specialized AI agents & orchestrator
│   ├── core/                       # LLM client, OWASP benchmarks, PDF generator, guardrails
│   ├── database/                   # SQLite database engine, migrations & schemas
│   ├── api.py                      # FastAPI REST API microservice
│   └── config.py                   # Platform configuration
├── frontend/
│   └── __init__.py                 # Frontend modules
├── knowledge_base/
│   ├── iso_27001_standards.json    # ISO 27001 benchmark catalog
│   ├── nist_ai_rmf_controls.json   # NIST AI RMF governance controls
│   └── owasp_llm_2025_vectors.json # OWASP LLM 2025 attack taxonomy
├── app.py                          # Streamlit UI Interactive Web Dashboard
├── run.py                          # Universal Python launcher
├── requirements.txt                # Dependencies specification
├── .env.example                    # Sample environment variables
├── .gitignore                      # Git ignore rules
├── AGENTS.md                       # Comprehensive 12-Agent Documentation
├── LICENSE                         # MIT License
└── README.md                       # Project Documentation
```

---

## 🚀 Quickstart Guide

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/23BQ1A61A4/SentinelAI.git
cd SentinelAI

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
Copy `.env.example` to `.env` to configure your Google Gemini API key (or leave empty to run in offline heuristic mode):
```bash
cp .env.example .env
```

### 3. Launch the Platform

#### Option A: Launch Streamlit Web UI (Default)
```bash
python run.py --mode ui
# Or directly:
streamlit run app.py
```
> Open **`http://localhost:8501`** in your browser.

#### Option B: Launch FastAPI REST Microservice
```bash
python run.py --mode api
# Or directly:
python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload
```
> Interactive Swagger API docs available at **`http://127.0.0.1:8000/docs`**.

#### Option C: Launch Both Simultaneously
```bash
python run.py --mode all
```

---

## 🧪 Automated Testing

Run the test suite covering all 12 agents, compliance matrices, red teaming vectors, and API endpoints:
```bash
python -m unittest discover -s backend/tests -p "test_*.py"
```

---

## 📚 Academic Citations & Literature Base

1. **Perez, E., et al. (2023).** *Red Teaming Language Models with Language Models.* In *ACL 2023*. (Base Paper)
2. **OWASP Foundation (2025).** *OWASP Top 10 for Large Language Model Applications (v2.0).*
3. **NIST (2024).** *Artificial Intelligence Risk Management Framework (NIST AI RMF 1.0).* NIST SP 1270.
4. **ISO/IEC (2023).** *ISO/IEC 27001:2022 Information Security Management Systems.*
5. **Greshake, K., et al. (2023).** *Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* In *ACM AISEC 2023*.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

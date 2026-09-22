# SentinelAI: Multi-Agent Architecture & Agent Specifications

SentinelAI utilizes an autonomous **12-Agent Directed Acyclic Graph (DAG) Pipeline** to deliver end-to-end cybersecurity compliance auditing and adversarial red-teaming for Enterprise Large Language Model (LLM) applications.

---

## 1. Multi-Agent Topology & Deliberation Flow

```
[Target LLM Application Config]
              │
              ▼
    [1. Policy Agent]  ───────────────► Ingests system prompt, tools & sensitivity
              │
              ├─────────────────────────────────┐
              ▼                                 ▼
    [2. Red Team Agent]               [3. Blue Team Agent]
    (Executes OWASP Attacks)          (Synthesizes Guardrails)
              │                                 │
              └──────────────┬──────────────────┘
                             ▼
                     [4. Debate Agent]
                (Red vs. Blue Deliberation)
                             │
                             ▼
                     [5. Judge Agent]
                (CVSS Scoring & Verification)
                             │
              ┌──────────────┴──────────────────┐
              ▼                                 ▼
    [6. Compliance Agent]             [7. Risk Agent]
    (ISO 27001 & NIST Check)          (Financial/Reputational/Legal)
              │                                 │
              └──────────────┬──────────────────┘
                             ▼
                    [8. Decision Agent] ──► Release Gate (Approved/Blocked)
                             │
              ┌──────────────┼──────────────────┐
              ▼              ▼                  ▼
    [9. Forecast Agent] [10. Roadmap Agent] [11. Memory Agent & 12. Report Agent]
    (180-Day ML Score)  (Phased Milestones) (SQLite Retention & CISO PDF Dossier)
```

---

## 2. The 12 Specialized AI Agents

### 1. 📜 Policy Agent (`backend/agents/policy_agent.py`)
- **Role:** Enterprise Governance & Specification Parser
- **Function:** Ingests target system prompts, tool interfaces, data classifications (Confidential/PII/Restricted), and custom security constraints to derive evaluation boundaries.

### 2. 🔴 Red Team Agent (`backend/agents/red_team_agent.py`)
- **Role:** Adversarial AI Security Penetration Tester
- **Function:** Simulates 10+ adversarial attack classes from OWASP Top 10 for LLMs (Direct Prompt Injection, DAN Jailbreaks, Canary/PII extraction, SQL tool injection, and System Prompt Leakage).

### 3. 🔵 Blue Team Agent (`backend/agents/blue_team_agent.py`)
- **Role:** Defensive Engineer & Guardrail Architect
- **Function:** Formulates tactical input sanitizers, regex DLP filters, system prompt sandwiching, and Principle of Least Privilege (PoLP) tool rules.

### 4. ⚔️ Debate Agent (`backend/agents/debate_agent.py`)
- **Role:** Red-Blue Deliberation Coordinator
- **Function:** Coordinates dynamic multi-turn debate rounds between Red Team (arguing exploitability and severity) and Blue Team (arguing defense feasibility and residual risk).

### 5. ⚖️ Judge Agent (`backend/agents/judge_agent.py`)
- **Role:** Impartial Evaluator & CVSS 3.1 Scorer
- **Function:** Evaluates debate transcripts objectively, eliminates false-positive findings, and assigns authoritative CVSS severity ratings (Critical, High, Medium, Low).

### 6. 📋 Compliance Agent (`backend/agents/compliance_agent.py`)
- **Role:** Regulatory & Standard Compliance Auditor
- **Function:** Evaluates technical controls against **ISO/IEC 27001:2022** (Annex A), **NIST CSF 2.0**, and **NIST AI RMF 1.0** (Govern, Map, Measure, Manage).

### 7. ⚠️ Risk Agent (`backend/agents/risk_agent.py`)
- **Role:** Enterprise Risk & Business Impact Modeler
- **Function:** Computes quantitative risk scores across Financial, Regulatory, Reputational, and Operational dimensions ($Risk = \sum w_i \cdot S_i$).

### 8. 🛡️ Decision Agent (`backend/agents/decision_agent.py`)
- **Role:** CISO Release Authority & Deployment Gatekeeper
- **Function:** Synthesizes multi-agent findings into an authoritative gatekeeper determination: `APPROVED`, `CONDITIONAL_RELEASE`, or `BLOCKED`.

### 9. 📈 Forecast Agent (`backend/agents/forecast_agent.py`)
- **Role:** Predictive Compliance & Trend Modeler
- **Function:** Projects 30, 60, 90, and 180-day compliance score trajectories under baseline (drift) vs with-remediation pathways.

### 10. 🗺️ Roadmap Agent (`backend/agents/roadmap_agent.py`)
- **Role:** Remediation & Engineering Roadmap Architect
- **Function:** Constructs phased engineering milestones (Phase 1: Hotfixes, Phase 2: Architectural Hardening, Phase 3: Continuous Assurance) with estimated hours and score deltas.

### 11. 🕰️ Memory Agent (`backend/agents/memory_agent.py`)
- **Role:** Audit Memory & Security Drift Tracker
- **Function:** Maintains historical SQLite audit logs, computes cross-run deltas ($\Delta$), and tracks resolved vulnerabilities vs newly introduced regressions.

### 12. 📄 Report Agent (`backend/agents/report_agent.py`)
- **Role:** Executive Dossier & ReportLab PDF Compiler
- **Function:** Synthesizes executive summaries, technical dossiers, and generates publication-quality PDF audit reports ready for CISO sign-off.

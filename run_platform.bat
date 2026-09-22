@echo off
title Agentic AI Compliance Auditor & AI Security Validation Platform
echo ===============================================================================
echo     AGENTIC AI-BASED SMART COMPLIANCE AUDITOR & AI SECURITY VALIDATION PLATFORM
echo ===============================================================================
echo.
echo [1/2] Starting FastAPI REST Microservice on http://127.0.0.1:8000 ...
start "FastAPI Backend" cmd /k "python -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload"

echo [2/2] Starting Streamlit Web Dashboard on http://localhost:8501 ...
timeout /t 2 /nobreak >nul
python -m streamlit run app.py

pause

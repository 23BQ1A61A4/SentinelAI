"""
SentinelAI Universal Runner: Launches Streamlit Dashboard or FastAPI REST Microservice
"""

import sys
import os
import subprocess
import argparse

def main():
    parser = argparse.ArgumentParser(description="SentinelAI Compliance & Security Auditor Platform")
    parser.add_argument("--mode", choices=["ui", "api", "all"], default="ui", help="Launch mode: ui (Streamlit), api (FastAPI), all (Both)")
    args = parser.parse_args()

    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)

    if args.mode == "ui":
        print("[*] Starting SentinelAI Streamlit Dashboard on http://localhost:8501 ...")
        subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])
    elif args.mode == "api":
        print("[*] Starting SentinelAI FastAPI Backend on http://127.0.0.1:8000 ...")
        subprocess.run([sys.executable, "-m", "uvicorn", "backend.api:app", "--host", "127.0.0.1", "--port", "8000", "--reload"])
    elif args.mode == "all":
        print("[*] Starting FastAPI Backend and Streamlit UI simultaneously...")
        p_api = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.api:app", "--host", "127.0.0.1", "--port", "8000", "--reload"])
        try:
            subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])
        finally:
            p_api.terminate()

if __name__ == "__main__":
    main()

#!/usr/bin/env bash
echo "======================================================================"
echo "   AI-Based Phishing Call Detection and Risk Analyzer"
echo "   2nd-Year B.Tech CSE Cyber Security Mini-Project"
echo "======================================================================"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 could not be found. Please install Python 3.10+."
    exit 1
fi

echo "[INFO] Launching Streamlit dashboard..."
streamlit run app.py

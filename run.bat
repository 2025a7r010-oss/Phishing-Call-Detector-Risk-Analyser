@echo off
title AI-Based Phishing Call Detection and Risk Analyzer
echo ======================================================================
echo    AI-Based Phishing Call Detection and Risk Analyzer
echo    2nd-Year B.Tech CSE Cyber Security Mini-Project
echo ======================================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not added to your PATH.
    echo Please install Python 3.10 or 3.11 from https://www.python.org/
    echo.
    pause
    exit /b 1
)

echo [INFO] Launching Streamlit dashboard...
echo [INFO] Opening web browser at http://localhost:8501
echo.
streamlit run app.py
if errorlevel 1 (
    echo.
    echo [ERROR] Application terminated with an error.
    pause
)

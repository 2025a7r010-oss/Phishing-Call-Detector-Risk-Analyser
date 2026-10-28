# AI-Based Phishing Call Detection and Risk Analyzer

**2nd-Year B.Tech CSE (Cyber Security) College Mini-Project**  
*A transparent, explainable, and local voice phishing (vishing) threat analyzer.*

[![CI Test Suite](https://github.com/2025a7r010-oss/Phishing-Call-Detector-Risk-Analyser/actions/workflows/ci.yml/badge.svg)](https://github.com/2025a7r010-oss/Phishing-Call-Detector-Risk-Analyser/actions/workflows/ci.yml)
![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?logo=streamlit)
![Speech STT](https://img.shields.io/badge/STT-faster--whisper%20(CPU)-green)
![Privacy](https://img.shields.io/badge/Privacy-100%25%20Offline%20Local-success)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📌 Project Overview

Voice phishing (**vishing**) is one of the fastest-growing attack vectors in cybercrime, responsible for millions of dollars in financial theft worldwide. Attackers deploy psychological manipulation, artificial urgency, and impersonation of trusted institutions (banks, law enforcement, telecom) to coerce victims into sharing OTPs, PINs, or installing Remote Access Trojans (RATs) such as AnyDesk.

**AI-Based Phishing Call Detection and Risk Analyzer** is a privacy-first cybersecurity tool designed to ingest call audio recordings, perform local offline speech-to-text transcription via **faster-whisper**, evaluate conversation transcripts against a **rule-based contextual threat engine**, compute an **explainable risk score (0–100)**, and export publication-ready **PDF forensic reports**.

---

## 🚀 Key Features

### 1. Core Capabilities
- **Multi-Format Audio Ingestion:** Supports `WAV`, `MP3`, and `M4A` audio files with safe temporary file destruction and size constraints.
- **Local Speech-to-Text (STT):** Powered by offline `faster-whisper` on CPU using int8 quantization. No audio data ever leaves the local machine.
- **Explainable Rule-Based Threat Engine:** 8 core cybersecurity threat vectors evaluated using contextual regex bigrams.
- **Transparent Mathematical Scoring:** Risk Score (0–100) calculated using base indicator weights plus compounding synergy multipliers.
- **Multi-Tier Risk Classification:**
  - **Low Risk (0–30):** Safe / Likely legitimate customer service interaction.
  - **Medium Risk (31–70):** Suspicious / Financial pressure, unverified fees, or artificial urgency.
  - **High Risk (71–100):** Critical Phishing / Immediate danger, credential theft, AnyDesk, or fake legal threats.
- **Actionable Safety Recommendations:** Dynamic contextual defense advice + official National Cyber Crime Reporting Hotline (**1930** / [cybercrime.gov.in](https://cybercrime.gov.in)).
- **Forensic PDF & TXT Report Generation:** Real PDF reports built with ReportLab featuring threat tables, forensic quotes, and legal disclaimers.

### 2. Modern UI/UX Design
- **Cybersecurity Theme:** Professional dark slate and navy palette with neon status badges and gauge cards.
- **Light / Dark Mode Toggle:** Working instant theme switch (☀️ Light / 🌙 Dark) preserving the active analysis session.
- **Demo Video Walkthrough:** In-app interactive simulator demonstrating the complete data pipeline.
- **Searchable Transcript Viewer:** In-transcript keyword search with color-coded threat excerpt chips.
- **Pre-Loaded Demo Mode:** 3 rich educational scenarios (Normal, Suspicious, Critical Vishing) that work 100% offline without Whisper.
- **Ready-to-Use Audio Samples:** Includes pre-synthesized WAV files in `sample_audio/` for instant audio upload testing.

### 3. Advanced Forensic & Academic Tools
- **SQLite Local Persistence:** Saves case records in `phishing_analysis.db` with search, filter by risk level, and full case re-opening.
- **Multi-Call Comparator:** Side-by-side comparison of 2 calls to contrast attack vectors, scores, and linguistic patterns.
- **Telemetry & Trends Dashboard:** Visualizes risk severity distribution and top detected attack tactics using Altair charts.
- **User Accuracy Feedback:** Rate analyses as "Accurate", "False Positive", or "False Negative" directly in the database.
- **CSV Data Export:** One-click export of complete case history for forensic records or academic submissions.
- **Academic Viva Voce Module:** Includes 10 curated examiner viva questions and detailed answers.

---

## 🏗️ System Architecture & Workflow

```
┌─────────────────────────────────┐
│     Audio Input Ingestion       │ (WAV / MP3 / M4A / Demo Mode)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│       Local Whisper STT         │ (CPU Int8 Quantized, Zero Cloud Egress)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│   Contextual Analysis Engine    │ (8 Threat Vectors, Non-redundant Bigrams)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│   Synergy & Risk Calculation    │ Score = min(100, Base Weights + Synergy)
└────────────────┬────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
┌──────────────┐   ┌──────────────┐
│  SQLite DB   │   │  ReportLab   │ (Forensic PDF & TXT Reports)
└──────────────┘   └──────────────┘
```

---

## 📐 Scoring Formula & Threat Indicators

$$\text{Raw Score} = \sum \text{Base Indicator Weights} + \text{Tactical Synergy Bonus}$$
$$\text{Final Score} = \min(100, \text{Raw Score})$$

### Indicator Categories:
1. **Credential Harvesting (+35 pts, Critical):** Requests for OTP, UPI PIN, ATM PIN, CVV, Net Banking credentials.
2. **Remote Access Hijacking (+30 pts, Critical):** Coercion to install AnyDesk, TeamViewer, QuickSupport, screen sharing.
3. **Psychological Coercion (+25 pts, High):** Fabricated arrest warrants, police FIR, account freezing, power cutoff.
4. **Financial Demands (+25 pts, High):** Demands for payment to 'safe accounts', advance processing fees, gift cards.
5. **Authority Impersonation (+20 pts, High):** Impersonating SBI, RBI, Cyber Crime Cell, Telecom Regulatory Authority.
6. **Victim Isolation & Secrecy (+20 pts, Medium):** 'Do not disconnect', 'do not inform bank branch or family'.
7. **Artificial Urgency (+15 pts, Medium):** 'Within 10 minutes', 'act right now', 'last and final warning'.
8. **Unsolicited Financial Lures (+15 pts, Medium):** Fake lotteries, unclaimed reward points, cashback rebates.

### Tactical Synergy Bonus:
- **Credential Theft + Coercion/Threats:** `+15 pts`
- **Remote Access + Financial Demand:** `+15 pts`
- **Authority Impersonation + Secrecy:** `+10 pts`
- **Artificial Urgency + Advance Fee:** `+10 pts`

---

## 📁 Project Directory Structure

```
Phishing Call Detector & Risk Analyser/
├── app.py                     # Streamlit multi-view cybersecurity dashboard
├── analyzer.py                # Rule-based contextual risk engine & synergy logic
├── transcriber.py             # Local Whisper STT integration & audio validation
├── database.py                # SQLite local persistence, search, stats, CSV export
├── demo_data.py               # Pre-configured demo conversations (Normal, Suspicious, High)
├── report_generator.py        # PDF (ReportLab) and TXT audit report generators
├── sample_audio/              # Demonstration audio directory
│   ├── generate_samples.py    # Speech synthesis generator for sample audio
│   ├── sample_1_normal_delivery.wav
│   ├── sample_2_suspicious_reward.wav
│   └── sample_3_critical_vishing.wav
├── tests/
│   └── test_analyzer.py       # Automated unit tests (Pytest)
├── requirements.txt           # Project dependencies
└── README.md                  # Complete documentation and viva guide
```

---

## 💻 Installation & Setup Instructions

### 1. Prerequisites
- Python 3.10 or 3.11 installed on your system.
- Operating System: Windows, macOS, or Linux.

### 2. Setup Virtual Environment (Recommended)
```bash
# Navigate to the project root directory
cd "C:\Users\HP\Downloads\Phishing Call Detector & Risk Analyser"

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Automated Test Suite
Verify that all unit tests, risk scoring boundaries, database operations, and report generation pass:
```bash
python -m pytest tests/test_analyzer.py -v
```

---

## 🏃 Running the Application

Execute the following command in PowerShell or terminal:

```bash
streamlit run app.py
```

The Streamlit web interface will launch automatically in your default browser at:
`http://localhost:8501`

---

## 🎓 Classroom & Examiner Demonstration Guide

Follow this 5-minute step-by-step walkthrough during your project presentation:

1. **Introduce the Architecture (1 min):**
   - Open the web interface.
   - Point out the cybersecurity theme, theme toggle (☀️ Light / 🌙 Dark), and click **▶ Demo Video** in the top navigation to show the pipeline diagram.
   - Explain that all speech transcription is executed **locally on CPU** with zero third-party cloud data leakage.

2. **Demonstrate Critical Vishing Detection (1.5 min):**
   - Under **🛡️ Call Analysis**, select **⚡ Quick Demo Scenarios (Pre-loaded)**.
   - Choose **Sample 3: Critical Vishing (Bank Fraud Impersonation & Remote Access)**.
   - Click **Run Forensic Analysis**.
   - Show the resulting **High Risk (Score: 100)** score card.
   - Open the **📐 Transparent Scoring Formula** expander to show the examiner exact points breakdown (+35 OTP, +30 AnyDesk, +25 Threats, +15 Synergy).
   - Show the highlighted keywords in the transcript.
   - Click **📄 Download Forensic Report (PDF)** to generate and open the official PDF audit report.

3. **Demonstrate Real Audio Upload with Local Whisper (1 min):**
   - Switch ingestion method to **🎙️ Upload Audio Recording**.
   - Click **Load Sample 3: Critical Bank Vishing (WAV)** under sample audio files.
   - Play the audio in the embedded player so the examiner hears the simulated caller.
   - Click **🚀 Transcribe Audio & Analyze**.
   - Show the live Whisper transcription completion in seconds.

4. **Demonstrate History, Analytics, and Comparator (1 min):**
   - Switch to **📊 Analytics Dashboard**: Show the threat distribution chart and top detected attack tactics.
   - Switch to **⚖️ Multi-Call Comparator**: Select **Call A (Sample 1 Normal)** and **Call B (Sample 3 Critical Vishing)** to visually contrast a benign call against an adversarial attack.

5. **Viva Voce Defense (0.5 min):**
   - Switch to the **🎓 Academic Viva & Docs** tab to address any examiner questions on vishing vectors, caller ID spoofing, or explainable AI vs black-box models.

---

## 🔒 Privacy & Ethical Safeguards

- **Zero Surveillance:** The application does not intercept live calls, record microphones in the background, or tap phone lines. It operates strictly on recordings intentionally provided by the user.
- **No Cloud Egress:** Speech-to-text processing occurs strictly on the local CPU using `faster-whisper`.
- **Heuristic Disclaimer:** The risk score represents a heuristic detection of suspicious patterns for screening and educational purposes; it does not constitute legal proof of fraud.

---

## 📞 Emergency Cyber Incident Response
If you suspect you have been targeted by a financial vishing attack:
- **National Cyber Crime Helpline (India):** Dial **1930** immediately.
- **Online Complaint Portal:** [https://cybercrime.gov.in](https://cybercrime.gov.in)

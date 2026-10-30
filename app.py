"""
app.py - AI-Based Phishing Call Detection & Risk Analyzer
Professional Cybersecurity Risk Analysis Platform
Local Whisper STT & Explainable Rule-Based Threat Engine
"""

import os
import time
import json
import io
import streamlit as st
import pandas as pd
import altair as alt

from analyzer import PhishingAnalyzer
from transcriber import transcribe_audio_file, is_whisper_available
from demo_data import DEMO_CONVERSATIONS, get_demo_by_id
import database
import report_generator

# Page Configuration
st.set_page_config(
    page_title="AI-Based Phishing Call Detection & Risk Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize SQLite database
database.init_db()

# Initialize Session State Variables
if "theme" not in st.session_state:
    st.session_state.theme = "dark"
if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None
if "current_transcript" not in st.session_state:
    st.session_state.current_transcript = ""
if "current_filename" not in st.session_state:
    st.session_state.current_filename = ""
if "current_source" not in st.session_state:
    st.session_state.current_source = ""
if "current_case_id" not in st.session_state:
    st.session_state.current_case_id = None
if "active_info_modal" not in st.session_state:
    st.session_state.active_info_modal = None
if "feedback_submitted" not in st.session_state:
    st.session_state.feedback_submitted = False


def toggle_theme():
    """Toggles theme between dark and light mode without resetting current analysis."""
    st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"


def set_info_modal(modal_name: str):
    """Toggles or sets the active information modal section."""
    if st.session_state.active_info_modal == modal_name:
        st.session_state.active_info_modal = None
    else:
        st.session_state.active_info_modal = modal_name


# Theme CSS Definitions with Flawless Contrast in Both Light and Dark Modes
THEME_CSS = {
    "dark": """
    <style>
    /* Dark Theme Cyber Palette */
    :root {
        --bg-main: #0a0e17;
        --bg-card: #111827;
        --bg-card-hover: #1e293b;
        --border-color: #334155;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
        --accent-cyan: #38bdf8;
        --accent-blue: #3b82f6;
        --danger-red: #ef4444;
        --warning-amber: #f59e0b;
        --success-green: #10b981;
    }
    .stApp {
        background-color: #0a0e17;
        color: #f8fafc;
    }
    /* Collapse Streamlit's injected header toolbar that causes the top dead zone */
    header[data-testid="stHeader"] {
        height: 0rem !important;
        min-height: 0rem !important;
        display: none !important;
    }
    /* Remove top padding from the main content block */
    section.main > div.block-container,
    .block-container,
    .stMainBlockContainer {
        padding-top: 1rem !important;
        padding-bottom: 2rem !important;
        margin-top: 0 !important;
    }
    .main-header-container {
        padding: 4px 0 14px 0;
        margin-bottom: 12px;
        border-bottom: 1px solid #1e293b;
    }
    .cyber-card {
        background-color: #111827;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
        box-shadow: 0 4px 14px rgba(0,0,0,0.4);
    }
    .info-modal-card {
        background-color: #0f172a;
        border: 1.5px solid #38bdf8;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 6px 20px rgba(56,189,248,0.15);
    }
    .step-card {
        background-color: #111827;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        height: 100%;
        text-align: center;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .step-card:hover {
        border-color: #38bdf8;
        transform: translateY(-2px);
    }
    .step-num {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        border-radius: 50%;
        background-color: #1e293b;
        color: #38bdf8;
        font-weight: 800;
        font-size: 0.95rem;
        margin-bottom: 10px;
        border: 1px solid #38bdf8;
    }
    .cyber-badge-high {
        background-color: #7f1d1d;
        color: #fca5a5;
        border: 1px solid #ef4444;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .cyber-badge-med {
        background-color: #78350f;
        color: #fde68a;
        border: 1px solid #f59e0b;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .cyber-badge-low {
        background-color: #064e3b;
        color: #a7f3d0;
        border: 1px solid #10b981;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .score-circle-high {
        color: #ef4444;
        font-size: 3.2rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-circle-med {
        color: #f59e0b;
        font-size: 3.2rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-circle-low {
        color: #10b981;
        font-size: 3.2rem;
        font-weight: 900;
        line-height: 1;
    }
    .highlight-chip {
        background-color: #7f1d1d;
        color: #fecaca;
        border: 1px solid #ef4444;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        margin: 3px;
        display: inline-block;
    }
    .safe-tip-card {
        background-color: #111827;
        border-left: 3px solid #38bdf8;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 12px;
        font-size: 0.88rem;
        color: #cbd5e1;
    }
    </style>
    """,
    "light": """
    <style>
    /* Light Theme Cyber Palette */
    :root {
        --bg-main: #f8fafc;
        --bg-card: #ffffff;
        --bg-card-hover: #f1f5f9;
        --border-color: #cbd5e1;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --accent-cyan: #0284c7;
        --accent-blue: #2563eb;
        --danger-red: #dc2626;
        --warning-amber: #d97706;
        --success-green: #059669;
    }
    .stApp {
        background-color: #f8fafc;
        color: #0f172a;
    }
    /* Collapse Streamlit's injected header toolbar that causes the top dead zone */
    header[data-testid="stHeader"] {
        height: 0rem !important;
        min-height: 0rem !important;
        display: none !important;
    }
    /* Remove top padding from the main content block */
    section.main > div.block-container,
    .block-container,
    .stMainBlockContainer {
        padding-top: 1rem !important;
        padding-bottom: 2rem !important;
        margin-top: 0 !important;
    }
    .main-header-container {
        padding: 4px 0 14px 0;
        margin-bottom: 12px;
        border-bottom: 1px solid #e2e8f0;
    }
    .cyber-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.06);
    }
    .info-modal-card {
        background-color: #f0fdf4;
        border: 1.5px solid #0284c7;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 6px 18px rgba(2, 132, 199, 0.12);
        color: #0f172a;
    }
    .step-card {
        background-color: #ffffff;
        border: 1px solid #cbd5e1;
        border-radius: 10px;
        padding: 16px;
        height: 100%;
        text-align: center;
        box-shadow: 0 2px 6px rgba(0,0,0,0.03);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .step-card:hover {
        border-color: #0284c7;
        transform: translateY(-2px);
    }
    .step-num {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        border-radius: 50%;
        background-color: #e0f2fe;
        color: #0284c7;
        font-weight: 800;
        font-size: 0.95rem;
        margin-bottom: 10px;
        border: 1px solid #0284c7;
    }
    .cyber-badge-high {
        background-color: #fee2e2;
        color: #991b1b;
        border: 1px solid #f87171;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .cyber-badge-med {
        background-color: #fef3c7;
        color: #92400e;
        border: 1px solid #fbbf24;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .cyber-badge-low {
        background-color: #dcfce7;
        color: #166534;
        border: 1px solid #4ade80;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .score-circle-high {
        color: #dc2626;
        font-size: 3.2rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-circle-med {
        color: #d97706;
        font-size: 3.2rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-circle-low {
        color: #059669;
        font-size: 3.2rem;
        font-weight: 900;
        line-height: 1;
    }
    .highlight-chip {
        background-color: #fee2e2;
        color: #991b1b;
        border: 1px solid #fca5a5;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        margin: 3px;
        display: inline-block;
    }
    .safe-tip-card {
        background-color: #f1f5f9;
        border-left: 3px solid #0284c7;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 12px;
        font-size: 0.88rem;
        color: #1e293b;
    }
    </style>
    """
}

# Inject Active Theme CSS
st.markdown(THEME_CSS[st.session_state.theme], unsafe_allow_html=True)


# ==========================================
# 1. MAIN HEADER & THEME TOGGLE
# ==========================================
st.markdown('<div class="main-header-container">', unsafe_allow_html=True)
header_left, header_right = st.columns([8.2, 1.8])

with header_left:
    st.markdown("""
        <h1 style="margin: 0; padding: 0; font-size: 2.1rem; font-weight: 800; letter-spacing: -0.5px; display: flex; align-items: center; gap: 12px;">
            <span>🛡️</span> AI-Based Phishing Call Detection & Risk Analyzer
        </h1>
    """, unsafe_allow_html=True)

with header_right:
    theme_label = "☀️ Light Mode" if st.session_state.theme == "dark" else "🌙 Dark Mode"
    st.button(theme_label, on_click=toggle_theme, help="Toggle visual appearance", use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)


# ==========================================
# 2. FIVE PROJECT INFORMATION ICONS
# ==========================================
info_cols = st.columns(5)

with info_cols[0]:
    if st.button("⚠️ Problem Statement", use_container_width=True):
        set_info_modal("problem")

with info_cols[1]:
    if st.button("💡 Proposed Solution", use_container_width=True):
        set_info_modal("solution")

with info_cols[2]:
    if st.button("🎯 Project Objectives", use_container_width=True):
        set_info_modal("objectives")

with info_cols[3]:
    if st.button("🏗️ Architecture Design", use_container_width=True):
        set_info_modal("architecture")

with info_cols[4]:
    if st.button("🚀 Next Milestones", use_container_width=True):
        set_info_modal("milestones")


# Active Modal / Information Box Display
if st.session_state.active_info_modal:
    modal_key = st.session_state.active_info_modal
    
    with st.container():
        st.markdown('<div class="info-modal-card">', unsafe_allow_html=True)
        modal_head, modal_close = st.columns([9.2, 0.8])
        
        with modal_close:
            if st.button("✕", help="Close Information Window", key="btn_close_modal"):
                st.session_state.active_info_modal = None
                st.rerun()

        with modal_head:
            if modal_key == "problem":
                st.markdown("### ⚠️ Problem Statement")
                st.markdown("""
                Voice phishing (**vishing**) is a pervasive form of social engineering where adversaries verbally deceive individuals over telecommunication networks. Scammers impersonate trusted institutions—such as commercial banks, law enforcement agencies, tax authorities, or technical support representatives—to coerce victims into divulging sensitive authentication credentials (OTPs, PINs, passwords, CVVs) or executing unauthorized financial transfers.

                Unlike digital email phishing, which benefits from established URL filters and text analysis gateways, phone conversations exploit immediate auditory psychological urgency, fear, and authority. Victims are often rushed into compliance within minutes, resulting in devastating financial loss and identity compromise.
                """)

            elif modal_key == "solution":
                st.markdown("### 💡 Proposed Solution")
                st.markdown("""
                The **AI-Based Phishing Call Detection & Risk Analyzer** is an explainable, privacy-preserving cybersecurity system designed to audit recorded voice telephone calls for social engineering tactics.

                - **Zero-Cloud Privacy:** Ingests call recordings and executes offline Speech-to-Text (STT) locally via quantized Whisper models, ensuring sensitive voice recordings never egress to third-party cloud servers.
                - **Transparent Contextual Heuristics:** Evaluates transcripts against an explainable rule-based engine covering 8 distinct threat vectors (including credential harvesting, remote desktop takeover, and psychological intimidation) rather than opaque black-box neural predictions.
                - **Explainable Threat Intelligence:** Produces a normalized risk score (0–100), severity tiering (Low, Medium, High), forensic quotation evidence, and actionable safety recommendations, supplemented by exportable PDF and TXT audit reports.
                """)

            elif modal_key == "objectives":
                st.markdown("### 🎯 Project Objectives (SMART)")
                st.markdown("""
                1. **Objective 1 (Detection & Accuracy):** Develop a transparent contextual threat engine capable of evaluating call transcripts across 8 primary vishing indicator categories, achieving a zero false-positive rate on routine legitimate service interactions across all benchmark test cases.
                2. **Objective 2 (Privacy & Local Processing):** Integrate an entirely local, on-device speech-to-text pipeline utilizing CPU-quantized Whisper models, ensuring 100% of audio transcription occurs without external network dependencies or data retention risks.
                3. **Objective 3 (Explainability & Response Time):** Generate an explainable mathematical risk assessment (0–100 scale) with detailed indicator breakdowns and downloadable forensic PDF/TXT reports within 15 seconds of transcription completion.
                """)

            elif modal_key == "architecture":
                st.markdown("### 🏗️ Architecture Design")
                st.markdown("""
                The application follows a modular, explainable cybersecurity processing pipeline:

                ```
                ┌────────────────────────────────┐
                │ 1. Voice Ingestion Subsystem   │ (WAV, MP3, M4A Audio Upload / Demo Scenario)
                └───────────────┬────────────────┘
                                │
                                ▼
                ┌────────────────────────────────┐
                │ 2. Local Whisper STT Engine    │ (Offline faster-whisper CPU Int8 Quantization)
                └───────────────┬────────────────┘
                                │
                                ▼
                ┌────────────────────────────────┐
                │ 3. Text Normalizer & Lexer     │ (Sentence Tokenization, Case Normalization)
                └───────────────┬────────────────┘
                                │
                                ▼
                ┌────────────────────────────────┐
                │ 4. Heuristic Rule Evaluator    │ (8 Contextual Threat Categories + Deduplication)
                └───────────────┬────────────────┘
                                │
                                ▼
                ┌────────────────────────────────┐
                │ 5. Tactical Synergy Calculator │ (Compounding Threat Bonuses, 0-100 Capped Score)
                └───────────────┬────────────────┘
                                │
                        ┌───────┴───────┐
                        ▼               ▼
                ┌───────────────┐ ┌────────────────┐
                │ 6. SQLite DB  │ │ 7. ReportLab   │ (Local History & Forensic PDF/TXT Reports)
                └───────────────┘ └────────────────┘
                ```
                """)

            elif modal_key == "milestones":
                st.markdown("### 🚀 Next Milestones")
                st.markdown("""
                - **Milestone 1 — Multilingual Vishing Support:** Implement acoustic models for Hindi and regional languages to detect multilingual code-switching scams prevalent in telephone fraud.
                - **Milestone 2 — Voice Biometrics & Deepfake Acoustic Analysis:** Integrate acoustic feature extraction to identify synthetic AI-generated voice clones, VoIP background latency, and unnatural pitch modulation.
                - **Milestone 3 — Enterprise Telephony Auditing:** Develop headless API endpoints to enable enterprise call centers and financial institutions to batch-audit recorded customer interactions asynchronously.
                """)

            elif modal_key == "video":
                st.markdown("### 🎬 Project Demonstration Video")
                video_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_video.mp4")
                if os.path.exists(video_path):
                    st.video(video_path)
                else:
                    st.info("ℹ️ **Demonstration Video Notice:** The video demonstration is currently being prepared and will be published shortly. You can experience the complete, live working workflow by uploading an audio recording or running any of the pre-loaded demo scenarios below.")

        st.markdown('</div>', unsafe_allow_html=True)

st.markdown("<div style='margin-bottom: 8px;'></div>", unsafe_allow_html=True)


# ==========================================
# 3. SIDEBAR NAVIGATION & STAY SAFE SECTION
# ==========================================
with st.sidebar:
    st.markdown("### 🧭 Explore Features")
    app_mode = st.radio(
        "Navigation Menu:",
        [
            "🛡️ Call Analysis",
            "📊 Analytics Dashboard",
            "📜 Analysis History",
            "⚖️ Multi-Call Comparison"
        ],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("### 🛡️ Stay Safe Online")
    st.markdown("""
        <div class="safe-tip-card">
            <b>🔒 Never Share Credentials:</b><br/>
            Legitimate banks, telecom agents, and police officers will NEVER ask for your OTP, UPI PIN, password, or CVV over the phone.
        </div>
        <div class="safe-tip-card">
            <b>🚫 Refuse Remote Desktop Tools:</b><br/>
            Never install AnyDesk, TeamViewer, or screen-sharing tools on instructions from an unknown caller.
        </div>
        <div class="safe-tip-card">
            <b>📞 Verify Independently:</b><br/>
            If a caller claims your bank account or power connection will be cut off, disconnect and call the verified number on your physical card or official bill.
        </div>
        <div class="safe-tip-card">
            <b>⏳ Resist False Urgency:</b><br/>
            Scammers create artificial panic ("within 10 minutes") to disable rational thinking. Take a breath and consult someone you trust.
        </div>
        <div class="safe-tip-card">
            <b>🚨 Report Incident:</b><br/>
            In case of financial scam or fraud, immediately dial <b>1930</b> (Cyber Crime Helpline) or lodge an incident at <b>cybercrime.gov.in</b>.
        </div>
    """, unsafe_allow_html=True)


# ==========================================
# VIEW 1: CALL ANALYSIS TAB (DEFAULT)
# ==========================================
if app_mode == "🛡️ Call Analysis":
    # Clearly Visible "How It Works" Section
    st.markdown("### ⚙️ How It Works")
    step_cols = st.columns(5)
    
    steps_data = [
        ("1", "🎙️ Upload Recording", "Upload an audio recording (.wav, .mp3, .m4a) or select a demonstration scenario."),
        ("2", "📝 Local Transcription", "The offline Whisper speech engine converts voice into text with 100% data privacy."),
        ("3", "🔍 Heuristic Analysis", "The engine inspects the transcript for urgency, credential demands, and impersonation."),
        ("4", "📊 Risk Evaluation", "Receive an explainable 0–100 risk score, categorized as Low, Medium, or High Risk."),
        ("5", "🛡️ Guidance & Report", "Follow actionable safety recommendations and download a formal forensic PDF report.")
    ]

    for idx, (num, title, desc) in enumerate(steps_data):
        with step_cols[idx]:
            st.markdown(f"""
                <div class="step-card">
                    <div class="step-num">{num}</div>
                    <div style="font-weight: 700; font-size: 0.95rem; margin-bottom: 6px;">{title}</div>
                    <div style="font-size: 0.82rem; opacity: 0.85; line-height: 1.4;">{desc}</div>
                </div>
            """, unsafe_allow_html=True)

    st.markdown("<div style='margin-bottom: 24px;'></div>", unsafe_allow_html=True)
    st.markdown("### 🛡️ Voice Call Audio Ingestion & Phishing Detection")
    st.write("Upload a call recording, test pre-configured scenarios, or directly paste a conversation transcript to audit for social engineering patterns.")

    input_method = st.radio(
        "Choose Ingestion Method:",
        [
            "🎙️ Upload Audio Recording (WAV, MP3, M4A)",
            "⚡ Quick Demo Scenarios (Pre-loaded)",
            "📝 Direct Transcript Input"
        ],
        horizontal=True
    )

    call_transcript = ""
    source_filename = ""
    source_type = ""
    audio_bytes = None

    # Option 1: Audio Upload
    if input_method == "🎙️ Upload Audio Recording (WAV, MP3, M4A)":
        col_up, col_samples = st.columns([3, 2])
        
        with col_up:
            uploaded_audio = st.file_uploader(
                "Upload recorded telephone conversation:",
                type=["wav", "mp3", "m4a"],
                help="Supports WAV, MP3, and M4A up to 35 MB. Audio is processed 100% locally on your machine."
            )
            if uploaded_audio is not None:
                audio_bytes = uploaded_audio.getvalue()
                source_filename = uploaded_audio.name
                source_type = "Audio Upload"
                st.audio(audio_bytes, format=f"audio/{uploaded_audio.name.split('.')[-1]}")

        with col_samples:
            st.markdown("##### 📁 Pre-Loaded Sample Audio Files:")
            sample_files = [
                ("Sample 1: Normal Delivery (WAV)", "sample_audio/sample_1_normal_delivery.wav", "demo_normal"),
                ("Sample 2: Suspicious Reward (WAV)", "sample_audio/sample_2_suspicious_reward.wav", "demo_suspicious"),
                ("Sample 3: Critical Bank Vishing (WAV)", "sample_audio/sample_3_critical_vishing.wav", "demo_phishing"),
            ]
            for label, rel_path, demo_key in sample_files:
                if os.path.exists(rel_path):
                    if st.button(f"Load {label}", key=f"btn_load_{demo_key}", use_container_width=True):
                        with open(rel_path, "rb") as f:
                            audio_bytes = f.read()
                        source_filename = os.path.basename(rel_path)
                        source_type = "Sample Audio File"
                        st.session_state["loaded_sample_audio"] = {
                            "name": source_filename,
                            "bytes": audio_bytes,
                            "demo_key": demo_key
                        }
                        st.rerun()

            if "loaded_sample_audio" in st.session_state:
                sample_info = st.session_state["loaded_sample_audio"]
                audio_bytes = sample_info["bytes"]
                source_filename = sample_info["name"]
                source_type = "Sample Audio File"
                st.success(f"Ready: `{source_filename}`")
                st.audio(audio_bytes, format="audio/wav")

        # Transcription Trigger
        if audio_bytes is not None:
            if st.button("🚀 Transcribe Audio & Analyze", type="primary", use_container_width=True):
                class MemoryAudioFile:
                    def __init__(self, name, data):
                        self.name = name
                        self.size = len(data)
                        self._data = data
                    def getvalue(self):
                        return self._data

                mem_file = MemoryAudioFile(source_filename, audio_bytes)
                
                with st.spinner("Transcribing audio using local Whisper engine (CPU)..."):
                    t_start = time.time()
                    trans_res = transcribe_audio_file(mem_file)
                    t_elapsed = round(time.time() - t_start, 2)

                if trans_res["success"]:
                    call_transcript = trans_res["transcript"]
                    st.success(f"✅ Audio transcribed successfully in {t_elapsed}s (Audio Duration: {trans_res['duration_seconds']}s)")
                    st.session_state.current_transcript = call_transcript
                    st.session_state.current_filename = source_filename
                    st.session_state.current_source = source_type
                else:
                    st.error(f"❌ Transcription Failed: {trans_res['error']}")
                    st.info("You can still evaluate conversational threats using the 'Quick Demo Scenarios' or 'Direct Transcript Input' options above.")

    # Option 2: Pre-Loaded Demo Scenarios
    elif input_method == "⚡ Quick Demo Scenarios (Pre-loaded)":
        st.markdown("##### 🔬 Select Demonstration Scenario:")
        demo_titles = [f"{d['title']} ({d['expected_risk']} Risk)" for d in DEMO_CONVERSATIONS]
        selected_idx = st.selectbox("Choose Scenario:", range(len(demo_titles)), format_func=lambda i: demo_titles[i])
        
        selected_demo = DEMO_CONVERSATIONS[selected_idx]
        
        # Display demo card
        st.markdown(f"""
            <div class="cyber-card">
                <b>Scenario:</b> {selected_demo['title']}<br/>
                <b>Simulated Caller ID:</b> <code>{selected_demo['simulated_caller_id']}</code> | <b>Call Duration:</b> {selected_demo['duration']}<br/>
                <b>Expected Risk Range:</b> <code>{selected_demo['expected_score_range']}</code> ({selected_demo['expected_risk']})<br/>
                <p style="margin-top: 8px; font-size: 0.9rem; opacity: 0.9;">{selected_demo['description']}</p>
            </div>
        """, unsafe_allow_html=True)

        call_transcript = selected_demo["transcript"]
        source_filename = f"{selected_demo['id']}.txt"
        source_type = "Demo Scenario"

        if st.button("⚡ Run Threat Analysis on This Scenario", type="primary", use_container_width=True):
            st.session_state.current_transcript = call_transcript
            st.session_state.current_filename = source_filename
            st.session_state.current_source = source_type

    # Option 3: Direct Transcript
    else:
        st.markdown("##### 📝 Paste or Type Call Transcript:")
        user_text = st.text_area(
            "Enter conversation text (Speaker dialogues or single block):",
            height=180,
            placeholder="Caller: Urgent call from bank security. Your account is blocked. Share the 6-digit OTP right now..."
        )
        if st.button("🔍 Analyze Custom Transcript", type="primary", use_container_width=True):
            if not user_text.strip():
                st.warning("Please enter conversation text before analyzing.")
            else:
                call_transcript = user_text.strip()
                source_filename = f"Custom_Transcript_{int(time.time())}.txt"
                source_type = "Direct Input"
                st.session_state.current_transcript = call_transcript
                st.session_state.current_filename = source_filename
                st.session_state.current_source = source_type

    # Execute Analysis if Transcript is ready in session
    if st.session_state.current_transcript:
        transcript_to_analyze = st.session_state.current_transcript
        fname = st.session_state.current_filename
        stype = st.session_state.current_source

        # Run analyzer
        analyzer = PhishingAnalyzer()
        analysis = analyzer.analyze(transcript_to_analyze)
        analysis["transcript"] = transcript_to_analyze
        st.session_state.current_analysis = analysis

        # Auto-save to SQLite if not already saved for this session
        if st.session_state.current_case_id is None or st.session_state.get("last_saved_fn") != fname:
            case_id = database.save_analysis(
                filename=fname,
                source_type=stype,
                transcript=transcript_to_analyze,
                risk_score=analysis["risk_score"],
                risk_level=analysis["risk_level"],
                indicators=analysis["indicators_detected"],
                recommendations=analysis["safety_recommendations"],
                breakdown=analysis["score_breakdown"]
            )
            st.session_state.current_case_id = case_id
            st.session_state["last_saved_fn"] = fname

        st.markdown("---")
        st.markdown(f"### 📋 Incident Analysis Report — `CASE-{st.session_state.current_case_id:04d}`")

        # Top Metric Banner
        score = analysis["risk_score"]
        level = analysis["risk_level"]

        if level == "HIGH":
            badge_class = "cyber-badge-high"
            circle_class = "score-circle-high"
            level_text = "HIGH RISK — CRITICAL VISHING DETECTED"
        elif level == "MEDIUM":
            badge_class = "cyber-badge-med"
            circle_class = "score-circle-med"
            level_text = "MEDIUM RISK — SUSPICIOUS CALL PATTERNS"
        else:
            badge_class = "cyber-badge-low"
            circle_class = "score-circle-low"
            level_text = "LOW RISK — LIKELY LEGITIMATE CALL"

        b_col1, b_col2, b_col3, b_col4 = st.columns([2.5, 3.5, 2, 2])
        
        with b_col1:
            st.markdown(f"""
                <div class="cyber-card" style="text-align: center;">
                    <div style="font-size: 0.85rem; opacity: 0.8; margin-bottom: 4px;">CALCULATED RISK SCORE</div>
                    <div class="{circle_class}">{score}</div>
                    <div style="font-size: 0.85rem; opacity: 0.7; margin-top: 4px;">Scale: 0 (Safe) to 100 (Critical)</div>
                </div>
            """, unsafe_allow_html=True)

        with b_col2:
            st.markdown(f"""
                <div class="cyber-card">
                    <div style="margin-bottom: 8px;">
                        <span class="{badge_class}">{level_text}</span>
                    </div>
                    <div style="font-size: 0.9rem; line-height: 1.4;">
                        <b>Source File:</b> <code>{fname}</code><br/>
                        <b>Threat Indicators Flagged:</b> <b>{analysis['indicator_count']}</b><br/>
                        <b>Tactical Synergy Multiplier:</b> +{analysis['synergy_bonus']} pts
                    </div>
                </div>
            """, unsafe_allow_html=True)

        with b_col3:
            st.markdown(f"""
                <div class="cyber-card" style="text-align: center;">
                    <div style="font-size: 0.85rem; opacity: 0.8;">THREAT LEVEL</div>
                    <h3 style="margin: 8px 0; color: {analysis['risk_color']};">{level}</h3>
                    <div style="font-size: 0.75rem; opacity: 0.7;">Low: 0-30 | Med: 31-70 | High: 71-100</div>
                </div>
            """, unsafe_allow_html=True)

        with b_col4:
            st.markdown(f"""
                <div class="cyber-card" style="text-align: center;">
                    <div style="font-size: 0.85rem; opacity: 0.8;">INCIDENT ID</div>
                    <h3 style="margin: 8px 0; color: #38bdf8;">#{st.session_state.current_case_id:04d}</h3>
                    <div style="font-size: 0.75rem; opacity: 0.7;">Saved to SQLite Storage</div>
                </div>
            """, unsafe_allow_html=True)

        # Transparent Mathematical Calculation Breakdown
        with st.expander("📐 Transparent Scoring Formula & Mathematical Breakdown", expanded=False):
            breakdown = analysis["score_breakdown"]
            st.markdown("""
                <p style="font-size: 0.9rem;">
                    Unlike black-box neural networks, this risk score is completely explainable. 
                    The score is computed using the sum of weighted contextual indicators plus a tactical synergy multiplier for combined threats:
                </p>
                <div style="font-family: monospace; background-color: rgba(56, 189, 248, 0.1); padding: 10px; border-radius: 6px; margin-bottom: 12px;">
                    Final Score = MIN( 100 , (Base Indicator Weights Sum) + (Tactical Synergy Bonus) )
                </div>
            """, unsafe_allow_html=True)

            calc_col1, calc_col2 = st.columns(2)
            with calc_col1:
                st.write("**Base Indicator Contributions:**")
                if not breakdown["base_indicator_weights"]:
                    st.write("• No indicators triggered (0 pts)")
                else:
                    for item in breakdown["base_indicator_weights"]:
                        st.write(f"• **{item['name']}** ({item['severity']}): `+{item['weight']} pts`")
                st.write(f"**Raw Indicator Sum:** `{breakdown['raw_sum']} pts`")

            with calc_col2:
                st.write("**Synergy Multiplier:**")
                st.write(f"• Synergy Addition: `+{breakdown['synergy_bonus']} pts`")
                st.write(f"• Synergy Analysis: *{breakdown['synergy_explanation']}*")
                st.write(f"**Final Capped Score:** `{breakdown['final_score_capped']} / 100`")

            st.caption(f"Risk Bands: Low ({breakdown['threshold_low']}) | Medium ({breakdown['threshold_medium']}) | High ({breakdown['threshold_high']})")

        # Interactive Transcript Viewer with Search & Highlighted Phishing Phrases
        st.markdown("#### 📜 Searchable Transcript & Evidence Highlighting")
        t_search_col, t_info_col = st.columns([3, 2])
        with t_search_col:
            search_term = st.text_input("🔍 Search keyword in transcript:", placeholder="e.g. OTP, AnyDesk, account, police...")

        # Display highlighted chips for detected patterns
        all_excerpts = []
        for ind in analysis["indicators_detected"]:
            for exc in ind["excerpts"]:
                all_excerpts.append(exc)

        st.markdown("**Detected Threat Excerpts & Keywords:**")
        if not all_excerpts:
            st.markdown("*(No suspicious excerpts detected)*")
        else:
            chip_html = " ".join([f"<span class='highlight-chip'>⚠️ {e[:60]}...</span>" if len(e) > 60 else f"<span class='highlight-chip'>⚠️ {e}</span>" for e in all_excerpts[:6]])
            st.markdown(chip_html, unsafe_allow_html=True)

        # Highlight transcript display
        display_transcript = transcript_to_analyze
        if search_term and search_term.strip():
            st.info(f"Occurrences of '{search_term}': {display_transcript.lower().count(search_term.lower())}")

        st.text_area("Full Call Transcript:", value=display_transcript, height=180, disabled=True)

        # Detailed Forensic Indicators Table
        st.markdown("#### 🚨 Forensic Indicator Breakdown & Attack Vectors")
        if not analysis["indicators_detected"]:
            st.success("✅ Clean Call: Zero social engineering or credential harvesting tactics identified.")
        else:
            for idx, ind in enumerate(analysis["indicators_detected"], 1):
                with st.container():
                    st.markdown(f"""
                        <div class="cyber-card">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <h4 style="margin: 0; color: #38bdf8;">[{idx}] {ind['name']}</h4>
                                <span style="font-weight: bold; color: {'#ef4444' if ind['severity'] == 'CRITICAL' else '#f59e0b'};">
                                    {ind['severity']} (+{ind['weight']} pts)
                                </span>
                            </div>
                            <div style="font-size: 0.85rem; opacity: 0.8; margin-top: 4px;">Category: <b>{ind['category']}</b></div>
                            <p style="margin: 8px 0 6px 0; font-size: 0.9rem;"><b>Why Dangerous:</b> {ind['why_dangerous']}</p>
                            <div style="background: rgba(239,68,68,0.1); border-left: 3px solid #ef4444; padding: 6px 12px; margin: 8px 0; border-radius: 4px; font-size: 0.85rem;">
                                <b>Forensic Quotes from Call:</b><br/>
                                {"<br/>".join([f'• "<i>{e}</i>"' for e in ind['excerpts']])}
                            </div>
                            <div style="font-size: 0.85rem; color: #10b981; margin-top: 4px;">
                                <b>Action Required:</b> {ind['recommendation']}
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

        # Actionable Safety Recommendations
        st.markdown("#### 🛡️ Actionable Safety Recommendations & Incident Response")
        for rec in analysis["safety_recommendations"]:
            st.markdown(f"• {rec}")

        # Download Reports & Accuracy Rating
        st.markdown("---")
        st.markdown("#### 📥 Export Incident Reports & Submit Forensic Feedback")
        d_col1, d_col2, d_col3 = st.columns([2, 2, 3])

        with d_col1:
            # Generate PDF
            pdf_bytes = report_generator.generate_pdf_report(analysis, fname)
            st.download_button(
                label="📄 Download Forensic Report (PDF)",
                data=pdf_bytes,
                file_name=f"Vishing_Forensic_Report_CASE_{st.session_state.current_case_id:04d}.pdf",
                mime="application/pdf",
                use_container_width=True
            )

        with d_col2:
            # Generate TXT
            txt_report = report_generator.generate_txt_report(analysis, fname)
            st.download_button(
                label="📝 Download Incident Audit (TXT)",
                data=txt_report,
                file_name=f"Vishing_Audit_CASE_{st.session_state.current_case_id:04d}.txt",
                mime="text/plain",
                use_container_width=True
            )

        with d_col3:
            # User Feedback
            feedback_options = ["Accurate Detection", "False Positive (Benign Call)", "False Negative (Phishing Missed)"]
            selected_fb = st.selectbox("Accuracy Feedback Rating:", feedback_options, key="feedback_select")
            if st.button("Submit Case Rating", use_container_width=True):
                database.update_feedback(st.session_state.current_case_id, selected_fb)
                st.success(f"Feedback '{selected_fb}' recorded for CASE-{st.session_state.current_case_id:04d}!")


# ==========================================
# VIEW 2: ANALYTICS & TRENDS DASHBOARD
# ==========================================
elif app_mode == "📊 Analytics Dashboard":
    st.markdown("### 📊 Threat Intelligence & Analytics Dashboard")
    st.write("Aggregated telemetry and risk metrics derived from all saved call analysis records.")

    stats = database.get_statistics()

    # Empty State Handling
    if stats["total_calls"] == 0:
        st.markdown("""
            <div class="cyber-card" style="text-align: center; padding: 40px 20px;">
                <span style="font-size: 3rem;">📭</span>
                <h3>No Call Analysis Records Found</h3>
                <p style="opacity: 0.8; max-width: 500px; margin: 0 auto 16px auto;">
                    The local SQLite database currently contains zero analyzed call cases. 
                    You can analyze a new call or click below to seed sample analysis records for demonstration.
                </p>
            </div>
        """, unsafe_allow_html=True)
        if st.button("⚡ Seed 3 Sample Cases for Demonstration", type="primary"):
            analyzer = PhishingAnalyzer()
            for demo in DEMO_CONVERSATIONS:
                res = analyzer.analyze(demo["transcript"])
                database.save_analysis(
                    filename=f"{demo['id']}.wav",
                    source_type="Demo Seeding",
                    transcript=demo["transcript"],
                    risk_score=res["risk_score"],
                    risk_level=res["risk_level"],
                    indicators=res["indicators_detected"],
                    recommendations=res["safety_recommendations"],
                    breakdown=res["score_breakdown"]
                )
            st.success("Successfully seeded 3 sample cases! Re-opening analytics...")
            st.rerun()

    else:
        # Top 4 Metric Cards
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Analyzed Calls", stats["total_calls"])
        m2.metric("Critical High Risk", stats["level_counts"]["HIGH"], delta="Needs Action", delta_color="inverse")
        m3.metric("Medium Suspicious", stats["level_counts"]["MEDIUM"], delta="Caution", delta_color="off")
        m4.metric("Low Risk / Benign", stats["level_counts"]["LOW"], delta="Normal", delta_color="normal")

        st.markdown("---")
        c_left, c_right = st.columns(2)

        with c_left:
            st.markdown("##### 🎯 Threat Severity Distribution")
            dist_data = pd.DataFrame([
                {"Risk Level": "HIGH", "Count": stats["level_counts"]["HIGH"]},
                {"Risk Level": "MEDIUM", "Count": stats["level_counts"]["MEDIUM"]},
                {"Risk Level": "LOW", "Count": stats["level_counts"]["LOW"]},
            ])
            chart = alt.Chart(dist_data).mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6).encode(
                x=alt.X("Risk Level:N", sort=["HIGH", "MEDIUM", "LOW"]),
                y=alt.Y("Count:Q", title="Total Calls"),
                color=alt.Color("Risk Level:N", scale=alt.Scale(
                    domain=["HIGH", "MEDIUM", "LOW"],
                    range=["#ef4444", "#f59e0b", "#10b981"]
                )),
                tooltip=["Risk Level", "Count"]
            ).properties(height=280)
            st.altair_chart(chart, use_container_width=True)

        with c_right:
            st.markdown("##### ⚡ Top Detected Social Engineering Tactics")
            if not stats["top_indicators"]:
                st.info("No threat indicators detected yet.")
            else:
                top_df = pd.DataFrame(stats["top_indicators"], columns=["Indicator", "Frequency"])
                tac_chart = alt.Chart(top_df).mark_bar(color="#38bdf8", cornerRadiusTopRight=6, cornerRadiusBottomRight=6).encode(
                    x=alt.X("Frequency:Q", title="Detection Count"),
                    y=alt.Y("Indicator:N", sort="-x", title=None),
                    tooltip=["Indicator", "Frequency"]
                ).properties(height=280)
                st.altair_chart(tac_chart, use_container_width=True)

        st.markdown("##### 📝 Recent Forensic Case Log")
        recent_cases = database.get_analyses(limit=5)
        case_rows = []
        for rc in recent_cases:
            case_rows.append({
                "Case ID": f"CASE-{rc['id']:04d}",
                "Timestamp": rc["created_at"],
                "Filename": rc["filename"],
                "Risk Score": f"{rc['risk_score']} / 100",
                "Risk Level": rc["risk_level"],
                "Indicators Flagged": len(rc["indicators"]),
                "Accuracy Rating": rc["feedback"]
            })
        st.dataframe(pd.DataFrame(case_rows), use_container_width=True)


# ==========================================
# VIEW 3: ANALYSIS HISTORY
# ==========================================
elif app_mode == "📜 Analysis History":
    st.markdown("### 📜 Forensic Investigation History & Case Management")
    st.write("Browse, search, reopen, or export historical call analysis records stored in the local SQLite database.")

    h_col1, h_col2, h_col3 = st.columns([3, 2, 2])
    with h_col1:
        search_kw = st.text_input("🔍 Search by Case Name, Keyword, or Content:", "")
    with h_col2:
        filter_lvl = st.selectbox("Filter Risk Level:", ["ALL", "HIGH", "MEDIUM", "LOW"])
    with h_col3:
        st.write("") # spacing
        csv_data = database.export_to_csv_string()
        st.download_button(
            "📥 Export Full History (CSV)",
            data=csv_data,
            file_name="Phishing_Investigation_History.csv",
            mime="text/csv",
            use_container_width=True
        )

    records = database.get_analyses(filter_level=filter_lvl, search_query=search_kw)

    if not records:
        st.info("No investigation records match your filter criteria.")
    else:
        st.write(f"Showing **{len(records)}** case records:")
        
        for r in records:
            with st.expander(f"📁 CASE-{r['id']:04d}: {r['filename']} | Score: {r['risk_score']}/100 [{r['risk_level']}] | {r['created_at']}"):
                col_info, col_actions = st.columns([4, 1.5])
                with col_info:
                    st.write(f"**Source Type:** {r['source_type']} | **Feedback Rating:** `{r['feedback']}`")
                    st.write(f"**Indicators Flagged ({len(r['indicators'])}):** " + (", ".join([i['name'] for i in r['indicators']]) if r['indicators'] else "None"))
                    st.text_area("Transcript Preview:", r["transcript"][:250] + ("..." if len(r["transcript"]) > 250 else ""), height=80, key=f"hist_txt_{r['id']}")

                with col_actions:
                    if st.button("📂 Re-Open Full Case", key=f"reopen_{r['id']}", use_container_width=True):
                        st.session_state.current_transcript = r["transcript"]
                        st.session_state.current_filename = r["filename"]
                        st.session_state.current_source = r["source_type"]
                        st.session_state.current_case_id = r["id"]
                        st.success(f"Case #{r['id']} loaded! Switch to '🛡️ Call Analysis' to view full report.")

                    if st.button("🗑️ Delete Record", key=f"del_{r['id']}", use_container_width=True):
                        database.delete_analysis(r["id"])
                        st.success(f"Record CASE-{r['id']:04d} deleted.")
                        st.rerun()

        st.markdown("---")
        if st.button("🧹 Clear All Database History (Reset)", help="Permanently erases all saved call records"):
            database.clear_all_analyses()
            st.warning("All investigation history has been erased.")
            st.rerun()


# ==========================================
# VIEW 4: MULTI-CALL COMPARISON
# ==========================================
elif app_mode == "⚖️ Multi-Call Comparison":
    st.markdown("### ⚖️ Multi-Call Threat Comparator")
    st.write("Compare 2 saved calls side-by-side to analyze differences in attack sophistication, urgency, and tactic diversity.")

    all_cases = database.get_analyses(limit=50)
    if len(all_cases) < 2:
        st.warning("You need at least 2 saved calls to use the comparator. Analyze more calls or seed samples in the Analytics Dashboard.")
        if st.button("⚡ Seed 3 Sample Calls Now"):
            analyzer = PhishingAnalyzer()
            for demo in DEMO_CONVERSATIONS:
                res = analyzer.analyze(demo["transcript"])
                database.save_analysis(
                    filename=f"{demo['id']}.wav",
                    source_type="Demo Seeding",
                    transcript=demo["transcript"],
                    risk_score=res["risk_score"],
                    risk_level=res["risk_level"],
                    indicators=res["indicators_detected"],
                    recommendations=res["safety_recommendations"],
                    breakdown=res["score_breakdown"]
                )
            st.success("Seeded sample cases! Reloading comparator...")
            st.rerun()
    else:
        case_options = {f"CASE-{c['id']:04d}: {c['filename']} ({c['risk_level']})": c['id'] for c in all_cases}
        
        comp_col1, comp_col2 = st.columns(2)
        with comp_col1:
            choice1 = st.selectbox("Select Call A:", list(case_options.keys()), index=0)
        with comp_col2:
            default_idx2 = 1 if len(case_options) > 1 else 0
            choice2 = st.selectbox("Select Call B:", list(case_options.keys()), index=default_idx2)

        id1 = case_options[choice1]
        id2 = case_options[choice2]

        c1 = database.get_analysis_by_id(id1)
        c2 = database.get_analysis_by_id(id2)

        if c1 and c2:
            st.markdown("#### 🔍 Side-by-Side Threat Comparison")
            c_a, c_b = st.columns(2)

            with c_a:
                st.markdown(f"""
                    <div class="cyber-card">
                        <h4 style="margin: 0; color: #38bdf8;">Call A: CASE-{c1['id']:04d}</h4>
                        <div style="font-size: 0.85rem; opacity: 0.8; margin-bottom: 10px;">{c1['filename']}</div>
                        <div style="font-size: 2.4rem; font-weight: 800; color: {'#ef4444' if c1['risk_level'] == 'HIGH' else '#f59e0b' if c1['risk_level'] == 'MEDIUM' else '#10b981'};">
                            {c1['risk_score']} / 100
                        </div>
                        <div style="margin: 8px 0;"><b>Level:</b> [{c1['risk_level']}]</div>
                        <div><b>Indicators Detected:</b> {len(c1['indicators'])}</div>
                    </div>
                """, unsafe_allow_html=True)
                st.write("**Detected Tactics:**")
                if not c1["indicators"]:
                    st.write("• *None (Clean Call)*")
                else:
                    for i in c1["indicators"]:
                        st.write(f"• **{i['name']}** ({i['severity']})")
                st.text_area("Transcript A:", c1["transcript"], height=140, key="comp_t1")

            with c_b:
                st.markdown(f"""
                    <div class="cyber-card">
                        <h4 style="margin: 0; color: #38bdf8;">Call B: CASE-{c2['id']:04d}</h4>
                        <div style="font-size: 0.85rem; opacity: 0.8; margin-bottom: 10px;">{c2['filename']}</div>
                        <div style="font-size: 2.4rem; font-weight: 800; color: {'#ef4444' if c2['risk_level'] == 'HIGH' else '#f59e0b' if c2['risk_level'] == 'MEDIUM' else '#10b981'};">
                            {c2['risk_score']} / 100
                        </div>
                        <div style="margin: 8px 0;"><b>Level:</b> [{c2['risk_level']}]</div>
                        <div><b>Indicators Detected:</b> {len(c2['indicators'])}</div>
                    </div>
                """, unsafe_allow_html=True)
                st.write("**Detected Tactics:**")
                if not c2["indicators"]:
                    st.write("• *None (Clean Call)*")
                else:
                    for i in c2["indicators"]:
                        st.write(f"• **{i['name']}** ({i['severity']})")
                st.text_area("Transcript B:", c2["transcript"], height=140, key="comp_t2")

            # Comparative Delta
            score_diff = abs(c1["risk_score"] - c2["risk_score"])
            higher_case = f"Call A (CASE-{c1['id']:04d})" if c1["risk_score"] > c2["risk_score"] else f"Call B (CASE-{c2['id']:04d})" if c2["risk_score"] > c1["risk_score"] else "Equal Risk"
            st.info(f"⚖️ **Comparison Summary:** Risk score disparity is **{score_diff} points**. More dangerous conversation: **{higher_case}**.")

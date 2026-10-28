"""
app.py - AI-Based Phishing Call Detection and Risk Analyzer
2nd-Year B.Tech CSE Cyber Security Mini-Project
Modern Streamlit Dashboard, Local Whisper STT, Rule-Based Threat Engine
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
    page_title="AI-Based Phishing Call Detector",
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
if "show_demo_video" not in st.session_state:
    st.session_state.show_demo_video = False
if "feedback_submitted" not in st.session_state:
    st.session_state.feedback_submitted = False


def toggle_theme():
    """Toggles theme between dark and light mode without reloading state."""
    st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"


# Theme CSS Definitions
THEME_CSS = {
    "dark": """
    <style>
    /* Dark Theme Cyber Palette */
    :root {
        --bg-main: #0b0f19;
        --bg-card: #111827;
        --bg-card-hover: #1f2937;
        --border-color: #374151;
        --text-primary: #f9fafb;
        --text-secondary: #9ca3af;
        --accent-cyan: #38bdf8;
        --accent-blue: #3b82f6;
        --danger-red: #ef4444;
        --warning-amber: #f59e0b;
        --success-green: #10b981;
    }
    .stApp {
        background-color: #0b0f19;
        color: #f9fafb;
    }
    .main-header {
        background: linear-gradient(135deg, #111827 0%, #1e1b4b 100%);
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .cyber-card {
        background-color: #111827;
        border: 1px solid #374151;
        border-radius: 10px;
        padding: 18px;
        margin-bottom: 16px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    }
    .cyber-badge-high {
        background-color: #7f1d1d;
        color: #fca5a5;
        border: 1px solid #ef4444;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .cyber-badge-med {
        background-color: #78350f;
        color: #fde68a;
        border: 1px solid #f59e0b;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .cyber-badge-low {
        background-color: #064e3b;
        color: #a7f3d0;
        border: 1px solid #10b981;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .score-circle-high {
        color: #ef4444;
        font-size: 3rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-circle-med {
        color: #f59e0b;
        font-size: 3rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-circle-low {
        color: #10b981;
        font-size: 3rem;
        font-weight: 900;
        line-height: 1;
    }
    .highlight-chip {
        background-color: #991b1b;
        color: #fef2f2;
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        margin: 2px;
        display: inline-block;
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
    .main-header {
        background: linear-gradient(135deg, #ffffff 0%, #e0e7ff 100%);
        border: 1px solid #cbd5e1;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
    }
    .cyber-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 18px;
        margin-bottom: 16px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    }
    .cyber-badge-high {
        background-color: #fee2e2;
        color: #991b1b;
        border: 1px solid #f87171;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .cyber-badge-med {
        background-color: #fef3c7;
        color: #92400e;
        border: 1px solid #fbbf24;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .cyber-badge-low {
        background-color: #dcfce7;
        color: #166534;
        border: 1px solid #4ade80;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .score-circle-high {
        color: #dc2626;
        font-size: 3rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-circle-med {
        color: #d97706;
        font-size: 3rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-circle-low {
        color: #059669;
        font-size: 3rem;
        font-weight: 900;
        line-height: 1;
    }
    .highlight-chip {
        background-color: #fee2e2;
        color: #991b1b;
        border: 1px solid #fca5a5;
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        margin: 2px;
        display: inline-block;
    }
    </style>
    """
}

# Inject Active Theme CSS
st.markdown(THEME_CSS[st.session_state.theme], unsafe_allow_html=True)


# ==========================================
# HEADER & TOP CONTROLS
# ==========================================
header_col1, header_col2, header_col3 = st.columns([6, 2, 2])

with header_col1:
    st.markdown("""
        <div style="display: flex; align-items: center; gap: 12px;">
            <span style="font-size: 2.2rem;">🛡️</span>
            <div>
                <h2 style="margin: 0; padding: 0; font-weight: 800; letter-spacing: -0.5px;">
                    AI-Based Phishing Call Detection & Risk Analyzer
                </h2>
                <p style="margin: 0; padding: 0; font-size: 0.95rem; opacity: 0.8;">
                    2nd-Year B.Tech CSE Cyber Security Mini-Project | Local Whisper STT & Explainable Heuristics
                </p>
            </div>
        </div>
    """, unsafe_allow_html=True)

with header_col2:
    demo_video_btn = st.button("▶ Demo Video", help="Watch simulated forensic walkthrough video", use_container_width=True)
    if demo_video_btn:
        st.session_state.show_demo_video = not st.session_state.show_demo_video

with header_col3:
    theme_icon = "☀️ Light" if st.session_state.theme == "dark" else "🌙 Dark"
    st.button(f"{theme_icon} Mode", on_click=toggle_theme, help="Toggle between Dark and Light mode", use_container_width=True)

# Demo Video Modal / Expander
if st.session_state.show_demo_video:
    with st.expander("🎬 Guided Demonstration & Forensic Walkthrough Video", expanded=True):
        st.markdown("""
            <div style="background-color: #0f172a; padding: 15px; border-radius: 8px; border: 1px solid #38bdf8;">
                <h4 style="color: #38bdf8; margin-top: 0;">System Architecture & Execution Pipeline Demonstration</h4>
                <p style="font-size: 0.9rem; color: #cbd5e1;">
                    This interactive simulator illustrates how real-world voice phishing (vishing) attacks are ingested,
                    transcribed via local Whisper AI, evaluated across 8 contextual indicator categories, and exported as forensic PDF evidence.
                </p>
            </div>
        """, unsafe_allow_html=True)
        
        # Interactive HTML5 Canvas / Audio-Visual Simulation
        simulation_html = """
        <div style="width: 100%; height: 260px; background: radial-gradient(circle at center, #1e293b 0%, #090d16 100%); border-radius: 8px; position: relative; overflow: hidden; display: flex; flex-direction: column; justify-content: center; align-items: center; border: 1px solid #334155; margin-top: 10px;">
            <div style="font-family: monospace; font-size: 14px; color: #38bdf8; margin-bottom: 8px; text-shadow: 0 0 8px rgba(56,189,248,0.6);">
                [SEC-SIMULATOR]: VISHING INGESTION & RISK ENGINE
            </div>
            <div style="display: flex; gap: 16px; align-items: center; margin-bottom: 12px;">
                <div style="background: #1e1b4b; border: 1px solid #6366f1; padding: 8px 14px; border-radius: 6px; text-align: center; color: #c7d2fe; font-size: 12px;">
                    1. Voice Ingestion<br/><span style="color:#a5b4fc;">WAV / MP3</span>
                </div>
                <div style="color: #38bdf8; font-weight: bold;">➔</div>
                <div style="background: #064e3b; border: 1px solid #10b981; padding: 8px 14px; border-radius: 6px; text-align: center; color: #a7f3d0; font-size: 12px;">
                    2. Local Whisper STT<br/><span style="color:#6ee7b7;">CPU Int8 Quantized</span>
                </div>
                <div style="color: #38bdf8; font-weight: bold;">➔</div>
                <div style="background: #78350f; border: 1px solid #f59e0b; padding: 8px 14px; border-radius: 6px; text-align: center; color: #fde68a; font-size: 12px;">
                    3. Context Pattern Engine<br/><span style="color:#fcd34d;">8 Threat Vectors</span>
                </div>
                <div style="color: #38bdf8; font-weight: bold;">➔</div>
                <div style="background: #7f1d1d; border: 1px solid #ef4444; padding: 8px 14px; border-radius: 6px; text-align: center; color: #fca5a5; font-size: 12px;">
                    4. Forensic PDF Report<br/><span style="color:#f87171;">Score & Emergency 1930</span>
                </div>
            </div>
            <div style="font-family: monospace; font-size: 11px; color: #94a3b8; text-align: center; max-width: 80%;">
                STATUS: Engine Ready | Whisper: Offline CPU Active | SQLite DB: Connected | Zero Surveillance Architecture
            </div>
        </div>
        """
        st.components.v1.html(simulation_html, height=280)
        
        st.info("💡 **Demonstration Walkthrough Steps:** Select **Sample 3 (Critical Vishing)** in the tab below, click **Analyze Call**, and inspect the mathematical synergy breakdown and generated PDF audit report.")
        if st.button("Close Demo Video Window"):
            st.session_state.show_demo_video = False
            st.rerun()

st.markdown("---")

# ==========================================
# SIDEBAR NAVIGATION
# ==========================================
with st.sidebar:
    st.markdown("### 🎛️ Navigation Menu")
    app_mode = st.radio(
        "Select Application View:",
        [
            "🛡️ Call Analysis",
            "📊 Analytics Dashboard",
            "📜 Investigation History",
            "⚖️ Multi-Call Comparator",
            "🎓 Academic Viva & Docs",
            "ℹ️ Privacy & Methodology"
        ]
    )

    st.markdown("---")
    st.markdown("### ⚙️ System Status")
    whisper_status = "🟢 Ready (Local)" if is_whisper_available() else "🟡 Fallback Only"
    st.write(f"**Whisper STT:** {whisper_status}")
    st.write(f"**Device Mode:** CPU (Int8 Quantized)")
    st.write(f"**Persistence:** SQLite Active")

    stats_quick = database.get_statistics()
    st.write(f"**Saved Incidents:** {stats_quick['total_calls']}")

    st.markdown("---")
    st.caption("College Mini-Project | 2nd-Year B.Tech CSE (Cyber Security)")


# ==========================================
# VIEW 1: CALL ANALYSIS TAB
# ==========================================
if app_mode == "🛡️ Call Analysis":
    st.markdown("### 🛡️ Voice Call Audio Ingestion & Phishing Detection")
    st.write("Upload an audio recording, test pre-configured educational samples, or paste a transcript to identify social engineering patterns.")

    input_method = st.radio(
        "Choose Input Ingestion Source:",
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
                "Upload recorded phone conversation file:",
                type=["wav", "mp3", "m4a"],
                help="Supports WAV, MP3, and M4A up to 30 MB. Processed 100% locally on your device."
            )
            if uploaded_audio is not None:
                audio_bytes = uploaded_audio.getvalue()
                source_filename = uploaded_audio.name
                source_type = "Audio Upload"
                st.audio(audio_bytes, format=f"audio/{uploaded_audio.name.split('.')[-1]}")

        with col_samples:
            st.markdown("##### 📁 Or Load Pre-Generated Audio Samples:")
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
                st.success(f"Loaded: `{source_filename}`")
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
                    st.info("You can still test using the 'Quick Demo Scenarios' or 'Direct Transcript Input' options above.")

    # Option 2: Pre-Loaded Demo Scenarios
    elif input_method == "⚡ Quick Demo Scenarios (Pre-loaded)":
        st.markdown("##### 🔬 Select Curated Demonstration Scenario:")
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

        if st.button("⚡ Run Forensic Analysis on This Scenario", type="primary", use_container_width=True):
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
                st.warning("Please enter some text before analyzing.")
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
                        <b>Source:</b> <code>{fname}</code><br/>
                        <b>Threat Indicators Flagged:</b> <b>{analysis['indicator_count']}</b><br/>
                        <b>Synergy Multiplier:</b> +{analysis['synergy_bonus']} pts
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
                    <div style="font-size: 0.75rem; opacity: 0.7;">Saved to SQLite DB</div>
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
            # Basic text highlight for searched term
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
    st.markdown("### 📊 Cyber Threat Intelligence & Analytics Dashboard")
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
                {"Risk Level": "HIGH", "Count": stats["level_counts"]["HIGH"], "Color": "#ef4444"},
                {"Risk Level": "MEDIUM", "Count": stats["level_counts"]["MEDIUM"], "Color": "#f59e0b"},
                {"Risk Level": "LOW", "Count": stats["level_counts"]["LOW"], "Color": "#10b981"},
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
                "Indicators": len(rc["indicators"]),
                "Feedback": rc["feedback"]
            })
        st.dataframe(pd.DataFrame(case_rows), use_container_width=True)


# ==========================================
# VIEW 3: INVESTIGATION HISTORY
# ==========================================
elif app_mode == "📜 Investigation History":
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
                    st.write(f"**Source Type:** {r['source_type']} | **Feedback:** `{r['feedback']}`")
                    st.write(f"**Indicators Flagged ({len(r['indicators'])}):** " + (", ".join([i['name'] for i in r['indicators']]) if r['indicators'] else "None"))
                    st.text_area("Transcript Preview:", r["transcript"][:250] + ("..." if len(r["transcript"]) > 250 else ""), height=80, key=f"hist_txt_{r['id']}")

                with col_actions:
                    if st.button("📂 Re-Open Full Case", key=f"reopen_{r['id']}", use_container_width=True):
                        st.session_state.current_transcript = r["transcript"]
                        st.session_state.current_filename = r["filename"]
                        st.session_state.current_source = r["source_type"]
                        st.session_state.current_case_id = r["id"]
                        st.success(f"Case #{r['id']} loaded! Switch to '🛡️ Call Analysis' tab to view.")

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
# VIEW 4: MULTI-CALL COMPARATOR
# ==========================================
elif app_mode == "⚖️ Multi-Call Comparator":
    st.markdown("### ⚖️ Multi-Call Threat Comparator")
    st.write("Compare 2 or 3 saved calls side-by-side to analyze differences in attack sophistication, urgency, and tactic diversity.")

    all_cases = database.get_analyses(limit=50)
    if len(all_cases) < 2:
        st.warning("You need at least 2 saved calls to use the comparator. Analyze more calls or seed samples in the Analytics tab.")
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
                        <div style="font-size: 2.2rem; font-weight: 800; color: {'#ef4444' if c1['risk_level'] == 'HIGH' else '#f59e0b' if c1['risk_level'] == 'MEDIUM' else '#10b981'};">
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
                        <div style="font-size: 2.2rem; font-weight: 800; color: {'#ef4444' if c2['risk_level'] == 'HIGH' else '#f59e0b' if c2['risk_level'] == 'MEDIUM' else '#10b981'};">
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


# ==========================================
# VIEW 5: ACADEMIC VIVA & TECHNICAL DOCS
# ==========================================
elif app_mode == "🎓 Academic Viva & Docs":
    st.markdown("### 🎓 Academic Viva Voce & Technical Documentation")
    st.write("Comprehensive examination preparation guide, architecture definitions, and cyber security concepts for B.Tech project presentation.")

    tab_viva, tab_arch, tab_concepts = st.tabs(["📚 10 Examiner Viva Q&A", "🏗️ System Architecture", "🛡️ Cyber Threat Theory"])

    with tab_viva:
        st.markdown("#### 🎯 Frequently Asked Viva Voce Questions & Model Answers")
        
        viva_qa = [
            (
                "Q1. What is voice phishing (vishing) and how does it differ from traditional email phishing?",
                "Vishing (Voice Phishing) is a social engineering attack conducted over telephone lines or VoIP where attackers verbally manipulate victims into disclosing sensitive authentication credentials (OTPs, PINs, passwords) or transferring money. Unlike email phishing which relies on hyperlinks and fake web forms, vishing leverages immediate auditory urgency, emotional intimidation, and real-time interactive deception to bypass the victim's critical thinking."
            ),
            (
                "Q2. Why did your project implement a transparent rule-based engine instead of a deep-learning black-box classifier?",
                "In cybersecurity incident response and digital forensics, explainability is paramount. Black-box neural models often output probabilities without verifiable justification and are susceptible to adversarial evasion or hallucinations. Our rule-based heuristic engine guarantees 100% explainability: every risk point is directly attributed to verifiable excerpts, specific attack categories, and transparent mathematical formulas required for legal and compliance audit trails."
            ),
            (
                "Q3. How does local Whisper speech-to-text preserve user privacy compared to cloud speech APIs?",
                "Commercial cloud speech APIs (such as Google Speech-to-Text or OpenAI Cloud API) transmit sensitive personal phone conversations across third-party networks, violating user confidentiality and data residency regulations. By deploying local faster-whisper on CPU with int8 quantization, the speech audio never leaves the host machine. All transcription occurs entirely in-memory or on local disk, ensuring complete zero-surveillance data privacy."
            ),
            (
                "Q4. How do attackers manipulate human psychology using urgency and fear?",
                "Attackers exploit fundamental cognitive biases, primarily the 'fight-or-flight' stress response. By fabricating severe time constraints ('within 10 minutes') or catastrophic penalties (police arrest warrants, power cutoffs, account freezing), attackers induce cognitive overload. Under heightened stress, the prefrontal cortex struggles to perform analytical scrutiny, forcing the victim to comply with demands they would otherwise reject."
            ),
            (
                "Q5. How does your detection algorithm prevent false positives on common words like 'bank' or 'card'?",
                "The engine rejects single-token matching. For instance, the isolated occurrence of 'bank' or 'pin' does not trigger an alert. Instead, the engine enforces contextual multi-token regular expressions and bigrams—such as `(share|verify|tell).{0,25}(otp|pin|cvv)` or `(police|fir|arrest).{0,25}(warrant|custody)`. Furthermore, matched indicators are deduplicated so repeating 'OTP' 5 times does not inflate the score fivefold."
            ),
            (
                "Q6. What is the 'Synergy Multiplier' and why is it crucial in risk assessment?",
                "In real-world cybercrime, individual indicators compound each other. A caller asking for an appointment has zero threat. But a caller impersonating a bank vigilance officer AND demanding an OTP under threat of arrest exhibits a compounding malicious signature. The synergy multiplier (+10 to +25 pts) captures this co-occurrence synergy, reflecting the exponential escalation of threat severity."
            ),
            (
                "Q7. Why is the weaponization of Remote Access Tools (AnyDesk, TeamViewer) so dangerous in financial scams?",
                "Scammers instruct victims to install remote desktop applications under the pretext of 'canceling fraudulent transactions'. Once connected, the attacker observes the victim's screen in real time. When the bank sends a 2FA OTP via SMS, the attacker reads it directly off the mirrored screen and executes unauthorized fund transfers without needing the victim to say anything."
            ),
            (
                "Q8. What are the key technical limitations of rule-based heuristic detection?",
                "Rule-based systems rely on known pattern signatures. They may experience limitations when: (1) Attackers utilize regional slang, coded language, or dialects not covered by existing regexes, (2) Audio transcription introduces phonetic spelling errors (e.g., 'any disc' instead of 'AnyDesk'), or (3) Attackers conduct prolonged recon calls without triggering immediate demand keywords."
            ),
            (
                "Q9. How does Caller ID spoofing work and why should displayed phone numbers never be trusted?",
                "Telecommunication networks using SIP (Session Initiation Protocol) and VoIP gateways allow the calling party to set the 'From' field in the call header to arbitrary phone numbers. Scammers spoof verified bank helplines or police control numbers. Therefore, security policy dictates that incoming caller identity must never be authenticated by Caller ID alone."
            ),
            (
                "Q10. What immediate incident response actions should a victim take if they shared an OTP?",
                "1. Immediately call the official bank card-blocking hotline or log into net banking to freeze all debit/credit cards and UPI access.<br/>2. Disconnect Wi-Fi and mobile data to terminate any active remote desktop sessions.<br/>3. File an urgent complaint on the National Cyber Crime Reporting Portal (cybercrime.gov.in) or call helpline 1930 within the golden hour to freeze recipient bank accounts.<br/>4. File an official police GD/FIR at the local cyber crime police station."
            )
        ]

        for q, a in viva_qa:
            with st.expander(f"📌 {q}"):
                st.markdown(f"<div style='font-size: 0.95rem; line-height: 1.5;'>{a}</div>", unsafe_allow_html=True)

    with tab_arch:
        st.markdown("#### 🏗️ Modular Pipeline Architecture")
        st.markdown("""
            ```
            ┌────────────────┐
            │ Audio Input    │  (WAV, MP3, M4A or Pre-loaded Demo)
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │ Whisper Engine │  (Local faster-whisper CPU Int8 Quantized)
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │ Text Normalizer│  (Regex cleaning, Sentence Boundary Splitting)
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │ Pattern Matcher│  (8 Contextual Indicators, De-duplicated Bigrams)
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │ Synergy Calc   │  (Compounding Tactic Multiplier: +10 to +25)
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │ Risk Scorer    │  (0-100 Capped Scale -> Low, Medium, High)
            └───────┬────────┘
                    │
             ┌──────┴──────┐
             ▼             ▼
      ┌────────────┐ ┌────────────┐
      │ SQLite DB  │ │ ReportLab  │  (Incident Archival & Forensic PDF Export)
      └────────────┘ └────────────┘
            ```
        """)

    with tab_concepts:
        st.markdown("#### 🛡️ Key Cybersecurity Threat Vectors Detected")
        st.markdown("""
        | Threat Vector | Category | Base Weight | Target Asset |
        | :--- | :--- | :--- | :--- |
        | **Credential Harvesting** | Identity Theft | +35 pts | OTP, UPI PIN, CVV, Passwords |
        | **Remote Desktop Hijacking** | RAT Coercion | +30 pts | AnyDesk, TeamViewer screen takeover |
        | **Psychological Coercion** | Intimidation | +25 pts | Arrest threat, Account suspension |
        | **Financial Demand** | Extortion | +25 pts | Safe account transfer, Advance fees |
        | **Authority Impersonation** | Social Engineering | +20 pts | RBI, SBI, Cyber Police, TRAI |
        | **Secrecy & Isolation** | Behavioral Lock | +20 pts | 'Do not tell bank/family' |
        | **Artificial Urgency** | Stress Inducement | +15 pts | 'Within 10 mins', 'Act now' |
        | **Financial Lures** | Phishing Bait | +15 pts | Fake lottery, Unclaimed bonus points |
        """)


# ==========================================
# VIEW 6: PRIVACY & METHODOLOGY
# ==========================================
elif app_mode == "ℹ️ Privacy & Methodology":
    st.markdown("### ℹ️ Privacy Architecture & Ethical Guidelines")
    
    st.markdown("""
        <div class="cyber-card">
            <h4 style="color: #38bdf8; margin-top: 0;">🔒 Zero-Surveillance Architecture Pledge</h4>
            <p style="font-size: 0.95rem; line-height: 1.5;">
                In strict adherence to cyber security ethics and Indian data privacy standards:
            </p>
            <ul>
                <li><b>No Secret Call Interception:</b> This application does NOT tap telephone lines, monitor live microphones, or record incoming calls automatically. It solely analyzes audio files or transcripts intentionally provided by the user.</li>
                <li><b>100% Local Processing:</b> Audio transcription runs entirely on the host machine using offline <code>faster-whisper</code>. No voice data or metadata is ever transmitted to cloud APIs or external servers.</li>
                <li><b>Safe Temporary File Lifecycle:</b> Temporary audio files generated during ingestion are created in ephemeral secure system directories and deleted immediately upon analysis completion.</li>
                <li><b>Local Incident Storage:</b> Analysis records are preserved strictly on your local SQLite database (<code>phishing_analysis.db</code>) and can be purged at any time.</li>
            </ul>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 📞 National Cyber Emergency Helplines")
    st.markdown("""
    - **India National Cyber Crime Helpline:** Dial **1930** (Toll-Free, 24x7)
    - **Official Reporting Portal:** [https://cybercrime.gov.in](https://cybercrime.gov.in)
    - **Chakshu Telecom Fraud Portal (Sanchar Saathi):** [https://sancharsaathi.gov.in](https://sancharsaathi.gov.in)
    - **Reserve Bank of India Sachet Portal:** [https://sachet.rbi.org.in](https://sachet.rbi.org.in)
    """)

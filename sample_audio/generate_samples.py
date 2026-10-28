"""
generate_samples.py - Generates Real Audio Recordings for Demonstration
AI-Based Phishing Call Detection and Risk Analyzer
2nd-Year B.Tech CSE Cyber Security Mini-Project

Generates clean WAV audio recordings for the three demo scenarios using
the system's speech synthesis engine, so users can test audio upload and
speech-to-text transcription immediately without needing a microphone.
"""

import os
import subprocess
import sys

AUDIO_DIR = os.path.dirname(os.path.abspath(__file__))

SAMPLE_TEXTS = {
    "sample_1_normal_delivery.wav": (
        "Hello good afternoon. I am calling from BlueDart Express delivery. "
        "I have a package from Amazon scheduled for delivery at Flat 402 Green Valley Apartments today. "
        "Are you available at home to receive the parcel? "
        "Our delivery associate Rohan will reach your address in about 25 minutes. "
        "No signature or payment is required as this was already pre-paid online. Thank you and have a good day."
    ),
    "sample_2_suspicious_reward.wav": (
        "Good afternoon. I am calling from the Customer Loyalty Rewards Desk. "
        "You have been selected for an exclusive cashback reward of 8000 rupees on your credit card reward points. "
        "To process this credit card cashback reward, there is a small refundable deposit processing charge of 199 rupees. "
        "You must complete this within 30 minutes before the limited time window closes today. "
        "You must act now without delay, otherwise your unclaimed reward points will be permanently cancelled."
    ),
    "sample_3_critical_vishing.wav": (
        "Urgent call from State Bank of India Head Office Fraud Prevention Department! "
        "I am Officer Rajesh Kumar from the Anti-Fraud Vigilance Cell speaking. "
        "An unauthorized international transaction of 85000 rupees was just attempted on your credit card! "
        "You must act right now without delay! If we do not cancel this within 10 minutes, "
        "your account will be blocked and frozen, and a police FIR will be filed against your name! "
        "Go to your mobile Play Store immediately and install AnyDesk Remote Support application. "
        "Do not hang up! Stay on the line! This is confidential investigation so do not inform anyone or talk to your branch manager. "
        "You will receive an SMS containing a 6-digit OTP verification code. "
        "Read out the OTP to me immediately right now or your account will be permanently terminated!"
    )
}


def generate_audio_files():
    """Generates WAV files using Windows PowerShell SpeechSynthesizer."""
    print("Generating demonstration audio files in:", AUDIO_DIR)

    for filename, text in SAMPLE_TEXTS.items():
        out_path = os.path.join(AUDIO_DIR, filename)
        # Escape single quotes in text for PowerShell
        escaped_text = text.replace("'", "''")
        escaped_out_path = out_path.replace("'", "''")

        ps_script = (
            f"[Reflection.Assembly]::LoadWithPartialName('System.Speech') | Out-Null; "
            f"$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
            f"$synth.Rate = 0; "
            f"$synth.SetOutputToWaveFile('{escaped_out_path}'); "
            f"$synth.Speak('{escaped_text}'); "
            f"$synth.Dispose();"
        )

        try:
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and os.path.exists(out_path):
                size_kb = round(os.path.getsize(out_path) / 1024, 1)
                print(f"[OK] Generated {filename} ({size_kb} KB)")
            else:
                print(f"[FAIL] Could not generate {filename}: {result.stderr}")
        except Exception as e:
            print(f"[ERROR] Error generating {filename}: {e}")


if __name__ == "__main__":
    generate_audio_files()

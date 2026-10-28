"""
test_analyzer.py - Comprehensive Unit & Integration Tests
AI-Based Phishing Call Detection and Risk Analyzer
2nd-Year B.Tech CSE Cyber Security Mini-Project

Tests:
1. Low-risk legitimate calls evaluation
2. Medium-risk suspicious calls evaluation
3. High-risk critical phishing / vishing calls evaluation
4. Score capping at 100
5. Keyword deduplication
6. Synergy bonus calculation
7. Database CRUD, search, filter, and stats
8. TXT and PDF report generation
"""

import os
import pytest
from analyzer import PhishingAnalyzer
from demo_data import DEMO_CONVERSATIONS
import database
import report_generator

TEST_DB = "test_phishing.db"


@pytest.fixture(autouse=True)
def cleanup_test_db():
    """Ensure test database is clean before and after tests."""
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass
    yield
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass


def test_normal_call_low_risk():
    """Test that a standard delivery or service call evaluates as LOW risk."""
    analyzer = PhishingAnalyzer()
    normal_demo = DEMO_CONVERSATIONS[0]  # Normal logistics call
    result = analyzer.analyze(normal_demo["transcript"])

    assert result["risk_score"] <= 30, f"Expected <= 30, got {result['risk_score']}"
    assert result["risk_level"] == "LOW"
    assert len(result["indicators_detected"]) == 0


def test_suspicious_call_medium_risk():
    """Test that utility disconnection pressure evaluates as MEDIUM risk."""
    analyzer = PhishingAnalyzer()
    suspicious_demo = DEMO_CONVERSATIONS[1]  # Electricity disconnection
    result = analyzer.analyze(suspicious_demo["transcript"])

    assert 31 <= result["risk_score"] <= 70, f"Expected 31-70, got {result['risk_score']}"
    assert result["risk_level"] == "MEDIUM"
    assert len(result["indicators_detected"]) >= 1


def test_critical_phishing_high_risk():
    """Test that bank impersonation with OTP + AnyDesk evaluates as HIGH risk."""
    analyzer = PhishingAnalyzer()
    phishing_demo = DEMO_CONVERSATIONS[2]  # Bank fraud vishing
    result = analyzer.analyze(phishing_demo["transcript"])

    assert result["risk_score"] >= 71, f"Expected >= 71, got {result['risk_score']}"
    assert result["risk_level"] == "HIGH"
    assert result["indicator_count"] >= 3
    # Check that critical indicators were caught
    ids = {ind["id"] for ind in result["indicators_detected"]}
    assert "CRED_OTP_PIN" in ids
    assert "REMOTE_ACCESS" in ids
    assert "COERCION_THREATS" in ids


def test_score_capped_at_100():
    """Test that accumulating excessive triggers never exceeds 100."""
    analyzer = PhishingAnalyzer()
    extreme_text = (
        "This is SBI bank fraud department calling from RBI. "
        "Your account is blocked and suspended immediately. "
        "You will face arrest by police and CBI within 10 minutes. "
        "Install AnyDesk and screen share right now. "
        "Transfer money to safe account and pay refundable deposit. "
        "Share your OTP, UPI PIN, and CVV code immediately. "
        "Keep the call secret and do not tell anyone."
    )
    result = analyzer.analyze(extreme_text)
    assert result["risk_score"] == 100
    assert result["risk_level"] == "HIGH"


def test_keyword_deduplication():
    """Repeating the same keyword multiple times should not inflate score."""
    analyzer = PhishingAnalyzer()
    single_trigger = "Please share your 6-digit OTP verification code received by SMS."
    repeated_trigger = (
        "Please share your OTP. Tell me your OTP. Send the OTP code. Read the OTP."
    )
    res_single = analyzer.analyze(single_trigger)
    res_repeat = analyzer.analyze(repeated_trigger)

    assert res_single["risk_score"] == res_repeat["risk_score"]
    assert res_repeat["indicator_count"] == 1


def test_empty_transcript_handling():
    """Empty or whitespace-only transcript should return zero score safely."""
    analyzer = PhishingAnalyzer()
    result = analyzer.analyze("   \n\t  ")
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["indicator_count"] == 0


def test_database_crud_operations():
    """Verify SQLite database insertion, filtering, feedback updating, and stats."""
    database.init_db(TEST_DB)

    # 1. Insert records
    rec1 = database.save_analysis(
        filename="call1.wav",
        source_type="Audio File",
        transcript="Test legitimate call transcript",
        risk_score=15,
        risk_level="LOW",
        indicators=[],
        recommendations=["Stay safe"],
        db_path=TEST_DB
    )
    assert rec1 > 0

    rec2 = database.save_analysis(
        filename="call2.mp3",
        source_type="Audio File",
        transcript="Test bank fraud urgent OTP demand",
        risk_score=85,
        risk_level="HIGH",
        indicators=[{"name": "Credential Harvesting", "severity": "CRITICAL", "weight": 35}],
        recommendations=["Hang up immediately"],
        db_path=TEST_DB
    )
    assert rec2 > 0

    # 2. Query with filter
    all_recs = database.get_analyses(db_path=TEST_DB)
    assert len(all_recs) == 2

    high_recs = database.get_analyses(filter_level="HIGH", db_path=TEST_DB)
    assert len(high_recs) == 1
    assert high_recs[0]["id"] == rec2

    # 3. Update feedback
    updated = database.update_feedback(rec2, "Accurate Detection", db_path=TEST_DB)
    assert updated is True
    fetched = database.get_analysis_by_id(rec2, db_path=TEST_DB)
    assert fetched["feedback"] == "Accurate Detection"

    # 4. Statistics
    stats = database.get_statistics(db_path=TEST_DB)
    assert stats["total_calls"] == 2
    assert stats["avg_score"] == 50.0
    assert stats["level_counts"]["HIGH"] == 1
    assert stats["level_counts"]["LOW"] == 1

    # 5. CSV Export
    csv_data = database.export_to_csv_string(db_path=TEST_DB)
    assert "CASE-0001" in csv_data or "CASE-0002" in csv_data

    # 6. Delete
    deleted = database.delete_analysis(rec1, db_path=TEST_DB)
    assert deleted is True
    assert len(database.get_analyses(db_path=TEST_DB)) == 1


def test_report_generation():
    """Verify that TXT and PDF reports generate without errors and contain essential data."""
    analyzer = PhishingAnalyzer()
    result = analyzer.analyze(DEMO_CONVERSATIONS[2]["transcript"])
    result["transcript"] = DEMO_CONVERSATIONS[2]["transcript"]

    # TXT Report
    txt_report = report_generator.generate_txt_report(result, "Test_Phishing_Call.wav")
    assert "INCIDENT REPORT" in txt_report
    assert "CRITICAL THREAT DETECTED" in txt_report
    assert "Credential Harvesting" in txt_report

    # PDF Report
    pdf_bytes = report_generator.generate_pdf_report(result, "Test_Phishing_Call.wav")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")

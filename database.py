"""
database.py - SQLite Local Persistence Engine
AI-Based Phishing Call Detection and Risk Analyzer
2nd-Year B.Tech CSE Cyber Security Mini-Project

Stores analysis records locally, enables search/filtering, re-opening past
cases, tracking user accuracy feedback, and computing real-time statistics.
"""

import sqlite3
import json
import csv
import io
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_FILE = "phishing_analysis.db"


def get_connection(db_path: str = DB_FILE) -> sqlite3.Connection:
    """Creates a database connection with dictionary-like row access."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DB_FILE) -> None:
    """Initializes the SQLite database tables if they do not exist."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS call_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source_type TEXT NOT NULL,
                filename TEXT NOT NULL,
                transcript TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                recommendations_json TEXT NOT NULL,
                breakdown_json TEXT,
                feedback TEXT DEFAULT 'Unrated',
                notes TEXT DEFAULT ''
            )
        """)
        # Index for fast search and filtering
        conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_level ON call_analyses(risk_level)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON call_analyses(created_at)")
    conn.close()


def save_analysis(
    filename: str,
    source_type: str,
    transcript: str,
    risk_score: int,
    risk_level: str,
    indicators: List[Dict[str, Any]],
    recommendations: List[str],
    breakdown: Optional[Dict[str, Any]] = None,
    notes: str = "",
    db_path: str = DB_FILE
) -> int:
    """
    Saves a newly analyzed call record to SQLite.
    
    Returns:
        The auto-generated record ID.
    """
    init_db(db_path)
    conn = get_connection(db_path)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    indicators_json = json.dumps(indicators)
    recommendations_json = json.dumps(recommendations)
    breakdown_json = json.dumps(breakdown) if breakdown else "{}"

    with conn:
        cursor = conn.execute("""
            INSERT INTO call_analyses (
                created_at, source_type, filename, transcript,
                risk_score, risk_level, indicators_json, recommendations_json,
                breakdown_json, feedback, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Unrated', ?)
        """, (
            now_str, source_type, filename, transcript,
            risk_score, risk_level, indicators_json, recommendations_json,
            breakdown_json, notes
        ))
        record_id = cursor.lastrowid
    conn.close()
    return record_id


def get_analyses(
    filter_level: Optional[str] = None,
    search_query: Optional[str] = None,
    limit: int = 100,
    db_path: str = DB_FILE
) -> List[Dict[str, Any]]:
    """
    Fetches saved analysis records with optional filtering and keyword search.
    """
    init_db(db_path)
    conn = get_connection(db_path)
    query = "SELECT * FROM call_analyses WHERE 1=1"
    params = []

    if filter_level and filter_level.upper() != "ALL":
        query += " AND risk_level = ?"
        params.append(filter_level.upper())

    if search_query and search_query.strip():
        term = f"%{search_query.strip()}%"
        query += " AND (filename LIKE ? OR transcript LIKE ? OR indicators_json LIKE ?)"
        params.extend([term, term, term])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, params)
    rows = cursor.fetchall()
    results = []

    for r in rows:
        results.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "source_type": r["source_type"],
            "filename": r["filename"],
            "transcript": r["transcript"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "indicators": json.loads(r["indicators_json"]),
            "recommendations": json.loads(r["recommendations_json"]),
            "breakdown": json.loads(r["breakdown_json"]) if r["breakdown_json"] else {},
            "feedback": r["feedback"],
            "notes": r["notes"]
        })

    conn.close()
    return results


def get_analysis_by_id(record_id: int, db_path: str = DB_FILE) -> Optional[Dict[str, Any]]:
    """Retrieves a single analysis record by ID."""
    init_db(db_path)
    conn = get_connection(db_path)
    cursor = conn.execute("SELECT * FROM call_analyses WHERE id = ?", (record_id,))
    r = cursor.fetchone()
    conn.close()

    if not r:
        return None

    return {
        "id": r["id"],
        "created_at": r["created_at"],
        "source_type": r["source_type"],
        "filename": r["filename"],
        "transcript": r["transcript"],
        "risk_score": r["risk_score"],
        "risk_level": r["risk_level"],
        "indicators": json.loads(r["indicators_json"]),
        "recommendations": json.loads(r["recommendations_json"]),
        "breakdown": json.loads(r["breakdown_json"]) if r["breakdown_json"] else {},
        "feedback": r["feedback"],
        "notes": r["notes"]
    }


def update_feedback(record_id: int, feedback_value: str, db_path: str = DB_FILE) -> bool:
    """Updates user accuracy rating ('Accurate', 'False Positive', 'False Negative')."""
    init_db(db_path)
    conn = get_connection(db_path)
    with conn:
        cursor = conn.execute(
            "UPDATE call_analyses SET feedback = ? WHERE id = ?",
            (feedback_value, record_id)
        )
        updated = cursor.rowcount > 0
    conn.close()
    return updated


def delete_analysis(record_id: int, db_path: str = DB_FILE) -> bool:
    """Deletes an analysis record."""
    init_db(db_path)
    conn = get_connection(db_path)
    with conn:
        cursor = conn.execute("DELETE FROM call_analyses WHERE id = ?", (record_id,))
        deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def clear_all_analyses(db_path: str = DB_FILE) -> None:
    """Clears all records in the table (useful for demonstration reset)."""
    init_db(db_path)
    conn = get_connection(db_path)
    with conn:
        conn.execute("DELETE FROM call_analyses")
    conn.close()


def get_statistics(db_path: str = DB_FILE) -> Dict[str, Any]:
    """
    Computes summary metrics and distributions across all saved call records.
    """
    init_db(db_path)
    conn = get_connection(db_path)

    cursor = conn.execute("SELECT COUNT(*) as total, AVG(risk_score) as avg_score FROM call_analyses")
    row = cursor.fetchone()
    total_calls = row["total"] or 0
    avg_score = round(row["avg_score"] or 0, 1)

    # Risk level counts
    cursor = conn.execute("""
        SELECT risk_level, COUNT(*) as count 
        FROM call_analyses 
        GROUP BY risk_level
    """)
    level_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for r in cursor.fetchall():
        if r["risk_level"] in level_counts:
            level_counts[r["risk_level"]] = r["count"]

    # Feedback breakdown
    cursor = conn.execute("""
        SELECT feedback, COUNT(*) as count 
        FROM call_analyses 
        GROUP BY feedback
    """)
    feedback_counts = {}
    for r in cursor.fetchall():
        feedback_counts[r["feedback"]] = r["count"]

    # Top detected attack indicators
    cursor = conn.execute("SELECT indicators_json FROM call_analyses")
    indicator_freq = {}
    for r in cursor.fetchall():
        try:
            indicators = json.loads(r["indicators_json"])
            for ind in indicators:
                name = ind.get("name", "Unknown")
                indicator_freq[name] = indicator_freq.get(name, 0) + 1
        except Exception:
            continue

    conn.close()

    sorted_indicators = sorted(indicator_freq.items(), key=lambda x: x[1], reverse=True)

    return {
        "total_calls": total_calls,
        "avg_score": avg_score,
        "level_counts": level_counts,
        "feedback_counts": feedback_counts,
        "top_indicators": sorted_indicators[:8]
    }


def export_to_csv_string(db_path: str = DB_FILE) -> str:
    """Exports all analysis records into a formatted CSV string."""
    init_db(db_path)
    conn = get_connection(db_path)
    cursor = conn.execute("""
        SELECT id, created_at, source_type, filename, risk_score, risk_level, 
               feedback, indicators_json, transcript
        FROM call_analyses 
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Case ID", "Timestamp", "Source", "Filename", "Risk Score (0-100)",
        "Risk Level", "User Feedback", "Indicators Detected", "Transcript Excerpt"
    ])

    for r in rows:
        try:
            indicators_list = json.loads(r["indicators_json"])
            indicator_names = "; ".join([ind.get("name", "") for ind in indicators_list])
        except Exception:
            indicator_names = ""

        # Truncate transcript excerpt for CSV readability
        transcript_sample = (r["transcript"][:150] + "...") if len(r["transcript"]) > 150 else r["transcript"]
        transcript_clean = transcript_sample.replace("\n", " ")

        writer.writerow([
            f"CASE-{r['id']:04d}",
            r["created_at"],
            r["source_type"],
            r["filename"],
            r["risk_score"],
            r["risk_level"],
            r["feedback"],
            indicator_names,
            transcript_clean
        ])

    return output.getvalue()

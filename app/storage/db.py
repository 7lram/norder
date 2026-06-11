import sqlite3
from pathlib import Path


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn, schema_path):
    schema = Path(schema_path).read_text(encoding="utf-8")
    conn.executescript(schema)
    for table in [
        "events",
        "alerts",
        "incidents",
        "ai_analysis_results",
        "response_actions",
        "sentry_issue_comments",
        "notifications",
        "watchlist",
    ]:
        conn.execute(f"DELETE FROM {table}")
    conn.execute("DELETE FROM sqlite_sequence")
    conn.commit()

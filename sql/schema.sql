CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  source_event_id TEXT,
  source_issue_id TEXT,
  timestamp TEXT,
  event_type TEXT,
  source_ip TEXT,
  user_id_hash TEXT,
  session_id_hash TEXT,
  endpoint TEXT,
  method TEXT,
  status_code INTEGER,
  user_agent TEXT,
  payload TEXT,
  exception_type TEXT,
  message TEXT,
  raw_event TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  source_ip TEXT,
  endpoint TEXT,
  title TEXT NOT NULL,
  description TEXT,
  evidence_json TEXT,
  dedup_key TEXT,
  status TEXT DEFAULT 'open',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  source_ip TEXT,
  endpoint TEXT,
  alert_ids TEXT,
  sentry_issue_ids TEXT,
  event_count INTEGER DEFAULT 1,
  summary TEXT,
  recommended_playbook TEXT,
  status TEXT DEFAULT 'open',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_analysis_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  risk_score INTEGER,
  risk_reason TEXT,
  analyst_summary TEXT,
  recommended_playbook TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS response_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  action_type TEXT NOT NULL,
  target_type TEXT,
  target_value TEXT,
  mode TEXT DEFAULT 'dry-run',
  status TEXT NOT NULL,
  result_message TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sentry_issue_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  issue_id TEXT,
  comment_body TEXT,
  mode TEXT DEFAULT 'dry-run',
  status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  channel TEXT,
  message TEXT,
  mode TEXT DEFAULT 'dry-run',
  status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  watch_type TEXT NOT NULL,
  value TEXT NOT NULL,
  reason TEXT,
  source_incident_id INTEGER,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

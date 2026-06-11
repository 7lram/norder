# Norder Sentry SIEM/SOAR Platform MVP

This is a refactored version of the Norder Sentry SIEM/SOAR MVP.

The original demo was split into a more platform-like structure:

```text
app/
  collectors/
  normalizers/
  detectors/
  correlation/
  ai/
  responders/
  storage/
  models/

data/
sql/
playbooks/
docs/
tests/
```

## Purpose

The project reuses Sentry events as security operation data. Sentry is not treated as a SIEM replacement. Instead, Sentry events are normalized into internal security events, then rule-based detectors create alerts, alerts are correlated into incidents, and SOAR playbooks execute dry-run responses.

## Pipeline

```text
Sentry JSONL events
  -> collector
  -> normalizer
  -> events table
  -> detectors
  -> alerts table
  -> incident correlator
  -> incidents table
  -> risk analysis
  -> SOAR playbook
  -> response_actions / notifications / Sentry comment records
```

## Run

```bash
python3 -m app.main --demo
```

Run from this folder:

```bash
cd outputs/github_ready/norder-sentry-platform
python3 -m app.main --demo
```

## Current Scope

Implemented:

- JSONL Sentry event collector
- Sentry event normalizer
- Internal Event/Alert/Incident models
- Separate detectors for auth errors, SMS abuse, payload attack, admin discovery, sensitive error, endpoint spike, IP error burst
- Alert to Incident correlation
- Risk scoring
- SOAR action router
- Dry-run notification, Sentry comment, IP block candidate, WAF/rate-limit recommendation records

Extension points:

- `collectors/sentry_collector.py`
- `collectors/sentry_webhook_receiver.py`
- `collectors/api_log_collector.py`
- `normalizers/api_event_normalizer.py`

These files are placeholders for production integrations.

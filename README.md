# Norder Sentry SIEM/SOAR Platform MVP

This is Norder Sentry SIEM/SOAR MVP.

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

## Optional External AI Triage

By default, the project uses local rule-based triage so the demo works without network access or API keys.

To use Claude through the Anthropic API, create a local `.env` file:

```bash
cp .env.example .env
```

Then edit `.env`:

```bash
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-anthropic-api-key
AI_API_URL=https://api.anthropic.com/v1/messages
AI_MODEL=claude-haiku-4-5
```

Run the demo. The app automatically loads `.env`:

```bash
python3 -m app.main --demo --external-ai
```

The same client can also call an OpenAI-compatible chat completions API:

```bash
AI_PROVIDER=openai
AI_API_KEY=your-api-key
AI_API_URL=https://api.openai.com/v1/chat/completions
AI_MODEL=gpt-4o-mini
```

Then run:

```bash
python3 -m app.main --demo --external-ai
```

Do not commit real API keys. `.env` is ignored by git, and `.env.example` contains only empty/example values.

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
- Separate detectors for auth errors, SMS abuse, payload attack, admin discovery, sensitive error, endpoint spike, IP error burst, legacy API bypass, Sentry event poisoning, semantic HTTP 200 errors, and stadium-specific behavior
- Alert to Incident correlation
- Risk scoring
- SOAR action router
- Dry-run notification, Sentry comment, IP block candidate, WAF/rate-limit recommendation records

## Stadium-Specific Detection Rules

The MVP includes Norder-specific stadium context rules using `contexts.norder` fields inside Sentry events.

Expected context fields:

```json
{
  "game_phase": "inning_break",
  "seat_block": "A103",
  "network_type": "stadium_wifi",
  "entry_channel": "qr",
  "qr_scan_id": "qr-A103-12"
}
```

Implemented rules:

- `STADIUM-001`: state-changing order request during a stadium peak phase without a valid QR or Kakao app entry context
- `STADIUM-002`: same user, session, or IP appears in multiple seat blocks within five minutes
- `STADIUM-003`: endpoint errors cluster during stadium peak phases such as inning break or cleaning time
- `STADIUM-004`: same user or session accesses multiple venues within a short window
- `STADIUM-005`: request references a venue outside the valid venue whitelist
- `STADIUM-006`: sensitive activity occurs outside configured game schedules
- `STADIUM-007`: sensitive request comes from an untrusted network stub such as cloud, VPN, overseas, or unknown
- `STADIUM-008`: payment API is called without prior cart or order flow

For Kakao app orders, the detector accepts `entry_channel=kakao_app` when a Kakao session and venue/store context are present. These rules are intended to reduce false positives by comparing suspicious activity with baseball stadium traffic patterns instead of applying only generic web thresholds.

## Tuned Norder Security Rules

- `SMS-001` / `SMS-002` in `sms_abuse.py`: treats stadium Wi-Fi as a shared NAT and uses phone-based grouping, while server/cloud networks and automation-like clients are suspicious immediately.
- `VERSION-001` / `VERSION-002` in `version_downgrade.py`: detects legacy v1 API use and the stronger pattern of being blocked on v2 before succeeding on v1.
- `SENTRY-001` / `SENTRY-002` in `sentry_poisoning.py`: detects concentrated Sentry events from server/cloud networks and events with invalid venue or seat context.
- `SEMANTIC-001` in `semantic_error.py`: detects cases where HTTP status is 200 but the message/body indicates probing for non-existing venues.

Extension points:

- `collectors/sentry_collector.py`
- `collectors/sentry_webhook_receiver.py`
- `collectors/api_log_collector.py`
- `normalizers/api_event_normalizer.py`

These files are placeholders for production integrations.

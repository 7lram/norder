import json
import os
import urllib.error
import urllib.request


DEFAULT_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5"
DEFAULT_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


def analyze_with_external_ai(incident, risk_score):
    provider = os.getenv("AI_PROVIDER", "anthropic").strip().lower()

    if provider == "anthropic":
        return _call_anthropic(incident, risk_score)
    if provider == "openai":
        return _call_openai_compatible(incident, risk_score)

    raise RuntimeError(f"Unsupported AI_PROVIDER: {provider}")


def _incident_payload(incident, risk_score):
    return {
        "incident_type": incident.incident_type,
        "severity": incident.severity,
        "title": incident.title,
        "source_ip": incident.source_ip,
        "endpoint": incident.endpoint,
        "event_count": incident.event_count,
        "sentry_issue_ids": incident.sentry_issue_ids,
        "current_risk_score": risk_score,
        "current_recommended_playbook": incident.recommended_playbook,
    }


def _analysis_prompt(incident, risk_score):
    return (
        "Analyze this security incident for a SIEM/SOAR demo. "
        "Return only one JSON object. Do not include markdown, code fences, or explanation. "
        "The JSON object must have exactly these string keys: "
        "summary, risk_reason, recommended_playbook.\n\n"
        + json.dumps(_incident_payload(incident, risk_score), ensure_ascii=False)
    )


def _call_anthropic(incident, risk_score):
    api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("AI_API_KEY")
    api_url = os.getenv("AI_API_URL", DEFAULT_ANTHROPIC_URL)
    model = os.getenv("AI_MODEL", DEFAULT_ANTHROPIC_MODEL)

    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY or AI_API_KEY is not set")

    payload = {
        "model": model,
        "max_tokens": 500,
        "temperature": 0.2,
        "system": (
            "You are a security incident triage assistant. "
            "Choose a playbook that matches the incident type and response risk. "
            "Your entire response must be valid JSON only."
        ),
        "messages": [
            {
                "role": "user",
                "content": _analysis_prompt(incident, risk_score),
            }
        ],
    }

    request = urllib.request.Request(
        api_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    body = _send_json_request(request)
    text = "".join(part.get("text", "") for part in body.get("content", []) if part.get("type") == "text")
    return _parse_json_response(text)


def _call_openai_compatible(incident, risk_score):
    api_key = os.getenv("AI_API_KEY")
    api_url = os.getenv("AI_API_URL", DEFAULT_OPENAI_URL)
    model = os.getenv("AI_MODEL", DEFAULT_OPENAI_MODEL)

    if not api_key:
        raise RuntimeError("AI_API_KEY is not set")

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a security incident triage assistant. "
                    "Return only compact JSON with keys: summary, risk_reason, recommended_playbook."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(_incident_payload(incident, risk_score), ensure_ascii=False),
            },
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }

    request = urllib.request.Request(
        api_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    body = _send_json_request(request)
    content = body["choices"][0]["message"]["content"]
    return _parse_json_response(content)


def _send_json_request(request):
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"AI API HTTP error {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"AI API connection error: {exc.reason}") from exc


def _parse_json_response(text):
    cleaned = (text or "").strip()
    if not cleaned:
        raise RuntimeError("AI API returned an empty text response")

    if cleaned.startswith("```"):
        cleaned = cleaned.removeprefix("```json").removeprefix("```").strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(cleaned[start:end + 1])
        preview = cleaned[:200].replace("\n", " ")
        raise RuntimeError(f"AI API returned non-JSON text: {preview}")

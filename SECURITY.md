# Security Policy

## Authentication

The API uses a simple shared-secret authentication mechanism:

- **Header**: `x-api-key`
- **Secret**: Set via the `MY_APP_SECRET` environment variable
- When `MY_APP_SECRET` is set and non-empty, all requests **must** include a matching `x-api-key` header
- Requests with a missing or incorrect key receive `HTTP 403 Forbidden`
- When `MY_APP_SECRET` is empty or unset, authentication is disabled (dev mode)

## Secrets Handling

| Secret | Storage | Notes |
|---|---|---|
| `OPENAI_API_KEY` | `.env` file, environment variable | Never committed to VCS |
| `MY_APP_SECRET` | `.env` file, environment variable | Shared with evaluator at submission |

- `.env.example` provides a template with placeholder values
- `.env` is listed in `.gitignore` and **never committed**
- No secrets appear in source code, logs, or responses

## Data Retention

- **Storage**: All session data is stored **in-memory only** (Python dict)
- **Persistence**: No data is written to disk or database
- **Lifetime**: All data is cleared when the process restarts
- **No PII stored**: Conversation text is held in memory during the session only

## Log Redaction

All log output is sanitized to prevent PII leakage. The API uses a `_redact()` utility:

### What IS logged

```
📥 Session: abc-123-def, msg_len: 85
📤 Reply length: 120, scam_detected: True
🧠 LLM extraction completed (turn 5)
✅ Handshake/ping detected
```

### What is NOT logged (redacted)

```
❌ Full message body / raw JSON payload
❌ API keys or secret values
❌ Phone numbers, bank accounts, emails
❌ Conversation history text
❌ Extracted intelligence values
```

### Redaction utility

```python
def _redact(text: str) -> str:
    """Redact sensitive data from log output."""
    text = re.sub(r'\+?\d[\d\s\-]{8,}\d', '[REDACTED_PHONE]', text)
    text = re.sub(r'[\w.+-]+@[\w.-]+\.\w+', '[REDACTED_EMAIL]', text)
    text = re.sub(r'\b\d{10,18}\b', '[REDACTED_DIGITS]', text)
    return text
```

### Example

| Input | Output |
|---|---|
| `"Call +91-9876543210"` | `"Call [REDACTED_PHONE]"` |
| `"Email: user@gmail.com"` | `"Email: [REDACTED_EMAIL]"` |
| `"Account: 1234567890123456"` | `"Account: [REDACTED_DIGITS]"` |

## CORS

- **Development**: `allow_origins=["*"]` for local testing
- **Production**: Should be set to your specific domain(s). See README Deployment Checklist.

## Vulnerability Reporting

If you discover a vulnerability, please contact the team directly.

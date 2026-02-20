# Honeypot API — Scam Detection & Intelligence Extraction

> by Team Yantraksh — Chethan Vasthaw Tippani & Mithuna Somireddy
> Built for the GUVI Hackathon 2025

## What this does

This is a honeypot API that pretends to be an old man named "Robert D'Souza" who talks to scammers. The idea is simple — when a scammer calls, Robert D'Souza acts confused and scared (like any 74-year-old retired teacher would), keeps the scammer talking, and quietly extracts all their information — phone numbers, bank accounts, UPI IDs, phishing links, emails, everything.

The longer we keep them on the line, the more we get out of them.

## How it works

1. Scammer sends a message (like "your account is blocked, share OTP")
2. Our API responds as Robert D'Souza — a retired schoolteacher who's scared but cooperative
3. Robert asks questions: "what is your name sir?", "which branch?", "give me your number I'll call back"
4. Behind the scenes, we extract every piece of info the scammer drops
5. We keep this going for as many turns as possible
6. At the end, we output everything we found

### The Robert D'Souza Strategy

We built Robert D'Souza with 3 phases:

- **Early turns (1-2):** He's confused and scared. Asks basic questions like "who are you?" and "which account?"
- **Middle turns (3-5):** He starts "cooperating" but keeps asking for verification — employee ID, branch name, official number
- **Late turns (6+):** He gets desperate — "my app crashed, send me your bank account for NEFT", "battery dying, give me number to call back"

Each phase is designed to extract maximum info without making the scammer suspicious.

## Tech Stack

- **Python + FastAPI** — lightweight and fast API framework
- **OpenAI API** — we use gpt-4o-mini for generating natural English responses
- **Regex extraction** — separate module with patterns for phone numbers, UPI IDs, bank accounts, URLs, emails, case IDs, policy numbers, order numbers
- **Obfuscation handling** — digit normalization, homoglyph/leetspeak URL detection
- **LLM post-validation** — all LLM-extracted intelligence is validated against the conversation text to reject hallucinations
- **Deployed on Render.com**

## Setup Instructions

1. Clone the repo

```bash
git clone https://github.com/Chethan4255/honeypot-api
cd honeypot-api
```

2. Install dependencies

```bash
pip install -r requirements.txt
```

3. Set up environment variables

```bash
cp .env.example .env
```

Then edit `.env` and add your actual keys:
- `OPENAI_API_KEY` — get it from https://platform.openai.com
- `MY_APP_SECRET` — any string you want, this is your API key for authentication

4. Run the app

```bash
python -m app.main
```

or

```bash
uvicorn app.main:app --host 0.0.0.0 --port 10000
```

The API will be running at `http://localhost:10000`

## API Endpoint

- **URL:** `POST /detect` (also available at `/detect-scam`, `/honeypot`, `/api/detect`)
- **Auth:** `x-api-key` header (enforced when `MY_APP_SECRET` is set)
- **Content-Type:** `application/json`

### Request body

```json
{
  "sessionId": "some-uuid",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account compromised. Share OTP now.",
    "timestamp": 1739000000000
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response

```json
{
  "status": "success",
  "reply": "Oh dear, what happened to my account? I am scared. Can you tell me your name and employee ID sir?",
  "sessionId": "some-uuid",
  "scamDetected": true,
  "totalMessagesExchanged": 2,
  "engagementDurationSeconds": 15,
  "finalOutput": {
    "sessionId": "some-uuid",
    "scamDetected": true,
    "totalMessagesExchanged": 2,
    "engagementDurationSeconds": 15,
    "extractedIntelligence": {
      "phoneNumbers": [
        "+91-9876543210"
      ],
      "bankAccounts": [],
      "upiIds": [],
      "phishingLinks": [],
      "emailAddresses": [],
      "caseIds": [],
      "policyNumbers": [],
      "orderNumbers": []
    },
    "agentNotes": "Scam type identified: bank_fraud. Red flags: urgency, requesting OTP...",
    "scamType": "bank_fraud",
    "confidenceLevel": 0.85,
    "_detailedIntelligence": {
      "phoneNumbers": [
        {"value": "+91-9876543210", "confidence": 0.95, "provenance": {"turn": 3, "timestamp": 1670000000.0, "source": "regex"}}
      ],
      "bankAccounts": [],
      "upiIds": [],
      "phishingLinks": [],
      "emailAddresses": [],
      "caseIds": []
    }
  }
}
```

## Testing

Run the test suite:

```bash
pip install pytest httpx
pytest tests/ -v
```

Test coverage includes:
- **Intelligence extraction**: all 8 data types, false-positive rejection, obfuscation handling
- **LLM validation**: hallucinated values rejected, real values preserved
- **Scenario replay**: bank fraud scenario with planted data
- **Auth enforcement**: correct key → 200, wrong key → 403
- **Scam detection**: evidence-based True/False verification

## Our Approach

### Scam Detection
- We detect scams using evidence-based scoring: red flags, extracted intelligence, keyword matching, and scam type classification
- The detection is content-driven and generic — no scenario-specific hardcoding
- See [CODE_REVIEW_NOTES.md](CODE_REVIEW_NOTES.md) for details

### Intelligence Extraction
- Dedicated extraction module (`intel_extractor.py`) with regex patterns for ALL data types
- Phone numbers — handles +91 format, 10 digit, with dashes/spaces, plus spaced-digit obfuscation
- Bank accounts — 10-18 digit numbers that aren't phone numbers or timestamps
- UPI IDs — `name@bankhandle` format, we know 30+ UPI handles
- URLs — catches http links, www links, domain-path patterns, and homoglyph/leetspeak detection
- Emails — standard email format, separated from UPI IDs using domain checking
- Case IDs, policy numbers, order numbers — pattern matching with false-positive filtering
- LLM second-pass extraction with post-validation to reject hallucinated values

### Engagement Strategy
- Phase-based conversation design (confused → cooperative → desperate)
- Natural English language with Indian expressions makes it believable
- Every response asks at least one question to keep things going
- We reference red flags and scammer details to show we're paying attention
- Goal: 8+ turns per conversation

### Red Flag Identification
- We track urgency, OTP requests, PIN requests, threats, impersonation, suspicious links
- Each flag is logged in the agent notes
- Target: 5+ unique red flags per conversation

## Deployment Checklist

Before deploying to production:

- [ ] Set `MY_APP_SECRET` environment variable and communicate it to the evaluator
- [ ] Set CORS `allow_origins` to your actual domain(s) instead of `["*"]`
- [ ] Verify API response times are consistently under 30 seconds
- [ ] Ensure `OPENAI_API_KEY` is set in the deployment environment
- [ ] Run `pytest tests/ -v` to validate all tests pass
- [ ] Verify the API is accessible at your deployment URL

## File Structure

```
honeypot-api/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI endpoints + auth + log redaction
│   ├── agent.py              # LLM-powered Robert D'Souza persona
│   ├── intel_extractor.py    # Regex intelligence extraction + LLM validation
│   ├── session_manager.py    # Session state, scam detection, final output
│   └── models.py             # Pydantic data models with provenance
├── tests/
│   ├── test_intel_extractor.py  # Extraction + obfuscation tests
│   └── test_self_eval.py        # Scenario replay + auth + structure tests
├── .env.example
├── requirements.txt
├── render.yaml
├── SECURITY.md               # Auth, secrets, data retention, log redaction
├── CODE_REVIEW_NOTES.md      # Why there's no hardcoded detection
└── README.md
```

## Why this approach

We tried a few things before landing on this:

1. First we tried keyword matching only — too robotic, scammers wouldn't engage
2. Then we tried GPT-4o — good responses but expensive and slow
3. Finally settled on OpenAI + gpt-4o-mini — fast responses, natural conversation, and easily handles the load

The Robert D'Souza persona works because:
- Old confused uncle is the most common target for scammers — they buy it immediately
- English with Indian expressions sounds natural
- The "helpful but slow" personality keeps scammers patient
- Asking for "verification" gives us an excuse to extract their info

---

Made with frustration and chai by Team Yantraksh ☕

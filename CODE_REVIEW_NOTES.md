# Code Review Notes

This document explains how the codebase ensures **no test-specific hardcoding** and demonstrates compliance with the GUVI Hackathon evaluation rules.

## No Hardcoded Detection

### Evidence-based scam detection

`scamDetected` is **not hardcoded to True**. It is computed dynamically by `SessionManager._compute_scam_detected()` which scores evidence from:

- **Red flags**: urgency, OTP requests, threats, impersonation (keyword-based pattern matching against a generic list)
- **Extracted intelligence**: phone numbers, bank accounts, UPI IDs, URLs, emails (regex-based extraction)
- **Scam type classification**: keyword scoring across 9 fraud categories
- **Turn count**: multiple turns of engagement increase confidence

The threshold is low (score ≥ 2) because the API is a honeypot designed to receive scam traffic, but the detection is still content-driven — benign messages return `scamDetected: false`.

### Generic extraction, not scenario-specific

The intelligence extraction module (`intel_extractor.py`) uses:

- **Regex patterns** that match any phone number, bank account, UPI ID, email, or URL in any format — not specific to test scenarios
- **Obfuscation handling**: digit normalization (spaced digits collapsed), homoglyph/leetspeak URL detection
- **LLM second-pass extraction**: uses the language model to find intelligence that regex might miss, with **post-validation** that rejects any value not actually present in the conversation text

### No evaluator detection

The code does not:
- Check for any evaluator-specific headers, IPs, or traffic patterns
- Respond differently based on known test data
- Pre-map answers to specific scenarios

## Test Coverage

| Test File | What It Verifies |
|---|---|
| `tests/test_intel_extractor.py` | All 8 extraction types, false-positive rejection, obfuscation handling, LLM validation |
| `tests/test_self_eval.py` | PDF scenario replay with planted data, auth 200/403, final output structure, scam detection logic |

### Key test assertions

1. **Planted data extraction**: Replays the bank fraud scenario from the PDF and asserts that `finalOutput.extractedIntelligence` includes `+91-9876543210`, `1234567890123456`, `scammer.fraud@fakebank`, `support@fakebank.com`
2. **Scam detection logic**: Verifies that scam content → `scamDetected: true`, benign content → `scamDetected: false`
3. **Auth enforcement**: Correct key → 200, wrong key → 403, missing key → 403
4. **False-positive rejection**: Timestamps, common words, and phone numbers are not misclassified as bank accounts or case IDs
5. **Obfuscation**: Spaced digits (e.g., `9 8 7 6 5 4 3 2 1 0`) and leetspeak domains (e.g., `amaz0n`) are detected

## LLM Usage

- **Conversation generation**: Uses OpenAI API (gpt-4o-mini) with anti-refusal safeguards and character consistency
- **Intelligence extraction**: LLM second-pass with `response_format: json_object` and temperature 0.1
- **Post-validation**: All LLM-extracted values are verified against the actual conversation text before being included. Hallucinated values are rejected.
- **Timeout**: All LLM calls have a 25-second timeout to stay under the 30-second PDF requirement

## Security Practices

See [SECURITY.md](SECURITY.md) for:
- Authentication enforcement
- Log redaction (no PII in stdout)
- In-memory-only data retention
- CORS configuration guidance

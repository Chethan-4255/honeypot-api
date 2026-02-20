"""
Self-evaluation tests — replays sample scenarios from the PDF evaluation document,
validates final output structure, auth enforcement, and scam detection logic.
"""

import os
import pytest
from fastapi.testclient import TestClient


# ── Setup ────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Create test client with no API key requirement."""
    os.environ["MY_APP_SECRET"] = ""
    from app.main import app
    return TestClient(app)


@pytest.fixture
def auth_client():
    """Create test client with API key requirement."""
    os.environ["MY_APP_SECRET"] = "test-secret-key-123"
    from app.main import app
    return TestClient(app)


# ── Bank Fraud Scenario Replay ──────────────────────────────────

BANK_FRAUD_MESSAGES = [
    {
        "sender": "scammer",
        "text": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "timestamp": 1771585363308,
    },
    {
        "sender": "user",
        "text": "Oh dear, my money! Please help me sir! Who are you?",
        "timestamp": 1771585364300,
    },
    {
        "sender": "scammer",
        "text": "Your account number is 1234567890123456; please provide the OTP sent to your phone immediately to secure your account.",
        "timestamp": 1771585369751,
    },
    {
        "sender": "user",
        "text": "You said my account number is 1234567890123456? But how can I trust you?",
        "timestamp": 1771585370490,
    },
    {
        "sender": "scammer",
        "text": "You can call me back at +91-9876543210, but please send the OTP right away.",
        "timestamp": 1771585376030,
    },
    {
        "sender": "user",
        "text": "Thank you sir, let me write it down.",
        "timestamp": 1771585376900,
    },
    {
        "sender": "scammer",
        "text": "Sure, you can reach me at support@fakebank.com and my UPI ID is scammer.fraud@fakebank.",
        "timestamp": 1771585377996,
    },
]


class TestBankFraudScenario:
    """Replay the bank fraud sample scenario from the PDF and verify extraction."""

    def test_final_output_includes_planted_data(self, client):
        """
        Send messages with planted fake data and verify finalOutput
        includes all extracted intelligence.
        """
        # Send the final scammer message with full conversation history
        response = client.post("/detect", json={
            "sessionId": "test-bank-fraud-001",
            "message": {
                "sender": "scammer",
                "text": BANK_FRAUD_MESSAGES[-1]["text"],
                "timestamp": BANK_FRAUD_MESSAGES[-1]["timestamp"],
            },
            "conversationHistory": BANK_FRAUD_MESSAGES[:-1],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        })

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "reply" in data
        assert "finalOutput" in data

        fo = data["finalOutput"]

        # Required fields present
        assert "sessionId" in fo
        assert "scamDetected" in fo
        assert "extractedIntelligence" in fo

        # Scam should be detected (evidence-based)
        assert fo["scamDetected"] is True

        # Check extracted intelligence for planted data (flat string arrays)
        intel = fo["extractedIntelligence"]

        # Phone number planted: +91-9876543210
        phone_vals = intel.get("phoneNumbers", [])
        assert any("9876543210" in str(v) for v in phone_vals), \
            f"Planted phone +91-9876543210 not found in: {phone_vals}"

        # Bank account planted: 1234567890123456
        bank_vals = intel.get("bankAccounts", [])
        assert any("1234567890123456" in str(v) for v in bank_vals), \
            f"Planted bank account not found in: {bank_vals}"

        # UPI ID planted: scammer.fraud@fakebank
        upi_vals = intel.get("upiIds", [])
        assert any("scammer.fraud@fakebank" in str(v) for v in upi_vals), \
            f"Planted UPI ID not found in: {upi_vals}"

        # Email planted: support@fakebank.com
        email_vals = intel.get("emailAddresses", [])
        assert any("support@fakebank.com" in str(v) for v in email_vals), \
            f"Planted email not found in: {email_vals}"

    def test_final_output_structure(self, client):
        """Verify all required and optional fields are present."""
        response = client.post("/detect", json={
            "sessionId": "test-structure-001",
            "message": {
                "sender": "scammer",
                "text": "URGENT: Your account has been blocked!",
                "timestamp": 1771585363308,
            },
            "conversationHistory": [],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        })

        assert response.status_code == 200
        fo = response.json()["finalOutput"]

        # Required fields (PDF scoring)
        assert "sessionId" in fo
        assert "scamDetected" in fo
        assert "extractedIntelligence" in fo

        # Optional fields (bonus points)
        assert "totalMessagesExchanged" in fo
        assert "engagementDurationSeconds" in fo

    def test_flat_intelligence_format(self, client):
        """Verify intelligence items are flat string arrays (evaluator format)."""
        response = client.post("/detect", json={
            "sessionId": "test-flat-format-001",
            "message": {
                "sender": "scammer",
                "text": "Call me at +91-9876543210 for verification.",
                "timestamp": 1771585363308,
            },
            "conversationHistory": [],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        })

        assert response.status_code == 200
        intel = response.json()["finalOutput"]["extractedIntelligence"]
        phones = intel.get("phoneNumbers", [])
        assert len(phones) >= 1, "No phone numbers extracted"

        # Items should be plain strings (evaluator format), not dicts
        item = phones[0]
        assert isinstance(item, str), f"Expected string, got {type(item)}: {item}"
        assert "9876543210" in item


# ── Authentication Tests ────────────────────────────────────────

class TestAuthentication:
    def test_correct_key_returns_200(self, auth_client):
        """With correct API key, request should succeed."""
        response = auth_client.post(
            "/detect",
            json={
                "sessionId": "test-auth-ok",
                "message": {"sender": "scammer", "text": "Test message"},
                "conversationHistory": [],
                "metadata": {},
            },
            headers={"x-api-key": "test-secret-key-123"},
        )
        assert response.status_code == 200

    def test_wrong_key_returns_403(self, auth_client):
        """With wrong API key, request should be rejected."""
        response = auth_client.post(
            "/detect",
            json={
                "sessionId": "test-auth-fail",
                "message": {"sender": "scammer", "text": "Test message"},
                "conversationHistory": [],
                "metadata": {},
            },
            headers={"x-api-key": "wrong-key"},
        )
        assert response.status_code == 403

    def test_missing_key_returns_403(self, auth_client):
        """With no API key, request should be rejected when secret is set."""
        response = auth_client.post(
            "/detect",
            json={
                "sessionId": "test-auth-missing",
                "message": {"sender": "scammer", "text": "Test message"},
                "conversationHistory": [],
                "metadata": {},
            },
        )
        assert response.status_code == 403


# ── Scam Detection Logic ───────────────────────────────────────

class TestScamDetection:
    def test_scam_content_detected(self, client):
        """Scam content should trigger scamDetected=True."""
        response = client.post("/detect", json={
            "sessionId": "test-scam-yes",
            "message": {
                "sender": "scammer",
                "text": "URGENT: Your SBI account compromised. Share OTP immediately or account will be blocked.",
            },
            "conversationHistory": [],
            "metadata": {},
        })

        assert response.status_code == 200
        assert response.json()["finalOutput"]["scamDetected"] is True

    def test_benign_content_not_detected(self, client):
        """Benign content should not trigger scamDetected=True."""
        response = client.post("/detect", json={
            "sessionId": "test-scam-no",
            "message": {
                "sender": "scammer",
                "text": "Hello, how are you today? Nice weather we are having.",
            },
            "conversationHistory": [],
            "metadata": {},
        })

        assert response.status_code == 200
        # Benign message should not have enough evidence
        assert response.json()["finalOutput"]["scamDetected"] is False


# ── Health Check ────────────────────────────────────────────────

class TestHealthCheck:
    def test_health_endpoint(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "Honeypot Active"

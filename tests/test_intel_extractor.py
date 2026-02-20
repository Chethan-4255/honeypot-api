"""
Tests for the intelligence extraction module.
Covers all 8 extraction types, false-positive rejection, obfuscation handling,
and LLM validation.
"""

import pytest
from app.intel_extractor import (
    extract_phone_numbers,
    extract_bank_accounts,
    extract_upi_ids,
    extract_emails,
    extract_urls,
    extract_case_ids,
    extract_policy_numbers,
    extract_order_numbers,
    extract_all_intelligence,
    validate_llm_intelligence,
    normalize_text,
    detect_homoglyph_domain,
)


# ── Phone Number Extraction ─────────────────────────────────────

class TestPhoneExtraction:
    def test_indian_format_with_plus(self):
        items = extract_phone_numbers("+91-9876543210")
        values = [i.value for i in items]
        assert any("9876543210" in v for v in values)

    def test_indian_format_with_spaces(self):
        items = extract_phone_numbers("+91 98765 43210")
        values = [i.value for i in items]
        assert len(values) >= 1

    def test_ten_digit_number(self):
        items = extract_phone_numbers("Call me at 9876543210")
        values = [i.value for i in items]
        assert len(values) >= 1

    def test_obfuscated_spaced_digits(self):
        """Test extraction when digits have spaces between them."""
        items = extract_phone_numbers("My number is 9 8 7 6 5 4 3 2 1 0")
        values = [i.value for i in items]
        assert len(values) >= 1, f"Failed to extract spaced digits, got: {values}"

    def test_different_separators(self):
        items = extract_phone_numbers("+91.9876.543.210")
        # May not match all separators, but should not crash
        assert isinstance(items, list)

    def test_provenance_tracking(self):
        items = extract_phone_numbers("+91-9876543210", turn=3, timestamp=1670000000.0)
        assert len(items) >= 1
        assert items[0].provenance.turn == 3
        assert items[0].provenance.source == "regex"


# ── Bank Account Extraction ─────────────────────────────────────

class TestBankAccountExtraction:
    def test_sixteen_digit_account(self):
        items = extract_bank_accounts("Account number is 1234567890123456")
        values = [i.value for i in items]
        assert "1234567890123456" in values

    def test_exclude_phone_numbers(self):
        """Phone numbers should not be extracted as bank accounts."""
        items = extract_bank_accounts("Call +91-9876543210 for help")
        values = [i.value for i in items]
        assert "9876543210" not in values

    def test_exclude_timestamps(self):
        """Epoch millisecond timestamps should not be extracted."""
        items = extract_bank_accounts("Timestamp: 1771585363308")
        values = [i.value for i in items]
        assert "1771585363308" not in values

    def test_short_numbers_excluded(self):
        """Numbers < 10 digits should not be extracted."""
        items = extract_bank_accounts("Code is 12345")
        assert len(items) == 0


# ── UPI ID Extraction ───────────────────────────────────────────

class TestUPIExtraction:
    def test_standard_upi(self):
        items = extract_upi_ids("Send to scammer.fraud@fakebank")
        values = [i.value for i in items]
        assert "scammer.fraud@fakebank" in values

    def test_paytm_upi(self):
        items = extract_upi_ids("UPI: user@paytm")
        values = [i.value for i in items]
        assert "user@paytm" in values

    def test_email_not_upi(self):
        """Email addresses should not be extracted as UPI IDs."""
        items = extract_upi_ids("Email: test@gmail.com")
        values = [i.value for i in items]
        assert len(values) == 0


# ── Email Extraction ────────────────────────────────────────────

class TestEmailExtraction:
    def test_standard_email(self):
        items = extract_emails("Contact support@fakebank.com")
        values = [i.value for i in items]
        assert "support@fakebank.com" in values

    def test_upi_not_email(self):
        """UPI IDs should not be extracted as emails."""
        items = extract_emails("UPI: user@paytm")
        values = [i.value for i in items]
        assert len(values) == 0

    def test_gmail(self):
        items = extract_emails("Send to user@gmail.com")
        values = [i.value for i in items]
        assert "user@gmail.com" in values


# ── URL Extraction ──────────────────────────────────────────────

class TestURLExtraction:
    def test_http_url(self):
        items = extract_urls("Visit http://malicious-site.com")
        values = [i.value for i in items]
        assert any("malicious-site.com" in v for v in values)

    def test_https_url(self):
        items = extract_urls("Click https://fake-bank-kyc.com/verify")
        values = [i.value for i in items]
        assert len(values) >= 1

    def test_safe_domains_excluded(self):
        items = extract_urls("Search at https://google.com/search?q=test")
        values = [i.value for i in items]
        assert len(values) == 0

    def test_homoglyph_detection(self):
        """Domains with leetspeak should be flagged."""
        assert detect_homoglyph_domain("http://amaz0n-deals.com/claim") is True
        assert detect_homoglyph_domain("http://g00gle.com/login") is True

    def test_normal_domain_no_homoglyph(self):
        assert detect_homoglyph_domain("http://example.com") is False


# ── Case ID Extraction ──────────────────────────────────────────

class TestCaseIDExtraction:
    def test_ref_format(self):
        items = extract_case_ids("Reference number REF-2023-4567")
        values = [i.value for i in items]
        assert any("2023-4567" in v or "REF-2023-4567" in v for v in values)

    def test_sbi_format(self):
        items = extract_case_ids("Case ID: SBI-12345")
        values = [i.value for i in items]
        assert any("SBI-12345" in v for v in values)

    def test_common_words_excluded(self):
        """Common English words should not be extracted as case IDs."""
        items = extract_case_ids("Please verify your identity")
        values = [i.value for i in items]
        assert "identity" not in values
        assert "verify" not in values

    def test_short_numbers_excluded(self):
        """Pure short numbers like employee IDs should be excluded."""
        items = extract_case_ids("ID is 9876")
        values = [i.value for i in items]
        assert "9876" not in values


# ── Policy Number Extraction ────────────────────────────────────

class TestPolicyExtraction:
    def test_sec_policy(self):
        items = extract_policy_numbers("Policy number 2023-SEC-001")
        values = [i.value for i in items]
        assert any("2023-SEC-001" in v for v in values)

    def test_pol_prefix(self):
        items = extract_policy_numbers("Your policy: POL-123456")
        values = [i.value for i in items]
        assert any("POL-123456" in v for v in values)


# ── Order Number Extraction ─────────────────────────────────────

class TestOrderExtraction:
    def test_order_prefix(self):
        items = extract_order_numbers("Order ORD-123456")
        values = [i.value for i in items]
        assert any("ORD-123456" in v for v in values)


# ── Normalization ───────────────────────────────────────────────

class TestNormalization:
    def test_collapse_spaced_digits(self):
        result = normalize_text("9 8 7 6 5 4 3 2 1 0")
        assert result == "9876543210"

    def test_preserve_non_digit_spaces(self):
        result = normalize_text("hello world")
        assert result == "hello world"

    def test_mixed_content(self):
        result = normalize_text("Call 9 8 7 6 5 4 3 2 1 0 for help")
        assert "9876543210" in result


# ── LLM Validation ──────────────────────────────────────────────

class TestLLMValidation:
    def test_valid_values_preserved(self):
        llm_data = {
            "phoneNumbers": ["+91-9876543210"],
            "emailAddresses": ["scammer@fake.com"],
        }
        conversation = "Call me at +91-9876543210 or email scammer@fake.com"
        result = validate_llm_intelligence(llm_data, conversation)
        assert "+91-9876543210" in result.get("phoneNumbers", [])
        assert "scammer@fake.com" in result.get("emailAddresses", [])

    def test_hallucinated_values_rejected(self):
        llm_data = {
            "phoneNumbers": ["+91-1111111111"],  # Not in conversation
            "emailAddresses": ["hallucinated@fake.com"],  # Not in conversation
        }
        conversation = "Hello, I am from the bank."
        result = validate_llm_intelligence(llm_data, conversation)
        assert len(result.get("phoneNumbers", [])) == 0
        assert len(result.get("emailAddresses", [])) == 0

    def test_empty_input(self):
        assert validate_llm_intelligence({}, "") == {}
        assert validate_llm_intelligence(None, "text") == {}

    def test_digit_matching(self):
        """Values should be found even if formatting differs."""
        llm_data = {"bankAccounts": ["1234567890123456"]}
        conversation = "Account 1234567890123456 is compromised"
        result = validate_llm_intelligence(llm_data, conversation)
        assert "1234567890123456" in result.get("bankAccounts", [])


# ── Full Integration ────────────────────────────────────────────

class TestFullExtraction:
    def test_bank_fraud_scenario(self):
        """Test extraction against a realistic bank fraud conversation."""
        text = """
        Your account number is 1234567890123456.
        Call me at +91-9876543210.
        My UPI ID is scammer.fraud@fakebank.
        Email me at support@fakebank.com.
        Reference number REF-2023-4567.
        """
        intel = extract_all_intelligence(text, turn=5, timestamp=1670000000.0)

        phone_vals = [i.value for i in intel.phoneNumbers]
        bank_vals = [i.value for i in intel.bankAccounts]
        upi_vals = [i.value for i in intel.upiIds]
        email_vals = [i.value for i in intel.emailAddresses]
        case_vals = [i.value for i in intel.caseIds]

        assert any("9876543210" in v for v in phone_vals), f"Phone not found: {phone_vals}"
        assert "1234567890123456" in bank_vals, f"Bank account not found: {bank_vals}"
        assert "scammer.fraud@fakebank" in upi_vals, f"UPI not found: {upi_vals}"
        assert "support@fakebank.com" in email_vals, f"Email not found: {email_vals}"
        assert any("2023-4567" in v or "REF-2023-4567" in v for v in case_vals), f"Case ID not found: {case_vals}"

        # Verify provenance
        assert intel.phoneNumbers[0].provenance.turn == 5
        assert intel.phoneNumbers[0].provenance.source == "regex"

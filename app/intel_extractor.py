"""
Intelligence extraction module.
Uses regex patterns + validation to extract ALL types of intelligence data.
Covers: phone numbers, bank accounts, UPI IDs, phishing links, email addresses,
case IDs, policy numbers, and order numbers.

Features:
- Per-field provenance tracking (turn, timestamp, source)
- LLM output post-validation against conversation text
- Obfuscation handling (spaced digits, homoglyph domains)
- False-positive filtering (word blocklist, timestamp filtering)
"""

import re
from typing import List, Set, Optional
from app.models import ExtractedIntelligence, IntelligenceItem, IntelligenceProvenance


# ── Common words to NEVER extract as case IDs ──────────────────

CASE_ID_BLOCKLIST = {
    "entity", "identity", "verify", "verified", "security", "department",
    "account", "blocked", "immediately", "password", "transfer", "customer",
    "service", "process", "transaction", "completed", "processing", "updated",
    "information", "confirmation", "notification", "communication", "resolution",
    "following", "regarding", "mentioned", "provided", "required", "received",
    "urgent", "important", "priority", "critical", "action", "response",
    "officer", "manager", "official", "executive", "representative",
    "minutes", "seconds", "hours", "please", "kindly", "thank",
    "mobile", "number", "amount", "balance", "payment", "status",
    "message", "details", "contact", "address", "branch", "office",
    "bank", "fraud", "scam", "error", "system", "server",
    "hello", "help", "right", "wrong", "okay", "fine",
    "first", "second", "third", "final", "warning", "notice",
    "your", "their", "about", "from", "with", "this", "that",
    "have", "will", "been", "what", "when", "where", "which",
}

# ── Regex Patterns ──────────────────────────────────────────────

# Phone numbers: Indian format with optional +91, other country codes
PHONE_PATTERNS = [
    re.compile(r'\+91[-.\\s]?(\d{5})[-.\\s]?(\d{5})'),           # +91-98765-43210
    re.compile(r'\+91[-.\\s]?(\d{10})'),                          # +91-9876543210
    re.compile(r'\+91[-.\\s]?\d[-.\\s]?\d[-.\\s]?\d[-.\\s]?\d[-.\\s]?\d[-.\\s]?\d[-.\\s]?\d[-.\\s]?\d[-.\\s]?\d[-.\\s]?\d'),  # +91 with spaces between digits
    re.compile(r'\b(?:\+?91[-.\\s]?)?([6-9]\d{9})\b'),           # 9876543210 or 91 9876543210
    re.compile(r'\+\d{1,3}[-.\\s]?\d{4,5}[-.\\s]?\d{4,6}'),      # Any international format
]

# Bank accounts: 9-18 digit numbers (standalone)
BANK_ACCT_PATTERN = re.compile(r'\b(\d{9,18})\b')

# UPI IDs: word@word format
UPI_PATTERN = re.compile(r'\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]{2,})\b')

# Email addresses: standard email format
EMAIL_PATTERN = re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')

# Phishing links
URL_PATTERN = re.compile(
    r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}/[^\s<>"\']*)',
    re.IGNORECASE
)

# Case/Reference IDs — require at least one digit
CASE_ID_PATTERNS = [
    re.compile(r'\b(?:case|ref|reference|ticket|complaint|id|incident|fir|ncr)[\s#:_-]+([A-Za-z0-9][\w-]{3,20})\b', re.IGNORECASE),
    re.compile(r'\b([A-Z]{2,5}-\d{3,10})\b'),  # SBI-12345, CASE-789
    re.compile(r'\b([A-Z]{2,5}-\d{4}-\d{2,6})\b'),  # REF-2023-4567
    re.compile(r'\b(?:FIR|NCR|CR)[\s#:_-]*(\d{3,15})\b', re.IGNORECASE),
]

# Policy numbers
POLICY_PATTERNS = [
    re.compile(r'\b(?:policy|insurance|cover)[\s#:_-]+([A-Za-z0-9][\w-]{5,20})\b', re.IGNORECASE),
    re.compile(r'\b(\d{4}-[A-Z]{2,5}-\d{2,6})\b'),  # 2023-SEC-001
    re.compile(r'\b(POL[\w-]{5,15})\b', re.IGNORECASE),
    re.compile(r'\b(LIC[\w-]{5,15})\b', re.IGNORECASE),
]

# Order numbers
ORDER_PATTERNS = [
    re.compile(r'\b(?:order|tracking|shipment|delivery|consignment)[\s#:_-]+([A-Za-z0-9][\w-]{5,25})\b', re.IGNORECASE),
    re.compile(r'\b(ORD[\w-]{5,20})\b', re.IGNORECASE),
    re.compile(r'\b(AWB[\w-]{5,20})\b', re.IGNORECASE),
]

# Known email domains
EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com',
    'mail.com', 'aol.com', 'icloud.com', 'live.com', 'rediffmail.com',
    'yandex.com', 'zoho.com', 'msn.com', 'inbox.com',
}

# Known UPI handles
UPI_HANDLES = {
    'paytm', 'ybl', 'okhdfcbank', 'okicici', 'oksbi', 'apl', 'upi',
    'ikwik', 'axisbank', 'sbi', 'ibl', 'federal', 'kotak', 'indus',
    'hdfcbank', 'icici', 'axl', 'barodampay', 'mahb', 'cnrb',
    'pnb', 'unionbank', 'bob', 'cbi', 'idbi', 'fbl', 'rbl',
    'dbs', 'hsbc', 'citi', 'sc', 'freecharge', 'jio', 'waaxis',
    'wahdfcbank', 'waicici', 'wasbi', 'fakebank', 'fakeupi',
    'airtel', 'postbank', 'abfspay', 'ratn', 'kvb', 'idfcbank',
    'jupiteraxis', 'slice', 'niyoicici', 'fi', 'onecard',
}

# Homoglyph / leetspeak map for URL detection
HOMOGLYPHS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a',
}


# ── Text Normalization ──────────────────────────────────────────

def normalize_text(text: str) -> str:
    """
    Normalize text for better extraction:
    - Collapse spaces between digits (e.g., '9 8 7 6' -> '9876')
    - Normalize unicode lookalikes
    """
    # Collapse spaces/dots/dashes between individual digits
    # e.g., "9 8 7 6 5 4 3 2 1 0" -> "9876543210"
    normalized = re.sub(r'(\d)\s+(?=\d)', r'\1', text)
    return normalized


def detect_homoglyph_domain(url: str) -> bool:
    """Check if a URL domain uses homoglyphs / leetspeak (e.g., amaz0n, g00gle)."""
    try:
        # Extract domain from URL
        domain = url.lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
        domain = domain.split('?')[0]

        # Check for digit-letter substitutions in domain
        for char, replacement in HOMOGLYPHS.items():
            if char in domain:
                return True
    except Exception:
        pass
    return False


# ── Helper Functions ────────────────────────────────────────────

def _dedupe_items(items: List[IntelligenceItem]) -> List[IntelligenceItem]:
    """Deduplicate IntelligenceItem list by value, preserving first occurrence."""
    seen: Set[str] = set()
    result = []
    for item in items:
        key = item.value.lower().strip()
        if key and key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _make_item(
    value: str,
    turn: int = 0,
    timestamp: Optional[float] = None,
    source: str = "regex",
    confidence: float = 0.95,
) -> IntelligenceItem:
    """Create an IntelligenceItem with provenance."""
    return IntelligenceItem(
        value=value.strip(),
        confidence=confidence,
        provenance=IntelligenceProvenance(
            turn=turn,
            timestamp=timestamp,
            source=source,
        ),
    )


def _is_upi_id(address: str) -> bool:
    """Check if an @-address is a UPI ID rather than an email."""
    if '@' not in address:
        return False
    domain = address.split('@')[1].lower().strip('.')
    # If it has a valid TLD, it's an email, not a UPI ID
    if re.match(r'^.*\.[a-z]{2,4}$', domain):
        return False
    if '.' not in domain:
        return True
    base_handle = domain.split('.')[0]
    if base_handle in UPI_HANDLES or domain in UPI_HANDLES:
        return True
    return False


def _is_email(address: str) -> bool:
    """Check if an @-address is an email rather than a UPI ID."""
    if '@' not in address:
        return False
    domain = address.split('@')[1].lower()
    if '.' not in domain:
        return False
    if re.match(r'^.*\.[a-z]{2,4}$', domain):
        return True
    return False


def _has_digit(s: str) -> bool:
    """Check if string contains at least one digit."""
    return any(c.isdigit() for c in s)


def _is_valid_case_id(val: str) -> bool:
    """Validate that a case ID is not a common English word and has digits."""
    cleaned = val.strip().lower()
    if cleaned in CASE_ID_BLOCKLIST:
        return False
    if not _has_digit(val):
        return False
    if len(val) < 3:
        return False
    stripped = val.strip()
    if stripped.isdigit() and len(stripped) <= 5:
        return False
    return True


# ── Extraction Functions ────────────────────────────────────────

def extract_phone_numbers(text: str, turn: int = 0, timestamp: Optional[float] = None) -> List[IntelligenceItem]:
    """Extract all phone numbers from text, preserving original format."""
    phones: Set[str] = set()
    items = []

    # Also try normalized text (spaces between digits collapsed)
    norm_text = normalize_text(text)

    for search_text in [text, norm_text]:
        for pattern in PHONE_PATTERNS:
            for match in pattern.finditer(search_text):
                full = match.group(0).strip()
                digits = re.sub(r'\D', '', full)

                if len(digits) >= 10:
                    phones.add(full)
                    if digits.startswith('91') and len(digits) >= 12:
                        d = digits[-10:]
                        phones.add(f"+91-{d[:5]}{d[5:]}")
                    elif len(digits) == 10:
                        phones.add(f"+91-{digits[:5]}{digits[5:]}")

    seen: Set[str] = set()
    for phone in phones:
        key = re.sub(r'\D', '', phone)[-10:]
        if key not in seen:
            seen.add(key)
            items.append(_make_item(phone, turn=turn, timestamp=timestamp))

    return items


def extract_bank_accounts(text: str, turn: int = 0, timestamp: Optional[float] = None) -> List[IntelligenceItem]:
    """Extract bank account numbers (10-18 digits, excluding phone numbers and timestamps)."""
    phone_digits: Set[str] = set()
    for pattern in PHONE_PATTERNS:
        for match in pattern.finditer(text):
            digits = re.sub(r'\D', '', match.group(0))
            phone_digits.add(digits)
            if len(digits) >= 10:
                phone_digits.add(digits[-10:])
                if digits.startswith('91'):
                    phone_digits.add(digits[2:])

    items = []
    for match in BANK_ACCT_PATTERN.finditer(text):
        num = match.group(1)
        if num in phone_digits or num[-10:] in phone_digits:
            continue
        if len(num) < 10:
            continue
        if len(num) == 13 and num[:2] in ('14', '15', '16', '17', '18', '19', '20'):
            continue
        if len(num) >= 13:
            try:
                val = int(num)
                if 1500000000000 <= val <= 2000000000000:
                    continue
            except ValueError:
                pass
        items.append(_make_item(num, turn=turn, timestamp=timestamp))

    return _dedupe_items(items)


def extract_upi_ids(text: str, turn: int = 0, timestamp: Optional[float] = None) -> List[IntelligenceItem]:
    """Extract UPI IDs from text."""
    items = []
    for match in UPI_PATTERN.finditer(text):
        address = match.group(0)
        if _is_upi_id(address):
            items.append(_make_item(address, turn=turn, timestamp=timestamp))
        elif not _is_email(address):
            domain = address.split('@')[1].lower()
            if domain in UPI_HANDLES or '.' not in domain:
                items.append(_make_item(address, turn=turn, timestamp=timestamp))
    return _dedupe_items(items)


def extract_emails(text: str, turn: int = 0, timestamp: Optional[float] = None) -> List[IntelligenceItem]:
    """Extract email addresses from text (excluding UPI IDs)."""
    items = []
    for match in EMAIL_PATTERN.finditer(text):
        address = match.group(0)
        if _is_email(address) and not _is_upi_id(address):
            items.append(_make_item(address, turn=turn, timestamp=timestamp))
    return _dedupe_items(items)


def extract_urls(text: str, turn: int = 0, timestamp: Optional[float] = None) -> List[IntelligenceItem]:
    """Extract phishing/suspicious URLs from text."""
    items = []
    safe_domains = ['google.com/search', 'wikipedia.org', 'github.com', 'stackoverflow.com']

    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip('.,;:!?)\'\"')
        if any(safe in url.lower() for safe in safe_domains):
            continue
        # Exclude apparent emails from being matched as purely a URL (unless it has http)
        if '@' in url and not url.lower().startswith('http'):
            continue
        # Boost confidence for homoglyph domains
        conf = 0.98 if detect_homoglyph_domain(url) else 0.95
        items.append(_make_item(url, turn=turn, timestamp=timestamp, confidence=conf))
    return _dedupe_items(items)


def extract_case_ids(text: str, turn: int = 0, timestamp: Optional[float] = None) -> List[IntelligenceItem]:
    """Extract case/reference IDs from text with strict validation."""
    items = []
    for pattern in CASE_ID_PATTERNS:
        for match in pattern.finditer(text):
            val = match.group(1) if pattern.groups else match.group(0)
            val = val.strip()
            if _is_valid_case_id(val):
                items.append(_make_item(val, turn=turn, timestamp=timestamp))
    return _dedupe_items(items)


def extract_policy_numbers(text: str, turn: int = 0, timestamp: Optional[float] = None) -> List[IntelligenceItem]:
    """Extract policy/insurance numbers from text."""
    items = []
    for pattern in POLICY_PATTERNS:
        for match in pattern.finditer(text):
            val = match.group(1) if pattern.groups else match.group(0)
            val = val.strip()
            if _has_digit(val):
                items.append(_make_item(val, turn=turn, timestamp=timestamp))
    return _dedupe_items(items)


def extract_order_numbers(text: str, turn: int = 0, timestamp: Optional[float] = None) -> List[IntelligenceItem]:
    """Extract order/tracking numbers from text."""
    items = []
    for pattern in ORDER_PATTERNS:
        for match in pattern.finditer(text):
            val = match.group(1) if pattern.groups else match.group(0)
            val = val.strip()
            if _has_digit(val):
                items.append(_make_item(val, turn=turn, timestamp=timestamp))
    return _dedupe_items(items)


# ── Main Extraction Entry Point ─────────────────────────────────

def extract_all_intelligence(
    text: str,
    turn: int = 0,
    timestamp: Optional[float] = None,
) -> ExtractedIntelligence:
    """
    Extract ALL types of intelligence from a single text block.
    This is the main entry point for regex-based extraction.
    """
    if not text:
        return ExtractedIntelligence()

    intel = ExtractedIntelligence(
        phoneNumbers=extract_phone_numbers(text, turn, timestamp),
        bankAccounts=extract_bank_accounts(text, turn, timestamp),
        upiIds=extract_upi_ids(text, turn, timestamp),
        phishingLinks=extract_urls(text, turn, timestamp),
        emailAddresses=extract_emails(text, turn, timestamp),
        caseIds=extract_case_ids(text, turn, timestamp),
        policyNumbers=extract_policy_numbers(text, turn, timestamp),
        orderNumbers=extract_order_numbers(text, turn, timestamp),
    )

    # ── Handle ambiguous @ strings based on surrounding context ──
    text_lower = text.lower()
    for match in re.finditer(r'\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]{2,})\b', text):
        val = match.group(0)
        # If "email" is mentioned, strongly assume it's an email
        if "email" in text_lower:
            if not any(e.value == val for e in intel.emailAddresses):
                intel.emailAddresses.append(_make_item(val, turn, timestamp))
        # If "upi" is mentioned, strongly assume it's a UPI ID
        if "upi" in text_lower:
            if not any(u.value == val for u in intel.upiIds):
                intel.upiIds.append(_make_item(val, turn, timestamp))

    return intel


# ── Merge Functions ─────────────────────────────────────────────

def merge_intelligence(a: ExtractedIntelligence, b: ExtractedIntelligence) -> ExtractedIntelligence:
    """Merge two intelligence objects, deduplicating by value."""
    return ExtractedIntelligence(
        phoneNumbers=_dedupe_items([*a.phoneNumbers, *b.phoneNumbers]),
        bankAccounts=_dedupe_items([*a.bankAccounts, *b.bankAccounts]),
        upiIds=_dedupe_items([*a.upiIds, *b.upiIds]),
        phishingLinks=_dedupe_items([*a.phishingLinks, *b.phishingLinks]),
        emailAddresses=_dedupe_items([*a.emailAddresses, *b.emailAddresses]),
        caseIds=_dedupe_items([*a.caseIds, *b.caseIds]),
        policyNumbers=_dedupe_items([*a.policyNumbers, *b.policyNumbers]),
        orderNumbers=_dedupe_items([*a.orderNumbers, *b.orderNumbers]),
    )


# ── LLM Validation ─────────────────────────────────────────────

def validate_llm_intelligence(llm_data: dict, full_conversation_text: str) -> dict:
    """
    Validate LLM-extracted intelligence against the actual conversation text.
    Rejects any hallucinated values not found in the text.
    Checks across ALL conversation history, not just the latest message.
    """
    if not llm_data or not full_conversation_text:
        return {}

    validated = {}
    text_lower = full_conversation_text.lower()
    # Also normalize for digit matching
    text_normalized = normalize_text(full_conversation_text).lower()

    for field_name, values in llm_data.items():
        if not isinstance(values, list):
            continue
        valid_values = []
        for val in values:
            if not val:
                continue
            val_str = str(val).strip()
            val_lower = val_str.lower()

            # Check if value or its digits appear in conversation
            digits_only = re.sub(r'\D', '', val_str)
            if (
                val_lower in text_lower
                or val_lower in text_normalized
                or (digits_only and len(digits_only) >= 5 and digits_only in re.sub(r'\D', '', full_conversation_text))
            ):
                valid_values.append(val_str)
            else:
                print(f"🚫 LLM hallucination rejected: {field_name}={val_str}", flush=True)

        if valid_values:
            validated[field_name] = valid_values

    return validated


def merge_llm_intelligence(
    base: ExtractedIntelligence,
    llm_data: dict,
    turn: int = 0,
    timestamp: Optional[float] = None,
) -> ExtractedIntelligence:
    """Merge validated LLM-extracted intelligence into the base intelligence object."""
    if not llm_data:
        return base

    def safe_items(key: str) -> List[IntelligenceItem]:
        vals = llm_data.get(key, [])
        if isinstance(vals, list):
            items = []
            for v in vals:
                if v:
                    items.append(_make_item(
                        str(v), turn=turn, timestamp=timestamp,
                        source="llm", confidence=0.80,
                    ))
            return items
        return []

    # For caseIds, apply validation
    case_items = [item for item in safe_items("caseIds") if _is_valid_case_id(item.value)]

    llm_intel = ExtractedIntelligence(
        phoneNumbers=safe_items("phoneNumbers"),
        bankAccounts=safe_items("bankAccounts"),
        upiIds=safe_items("upiIds"),
        phishingLinks=safe_items("phishingLinks"),
        emailAddresses=safe_items("emailAddresses"),
        caseIds=case_items,
        policyNumbers=safe_items("policyNumbers"),
        orderNumbers=safe_items("orderNumbers"),
    )

    # Merge — items with same value get source upgraded to "both"
    merged = _merge_with_source_upgrade(base, llm_intel)
    return merged


def _merge_with_source_upgrade(
    base: ExtractedIntelligence,
    llm: ExtractedIntelligence,
) -> ExtractedIntelligence:
    """Merge and upgrade source to 'both' when both regex and LLM found the same value."""
    result = ExtractedIntelligence()

    for field_name in [
        "phoneNumbers", "bankAccounts", "upiIds", "phishingLinks",
        "emailAddresses", "caseIds", "policyNumbers", "orderNumbers",
    ]:
        base_items: List[IntelligenceItem] = getattr(base, field_name)
        llm_items: List[IntelligenceItem] = getattr(llm, field_name)

        # Build lookup by normalized value
        merged_map = {}
        for item in base_items:
            key = item.value.lower().strip()
            merged_map[key] = item

        for item in llm_items:
            key = item.value.lower().strip()
            if key in merged_map:
                # Found by both — upgrade source and boost confidence
                existing = merged_map[key]
                merged_map[key] = IntelligenceItem(
                    value=existing.value,
                    confidence=min(0.99, max(existing.confidence, 0.95)),
                    provenance=IntelligenceProvenance(
                        turn=existing.provenance.turn,
                        timestamp=existing.provenance.timestamp,
                        source="both",
                    ),
                )
            else:
                merged_map[key] = item

        setattr(result, field_name, list(merged_map.values()))

    return result

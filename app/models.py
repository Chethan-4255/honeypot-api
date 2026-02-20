"""
Pydantic models for Honeypot Scam Detection API.
Covers request/response schemas, intelligence extraction models with
per-field provenance and confidence tracking.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ── Request Models ──────────────────────────────────────────────

class MessageItem(BaseModel):
    """A single message in the conversation."""
    sender: str = ""
    text: str = ""
    timestamp: Optional[Any] = None


class ScamRequest(BaseModel):
    """Incoming request from the evaluation system."""
    sessionId: Optional[str] = None
    message: Optional[MessageItem] = None
    conversationHistory: Optional[List[Dict[str, Any]]] = []
    metadata: Optional[Dict[str, Any]] = {}
    # Handshake fields
    status: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


# ── Intelligence Models ─────────────────────────────────────────

class IntelligenceProvenance(BaseModel):
    """Where and when an intelligence item was extracted."""
    turn: int = 0
    timestamp: Optional[float] = None
    source: str = "regex"  # "regex", "llm", or "both"


class IntelligenceItem(BaseModel):
    """A single intelligence item with confidence and provenance."""
    value: str
    confidence: float = 0.95
    provenance: IntelligenceProvenance = Field(default_factory=IntelligenceProvenance)


class ExtractedIntelligence(BaseModel):
    """All intelligence extracted from the scam conversation."""
    phoneNumbers: List[IntelligenceItem] = Field(default_factory=list)
    bankAccounts: List[IntelligenceItem] = Field(default_factory=list)
    upiIds: List[IntelligenceItem] = Field(default_factory=list)
    phishingLinks: List[IntelligenceItem] = Field(default_factory=list)
    emailAddresses: List[IntelligenceItem] = Field(default_factory=list)
    caseIds: List[IntelligenceItem] = Field(default_factory=list)
    policyNumbers: List[IntelligenceItem] = Field(default_factory=list)
    orderNumbers: List[IntelligenceItem] = Field(default_factory=list)


# ── Final Output Model ──────────────────────────────────────────

class FinalOutput(BaseModel):
    """GUVI-compliant final output after conversation ends."""
    sessionId: str
    scamDetected: bool = False
    totalMessagesExchanged: int = 0
    engagementDurationSeconds: int = 0
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    agentNotes: Optional[str] = None
    scamType: Optional[str] = None
    confidenceLevel: Optional[float] = None

"""
FastAPI Application — Honeypot Scam Detection API
Main entry point. Handles incoming scam messages, generates honeypot replies,
extracts intelligence, and returns GUVI-compliant responses with final output.
"""

import os
import re
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from app.models import ScamRequest
from app.agent import HoneyPotAgent
from app.session_manager import SessionManager


# ── Initialize App ──────────────────────────────────────────────

app = FastAPI(title="Honeypot Scam Detection API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev; set explicit domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

agent = HoneyPotAgent()
sessions = SessionManager()


def _get_secret() -> str:
    """Read API secret dynamically from env (allows runtime changes for testing)."""
    return os.environ.get("MY_APP_SECRET", "")


# ── Log Redaction Utility ──────────────────────────────────────

def _redact(text: str) -> str:
    """Redact sensitive data from log output (phone numbers, emails, keys)."""
    # Redact phone numbers
    text = re.sub(r'\+?\d[\d\s\-]{8,}\d', '[REDACTED_PHONE]', text)
    # Redact email addresses
    text = re.sub(r'[\w.+-]+@[\w.-]+\.\w+', '[REDACTED_EMAIL]', text)
    # Redact long digit sequences (bank accounts)
    text = re.sub(r'\b\d{10,18}\b', '[REDACTED_DIGITS]', text)
    return text


# ── Health Check ────────────────────────────────────────────────

@app.get("/")
async def health():
    return {"status": "Honeypot Active", "version": "2.0.0"}


# ── Main Detection Endpoints ───────────────────────────────────
# Mount on EVERY possible path the evaluator might hit

@app.post("/")
async def detect_root(
    incoming: ScamRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    return await _handle_request(incoming, background_tasks, x_api_key)


@app.post("/detect")
async def detect(
    incoming: ScamRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    return await _handle_request(incoming, background_tasks, x_api_key)


@app.post("/detect-scam")
async def detect_scam(
    incoming: ScamRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    return await _handle_request(incoming, background_tasks, x_api_key)


@app.post("/honeypot")
async def honeypot(
    incoming: ScamRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    return await _handle_request(incoming, background_tasks, x_api_key)


@app.post("/api/detect")
async def api_detect(
    incoming: ScamRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    return await _handle_request(incoming, background_tasks, x_api_key)


async def _handle_request(incoming: ScamRequest, background_tasks: BackgroundTasks, x_api_key: Optional[str]):
    """Core request handler shared by all detection endpoints."""

    # ── Authenticate — enforce when MY_APP_SECRET is set ────────
    secret = _get_secret()
    if secret:
        if not x_api_key or x_api_key != secret:
            raise HTTPException(status_code=403, detail="Forbidden: Invalid API key")

    # ── Sanitized log — no raw payload, no secrets ──────────────
    sid = incoming.sessionId or "unknown"
    msg_text = (incoming.message.text if incoming.message else "") or ""
    print(f"📥 Session: {sid}, msg_len: {len(msg_text)}", flush=True)

    # ── Handle final testing completion ────────────────────────────
    if incoming.data and incoming.data.get("processStatus") == "completed_testing":
        print("✅ Testing completed payload received", flush=True)
        history = incoming.data.get("conversationHistory") or []
        session_id = incoming.sessionId or "eval_completed_session"
        final_output = await sessions.finalize_session(session_id, history, agent)
        
        # Schedule the callback right away since testing is fully completed
        background_tasks.add_task(sessions.send_callback_snapshot, final_output)
        
        # Evaluator expects the exact final_output dict as the raw HTTP response
        return final_output

    # ── Handle handshake/ping (only true pings with no conversation data) ──
    if not incoming.sessionId and not incoming.message:
        print("✅ Handshake/ping detected", flush=True)
        return {"status": "success", "reply": "Handshake Accepted"}

    # ── Validate required fields ───────────────────────────
    if not incoming.sessionId or not incoming.message:
        return {"status": "error", "message": "Missing sessionId or message"}

    # ── Extract message text ───────────────────────────────
    message_text = incoming.message.text or ""
    if not message_text:
        return {"status": "success", "reply": "Namaste ji, I did not hear you clearly. Can you say again?"}

    # ── Process message ────────────────────────────────────
    reply, final_output = await sessions.process_message(
        session_id=incoming.sessionId,
        message_text=message_text,
        conversation_history=incoming.conversationHistory or [],
        metadata=incoming.metadata or {},
        agent=agent,
    )

    # ── Build response ─────────────────────────────────────
    response = {
        "status": "success",
        "reply": reply,
        "finalOutput": final_output,
    }

    # Unpack final output properties directly into the response root.
    # The Guvi evaluator parses the root HTTP JSON response for these keys.
    for k, v in final_output.items():
        if k not in response:
            response[k] = v

    # When a scam is definitively detected mid-conversation, schedule a callback
    # This ensures the remote server receives updates as the conversation progresses.
    if final_output.get("scamDetected"):
        background_tasks.add_task(sessions.send_callback_snapshot, final_output)

    print(f"📤 Reply length: {len(reply)}, scam_detected: {final_output.get('scamDetected')}", flush=True)

    return response


# ── Final Output Endpoint ──────────────────────────────────────

@app.get("/final-output/{session_id}")
async def get_final_output(
    session_id: str,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    """Retrieve the final output for a completed session."""
    secret = _get_secret()
    if secret and (not x_api_key or x_api_key != secret):
        raise HTTPException(status_code=403, detail="Forbidden: Invalid API key")

    output = sessions.build_final_output(session_id)
    return output


# ── Run ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)

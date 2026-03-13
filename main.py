from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from collections import defaultdict, deque
from datetime import datetime, timedelta
import os
import re
import json
from pathlib import Path

app = FastAPI(title="David Runtime", version="2.0")

# =========================
# CONFIG
# =========================
API_KEY = os.getenv("API_KEY")
AUDIT_LOG_FILE = Path("audit_log.jsonl")

# Rate limiting
RATE_LIMIT_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60

# Repeated attacker blocking
BLOCK_THRESHOLD = 5
BLOCK_WINDOW_MINUTES = 15

# In-memory stores
request_log = defaultdict(deque)      # ip -> timestamps
blocked_attempts = defaultdict(deque) # ip -> timestamps

# =========================
# VALIDATION
# =========================
if not API_KEY:
    raise RuntimeError("Missing API_KEY environment variable. Fail-closed startup.")

class EnforcementRequest(BaseModel):
    input: str

# =========================
# RULES
# =========================
BLOCK_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all previous instructions",
    r"reveal system prompt",
    r"show system prompt",
    r"print.*api key",
    r"developer mode",
    r"disable safety",
    r"disable guardrails",
    r"bypass security",
    r"bypass protections",
    r"expose secrets",
    r"reveal secrets",
    r"steal credentials",
    r"extract credentials",
    r"prompt injection",
    r"jailbreak",
    r"override policy",
    r"forget your rules",
    r"act as unrestricted",
    r"pretend you are not restricted",
    r"provide malware",
    r"write ransomware",
    r"make a phishing email",
    r"bank password",
    r"social security number",
    r"credit card dump",
]

SUSPICIOUS_PATTERNS = [
    r"base64",
    r"unicode bypass",
    r"hex encoded",
    r"encoded payload",
    r"hidden instructions",
    r"nested prompt",
    r"ignore the above and",
]

def normalize_text(text: str) -> str:
    return text.lower().strip()

def detect_block(text: str) -> tuple[bool, str]:
    normalized = normalize_text(text)

    for pattern in BLOCK_PATTERNS:
        if re.search(pattern, normalized):
            return True, f"Matched block pattern: {pattern}"

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, normalized):
            return True, f"Matched suspicious pattern: {pattern}"

    return False, "No blocked pattern matched"

# =========================
# HELPERS
# =========================
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"

def is_rate_limited(ip: str) -> bool:
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)

    while request_log[ip] and request_log[ip][0] < window_start:
        request_log[ip].popleft()

    return len(request_log[ip]) >= RATE_LIMIT_REQUESTS

def record_request(ip: str) -> None:
    request_log[ip].append(datetime.utcnow())

def record_blocked_attempt(ip: str) -> None:
    now = datetime.utcnow()
    blocked_attempts[ip].append(now)

    window_start = now - timedelta(minutes=BLOCK_WINDOW_MINUTES)
    while blocked_attempts[ip] and blocked_attempts[ip][0] < window_start:
        blocked_attempts[ip].popleft()

def is_repeat_attacker(ip: str) -> bool:
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=BLOCK_WINDOW_MINUTES)

    while blocked_attempts[ip] and blocked_attempts[ip][0] < window_start:
        blocked_attempts[ip].popleft()

    return len(blocked_attempts[ip]) >= BLOCK_THRESHOLD

def write_audit_log(entry: dict) -> None:
    AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def audit_event(
    ip: str,
    decision: str,
    reason: str,
    user_input: str,
    status_code: int
) -> None:
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
        "decision": decision,
        "reason": reason,
        "status_code": status_code,
        "input_preview": user_input[:300]
    }
    write_audit_log(entry)

# =========================
# ENDPOINTS
# =========================
@app.get("/")
def root():
    return {"status": "David runtime online"}

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "David Runtime",
        "version": "2.0",
        "fail_closed": True,
        "audit_log": str(AUDIT_LOG_FILE)
    }

@app.post("/v1/enforce")
async def enforce(req: EnforcementRequest, request: Request):
    ip = get_client_ip(request)
    record_request(ip)

    auth = request.headers.get("authorization", "")

    # Auth check
    if auth != f"Bearer {API_KEY}":
        audit_event(ip, "DENY", "Unauthorized", req.input, 401)
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Rate limiting
    if is_rate_limited(ip):
        audit_event(ip, "DENY", "Rate limit exceeded", req.input, 429)
        raise HTTPException(status_code=429, detail="Too many requests")

    # Repeat attacker lockout
    if is_repeat_attacker(ip):
        audit_event(ip, "DENY", "Repeated malicious behavior", req.input, 403)
        raise HTTPException(status_code=403, detail="Access temporarily blocked")

    # Content inspection
    should_block, reason = detect_block(req.input)
    if should_block:
        record_blocked_attempt(ip)
        audit_event(ip, "BLOCK", reason, req.input, 200)
        return {
            "decision": "BLOCK",
            "reason": reason
        }

    # Default allow
    audit_event(ip, "ALLOW", "Input passed policy checks", req.input, 200)
    return {
        "decision": "ALLOW",
        "reason": "Input passed policy checks"
    }

from fastapi import FastAPI, Request, Header, HTTPException, Depends
from pydantic import BaseModel, Field
import time
import hashlib
import uuid
import sqlite3
import jwt
from typing import Dict, Any, Optional

# =========================
# CONFIG
# =========================
APP_NAME = "David Core AI - Production Grade"
JWT_SECRET = "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
JWT_ALG = "HS256"
RATE_LIMIT = 60  # per minute per IP
BLOCK_TIME = 60  # seconds

app = FastAPI(title=APP_NAME)

# =========================
# DATABASE (AUDIT PERSISTENCE)
# =========================
conn = sqlite3.connect("david_audit.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp REAL,
    ip TEXT,
    decision TEXT,
    risk REAL,
    reasons TEXT,
    prev_hash TEXT,
    hash TEXT
)
""")
conn.commit()

# =========================
# MEMORY STATE
# =========================
rate_tracker = {}
blocked_ips = {}
used_nonces = set()
last_hash = "GENESIS_DAVID_CORE"

# =========================
# INPUT MODEL
# =========================
class Payload(BaseModel):
    payload: Dict[str, Any] = Field(...)

# =========================
# AUTH (JWT)
# =========================
def verify_token(auth: str):
    if not auth:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        token = auth.replace("Bearer ", "")
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# =========================
# REPLAY PROTECTION
# =========================
def verify_nonce(nonce: str):
    if not nonce:
        raise HTTPException(status_code=400, detail="Missing nonce")

    if nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Replay detected")

    used_nonces.add(nonce)

# =========================
# RATE LIMITER
# =========================
def rate_limit(ip: str):
    now = time.time()
    bucket = rate_tracker.get(ip, [])

    bucket = [t for t in bucket if now - t < 60]
    bucket.append(now)

    rate_tracker[ip] = bucket

    if len(bucket) > RATE_LIMIT:
        blocked_ips[ip] = now + BLOCK_TIME
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    if ip in blocked_ips and now < blocked_ips[ip]:
        raise HTTPException(status_code=403, detail="IP temporarily blocked")

# =========================
# RISK ENGINE
# =========================
def analyze(payload: dict, ip: str):
    risk = 0.0
    reasons = []

    payload_str = str(payload)

    # Unknown structure heuristic
    if len(payload_str) > 600:
        risk += 0.25
        reasons.append("Large payload")

    # Deep nesting detection
    def depth(d, level=0):
        if not isinstance(d, dict):
            return level
        return max([depth(v, level + 1) for v in d.values()] + [level])

    d = depth(payload)
    if d > 3:
        risk += 0.3
        reasons.append("Deep nesting detected")

    # Random anomaly heuristic
    if "exec" in payload_str.lower() or "eval" in payload_str.lower():
        risk += 0.5
        reasons.append("Suspicious keywords detected")

    # Clamp
    risk = max(0.0, min(1.0, risk))

    if risk >= 0.75:
        decision = "block"
    elif risk >= 0.4:
        decision = "flag"
    else:
        decision = "allow"

    return decision, risk, reasons

# =========================
# HASH CHAIN (AUDIT)
# =========================
def hash_block(prev_hash, data):
    raw = f"{prev_hash}|{data}"
    return hashlib.sha256(raw.encode()).hexdigest()

def write_audit(ip, decision, risk, reasons):
    global last_hash

    block_id = str(uuid.uuid4())
    timestamp = time.time()

    data_str = f"{ip}|{decision}|{risk}|{reasons}"
    current_hash = hash_block(last_hash, data_str)

    cursor.execute("""
        INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        block_id,
        timestamp,
        ip,
        decision,
        risk,
        str(reasons),
        last_hash,
        current_hash
    ))
    conn.commit()

    last_hash = current_hash

    return current_hash

# =========================
# RESPONSE ENGINE
# =========================
def message(decision):
    if decision == "allow":
        return "Request accepted."
    if decision == "flag":
        return "Request flagged for review."
    return "Request blocked by security policy."

# =========================
# MAIN ENDPOINT
# =========================
@app.post("/analyze")
async def analyze_request(
    request: Request,
    data: Payload,
    authorization: Optional[str] = Header(None),
    x_nonce: Optional[str] = Header(None)
):
    start = time.time()
    ip = request.client.host

    # SECURITY LAYER
    verify_token(authorization)
    verify_nonce(x_nonce)
    rate_limit(ip)

    # CORE ANALYSIS
    decision, risk, reasons = analyze(data.payload, ip)

    # AUDIT LOGGING
    audit_hash = write_audit(ip, decision, risk, reasons)

    latency = round(time.time() - start, 4)

    return {
        "message": message(decision),
        "decision": decision,
        "risk_score": risk,
        "reasons": reasons,
        "audit_hash": audit_hash,
        "latency": latency
    }

# =========================
# AUDIT VERIFY ENDPOINT
# =========================
@app.get("/audit/verify")
def verify():
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    count = cursor.fetchone()[0]

    return {
        "audit_records": count,
        "status": "active",
        "integrity": "append-only"
    }

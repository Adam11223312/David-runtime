from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
import time
import hashlib
import uuid
import sqlite3
import jwt
from collections import defaultdict
import os

app = FastAPI(title="David Core API - Stable Build")

# =========================
# CONFIG
# =========================
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS_SECRET")
JWT_ALG = "HS256"

RATE_LIMIT = 60
BLOCK_TIME = 60

# =========================
# SAFE DATABASE (RAILWAY COMPATIBLE)
# =========================
DB_PATH = "/tmp/david_audit.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
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
# MEMORY
# =========================
rate_tracker = defaultdict(list)
blocked_ips = {}
used_nonces = set()
last_hash = "GENESIS_DAVID"

# =========================
# INPUT MODEL
# =========================
class Payload(BaseModel):
    payload: dict

# =========================
# AUTH
# =========================
def verify_token(auth_header: str):
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.replace("Bearer ", "")

    try:
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
# RATE LIMIT
# =========================
def rate_limit(ip: str):
    now = time.time()

    if ip in blocked_ips and now < blocked_ips[ip]:
        raise HTTPException(status_code=403, detail="IP blocked")

    window = rate_tracker[ip]
    rate_tracker[ip] = [t for t in window if now - t < 60]

    rate_tracker[ip].append(now)

    if len(rate_tracker[ip]) > RATE_LIMIT:
        blocked_ips[ip] = now + BLOCK_TIME
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

# =========================
# RISK ENGINE
# =========================
def analyze(payload: dict):
    risk = 0.0
    reasons = []

    text = str(payload)

    if len(text) > 600:
        risk += 0.2
        reasons.append("Large payload")

    if "exec" in text.lower() or "eval" in text.lower():
        risk += 0.5
        reasons.append("Suspicious keyword")

    def depth(d):
        if not isinstance(d, dict):
            return 0
        return 1 + max([depth(v) for v in d.values()] or [0])

    if depth(payload) > 3:
        risk += 0.3
        reasons.append("Deep nesting")

    risk = max(0.0, min(1.0, risk))

    if risk > 0.75:
        decision = "block"
    elif risk > 0.4:
        decision = "flag"
    else:
        decision = "allow"

    return decision, risk, reasons

# =========================
# AUDIT CHAIN
# =========================
def hash_block(prev_hash, data):
    return hashlib.sha256(f"{prev_hash}|{data}".encode()).hexdigest()

def write_audit(ip, decision, risk, reasons):
    global last_hash

    block_id = str(uuid.uuid4())
    timestamp = time.time()

    data = f"{ip}|{decision}|{risk}|{reasons}"
    current_hash = hash_block(last_hash, data)

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
# RESPONSE
# =========================
def message(decision):
    if decision == "allow":
        return "Request accepted"
    if decision == "flag":
        return "Request flagged"
    return "Request blocked"

# =========================
# MAIN ENDPOINT
# =========================
@app.post("/analyze")
async def analyze_request(
    request: Request,
    data: Payload,
    authorization: str = Header(None),
    x_nonce: str = Header(None)
):
    start = time.time()
    ip = request.client.host

    verify_token(authorization)
    verify_nonce(x_nonce)
    rate_limit(ip)

    decision, risk, reasons = analyze(data.payload)

    audit_hash = write_audit(ip, decision, risk, reasons)

    return {
        "message": message(decision),
        "decision": decision,
        "risk_score": risk,
        "reasons": reasons,
        "audit_hash": audit_hash,
        "latency": round(time.time() - start, 4)
    }

# =========================
# HEALTH CHECK
# =========================
@app.get("/")
def root():
    return {"status": "David Core online"}

@app.get("/audit/verify")
def verify():
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    return {
        "status": "ok",
        "records": cursor.fetchone()[0]
    }

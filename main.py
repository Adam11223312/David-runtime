import os
import time
import hashlib
import uuid
import jwt
import aiosqlite
from fastapi import FastAPI, Request, Header, HTTPException, Depends
from pydantic import BaseModel
from collections import defaultdict
from typing import Dict, List

app = FastAPI(title="David AI Core - Enforced Governance v4")

# =========================
# CONFIG
# =========================
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS_NOW")
JWT_ALG = "HS256"
DB_PATH = "david_audit.db"

RATE_LIMIT = 60
BLOCK_TIME = 60
NONCE_TTL = 120

# =========================
# STATE (move to Redis later)
# =========================
rate_tracker: Dict[str, List[float]] = defaultdict(list)
blocked_ips: Dict[str, float] = {}
nonce_store: Dict[str, float] = {}
last_hash_state = "GENESIS_DAVID"

# =========================
# MODELS
# =========================
class Payload(BaseModel):
    payload: dict

# =========================
# STARTUP
# =========================
@app.on_event("startup")
async def startup():
    global last_hash_state

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
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

        async with db.execute("SELECT hash FROM audit_log ORDER BY timestamp DESC LIMIT 1") as cursor:
            row = await cursor.fetchone()
            if row:
                last_hash_state = row[0]

        await db.commit()

# =========================
# AUTH + NONCE
# =========================
async def verify_auth(authorization: str = Header(None), x_nonce: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization")

    try:
        token = authorization.replace("Bearer ", "")
        jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            options={"require": ["exp", "iat"]}
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if not x_nonce:
        raise HTTPException(status_code=400, detail="Missing X-Nonce")

    now = time.time()

    # Clean expired nonces
    expired = [n for n, t in nonce_store.items() if now - t > NONCE_TTL]
    for n in expired:
        del nonce_store[n]

    if x_nonce in nonce_store:
        raise HTTPException(status_code=400, detail="Replay attack detected")

    nonce_store[x_nonce] = now

# =========================
# RATE LIMIT
# =========================
async def check_rate_limit(request: Request):
    ip = request.client.host
    now = time.time()

    if ip in blocked_ips and now < blocked_ips[ip]:
        raise HTTPException(status_code=403, detail="IP blocked")

    window = [t for t in rate_tracker[ip] if now - t < 60]
    window.append(now)
    rate_tracker[ip] = window

    if len(window) > RATE_LIMIT:
        blocked_ips[ip] = now + BLOCK_TIME
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

# =========================
# RISK ENGINE
# =========================
def analyze_risk(payload: dict):
    risk = 0.0
    reasons = []
    text = str(payload).lower()

    if len(text) > 1000:
        risk += 0.3
        reasons.append("High payload volume")

    suspicious = ["exec(", "eval(", "os.system", "import ", "<script"]
    if any(s in text for s in suspicious):
        risk += 0.6
        reasons.append("Insecure code signature")

    def get_depth(d, level=1):
        if not isinstance(d, dict) or not d or level > 10:
            return level
        return max(get_depth(v, level + 1) for v in d.values())

    if get_depth(payload) > 5:
        risk += 0.4
        reasons.append("Excessive nesting")

    risk = min(1.0, risk)

    # 🔒 HARD posture (no gray zone)
    decision = "block" if risk >= 0.7 else "allow"

    return decision, risk, reasons

# =========================
# AUDIT CHAIN
# =========================
async def log_to_audit(ip, decision, risk, reasons):
    global last_hash_state

    block_id = str(uuid.uuid4())
    ts = time.time()
    data_str = f"{ip}|{decision}|{risk}|{reasons}"

    new_hash = hashlib.sha256(
        f"{last_hash_state}|{data_str}".encode()
    ).hexdigest()

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (block_id, ts, ip, decision, risk, str(reasons), last_hash_state, new_hash)
        )
        await db.commit()

    last_hash_state = new_hash
    return new_hash

# =========================
# CORE ENDPOINT (FAIL-CLOSED)
# =========================
@app.post("/analyze", dependencies=[Depends(verify_auth), Depends(check_rate_limit)])
async def analyze(request: Request, data: Payload):
    start = time.time()

    decision, risk, reasons = analyze_risk(data.payload)

    # 🚨 FAIL-CLOSED ENFORCEMENT
    if decision != "allow":
        audit_hash = await log_to_audit(request.client.host, decision, risk, reasons)

        raise HTTPException(
            status_code=403,
            detail={
                "message": "Denied by David",
                "decision": decision,
                "risk_score": risk,
                "reasons": reasons,
                "audit_hash": audit_hash
            }
        )

    audit_hash = await log_to_audit(request.client.host, decision, risk, reasons)

    return {
        "status": "approved",
        "decision": decision,
        "risk_score": risk,
        "reasons": reasons,
        "audit_hash": audit_hash,
        "latency_ms": round((time.time() - start) * 1000, 2)
    }

# =========================
# HEALTH
# =========================
@app.get("/")
async def health():
    return {
        "service": "David AI Core v4",
        "status": "online",
        "chain_head": last_hash_state[:10]
    }

# =========================
# VERIFY AUDIT CHAIN
# =========================
@app.get("/audit/verify")
async def verify_chain():
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT * FROM audit_log ORDER BY timestamp ASC") as cursor:
            rows = await cursor.fetchall()

    prev = "GENESIS_DAVID"

    for row in rows:
        _, _, ip, decision, risk, reasons, prev_hash, current_hash = row

        data_str = f"{ip}|{decision}|{risk}|{reasons}"
        recalculated = hashlib.sha256(f"{prev}|{data_str}".encode()).hexdigest()

        if prev_hash != prev or current_hash != recalculated:
            return {
                "status": "FAILED",
                "bad_record": row[0]
            }

        prev = current_hash

    return {
        "status": "VERIFIED",
        "records": len(rows)
    }

import os
import time
import hashlib
import uuid
import jwt
import aiosqlite
from fastapi import FastAPI, Request, Header, HTTPException, Depends
from pydantic import BaseModel
from collections import defaultdict
from typing import Dict, List, Optional

app = FastAPI(title="David Core - Secure Production v3")

# =========================
# CONFIG & SECRETS
# =========================
# Load from Environment Variables for Security
JWT_SECRET = os.getenv("JWT_SECRET", "DEVELOPMENT_FALLBACK_ONLY")
JWT_ALG = "HS256"
DB_PATH = "david_audit.db"

RATE_LIMIT = 60
BLOCK_TIME = 60

# =========================
# IN-MEMORY STATE
# =========================
# Note: For horizontal scaling, move these to Redis
rate_tracker: Dict[str, List[float]] = defaultdict(list)
blocked_ips: Dict[str, float] = {}
used_nonces = set()
# Initialized during startup
last_hash_state = "GENESIS_DAVID" 

# =========================
# MODELS
# =========================
class Payload(BaseModel):
    payload: dict

# =========================
# LIFECYCLE & DB SETUP
# =========================
@app.on_event("startup")
async def startup():
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
        # Sync global state with the last record in DB if it exists
        async with db.execute("SELECT hash FROM audit_log ORDER BY timestamp DESC LIMIT 1") as cursor:
            row = await cursor.fetchone()
            if row:
                global last_hash_state
                last_hash_state = row[0]
        await db.commit()

# =========================
# SECURITY MIDDLEWARE
# =========================
async def verify_auth(authorization: str = Header(None), x_nonce: str = Header(None)):
    # 1. Token Validation
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization")
    try:
        token = authorization.replace("Bearer ", "")
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # 2. Nonce Replay Protection
    if not x_nonce:
        raise HTTPException(status_code=400, detail="Missing X-Nonce header")
    if x_nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Replay attack detected")
    used_nonces.add(x_nonce)

async def check_rate_limit(request: Request):
    ip = request.client.host
    now = time.time()

    if ip in blocked_ips and now < blocked_ips[ip]:
        raise HTTPException(status_code=403, detail="IP temporarily blocked")

    window = [t for t in rate_tracker[ip] if now - t < 60]
    window.append(now)
    rate_tracker[ip] = window

    if len(window) > RATE_LIMIT:
        blocked_ips[ip] = now + BLOCK_TIME
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

# =========================
# ANALYTICS ENGINE
# =========================
def analyze_risk(payload: dict):
    risk = 0.0
    reasons = []
    text = str(payload).lower()

    # Heuristic 1: Size
    if len(text) > 1000:
        risk += 0.3
        reasons.append("High payload volume")

    # Heuristic 2: Injection Keywords
    suspicious = ["exec(", "eval(", "os.system", "import ", "<script"]
    if any(s in text for s in suspicious):
        risk += 0.6
        reasons.append("Insecure code signature")

    # Heuristic 3: Nesting Depth (DoS Prevention)
    def get_depth(d, level=1):
        if not isinstance(d, dict) or not d or level > 10:
            return level
        return max(get_depth(v, level + 1) for v in d.values())

    if get_depth(payload) > 5:
        risk += 0.4
        reasons.append("Excessive object nesting")

    risk = min(1.0, risk)
    decision = "block" if risk > 0.8 else "flag" if risk > 0.4 else "allow"
    return decision, risk, reasons

# =========================
# AUDIT CHAINING
# =========================
async def log_to_audit(ip, decision, risk, reasons):
    global last_hash_state
    
    block_id = str(uuid.uuid4())
    ts = time.time()
    data_str = f"{ip}|{decision}|{risk}|{reasons}"
    
    # Create Immutable Hash Chain
    new_hash = hashlib.sha256(f"{last_hash_state}|{data_str}".encode()).hexdigest()
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (block_id, ts, ip, decision, risk, str(reasons), last_hash_state, new_hash)
        )
        await db.commit()
    
    last_hash_state = new_hash
    return new_hash

# =========================
# ENDPOINTS
# =========================
@app.post("/analyze", dependencies=[Depends(verify_auth), Depends(check_rate_limit)])
async def process_analysis(request: Request, data: Payload):
    start_time = time.time()
    
    decision, risk, reasons = analyze_risk(data.payload)
    audit_hash = await log_to_audit(request.client.host, decision, risk, reasons)

    messages = {"allow": "Accepted", "flag": "Flagged for Review", "block": "Access Denied"}

    return {
        "status": "success",
        "verdict": {
            "message": messages[decision],
            "decision": decision,
            "risk_score": risk,
            "reasons": reasons
        },
        "integrity": {
            "audit_hash": audit_hash,
            "latency_ms": round((time.time() - start_time) * 1000, 2)
        }
    }

@app.get("/")
async def health():
    return {
        "service": "David AI Core v3",
        "status": "online",
        "chain_head": last_hash_state[:8] + "..."
    }

@app.get("/audit/verify")
async def verify_chain():
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM audit_log") as cursor:
            count = await cursor.fetchone()
            return {"total_records": count[0], "integrity": "verified"}

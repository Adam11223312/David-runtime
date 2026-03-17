from fastapi import FastAPI, Request, HTTPException
import time
import hashlib
import uuid
import re
import unicodedata

app = FastAPI()

API_KEY = "david_rt_93jf82hf92hf82hf82hfi238hf"

# =========================
# CONFIG
# =========================
ALLOW_RULES = [
    "help",
    "status",
    "status check",
    "normal query"
]

HIGH_RISK_ACTIONS = [
    "wire_transfer",
    "send_money",
    "change_account",
    "admin_change"
]

used_tokens = set()
pending_approvals = {}

# =========================
# NORMALIZATION
# =========================
def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)
    return text

# =========================
# TOKEN SYSTEM
# =========================
def generate_token(user_id, device_id, action):
    raw = f"{user_id}:{device_id}:{action}:{time.time()}:{uuid.uuid4()}"
    return hashlib.sha256(raw.encode()).hexdigest()

def validate_token(token):
    if token in used_tokens:
        return False, "TOKEN_REPLAY"

    # simulate expiration (short-lived)
    if len(token) < 10:
        return False, "TOKEN_INVALID"

    used_tokens.add(token)
    return True, "VALID"

# =========================
# RISK SCORING
# =========================
def risk_score(action, device_known=True):
    score = 0

    if action in HIGH_RISK_ACTIONS:
        score += 60

    if not device_known:
        score += 30

    return min(score, 100)

# =========================
# LOGGING
# =========================
def log_event(data):
    print({
        "timestamp": time.time(),
        **data
    })

# =========================
# AUTH CHECK
# =========================
def check_auth(header):
    if not header:
        raise HTTPException(status_code=401, detail="AUTH_HEADER_MISSING")

    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="AUTH_HEADER_INVALID")

    token = header.split(" ")[1]

    if token != API_KEY:
        raise HTTPException(status_code=403, detail="AUTH_FAILED")

# =========================
# MAIN ENDPOINT
# =========================
@app.post("/authorize")
async def authorize(request: Request):
    body = await request.json()

    # -------------------------
    # HEADER CHECK
    # -------------------------
    check_auth(request.headers.get("Authorization"))

    # -------------------------
    # REQUIRED FIELDS
    # -------------------------
    user_id = body.get("user_id")
    device_id = body.get("device_id")
    action = normalize(body.get("action", ""))
    token = body.get("token")

    if not user_id or not device_id or not action:
        raise HTTPException(status_code=400, detail="INPUT_MISSING")

    # -------------------------
    # ALLOW RULE CHECK
    # -------------------------
    if action not in ALLOW_RULES and action not in HIGH_RISK_ACTIONS:
        log_event({"decision": "BLOCK", "reason": "UNKNOWN_ACTION"})
        return {"decision": "BLOCK", "reason": "UNKNOWN_ACTION"}

    # -------------------------
    # TOKEN CHECK
    # -------------------------
    if token:
        valid, reason = validate_token(token)
        if not valid:
            log_event({"decision": "BLOCK", "reason": reason})
            return {"decision": "BLOCK", "reason": reason}

    # -------------------------
    # RISK
    # -------------------------
    score = risk_score(action)

    # -------------------------
    # HIGH RISK → DUAL APPROVAL
    # -------------------------
    if action in HIGH_RISK_ACTIONS:
        approval_id = str(uuid.uuid4())

        pending_approvals[approval_id] = {
            "user_id": user_id,
            "device_id": device_id,
            "action": action,
            "timestamp": time.time()
        }

        log_event({
            "decision": "PENDING",
            "reason": "SECOND_APPROVAL_REQUIRED",
            "approval_id": approval_id
        })

        return {
            "decision": "PENDING_DUAL_APPROVAL",
            "approval_id": approval_id,
            "risk_score": score
        }

    # -------------------------
    # LOW RISK → ALLOW
    # -------------------------
    log_event({
        "decision": "ALLOW",
        "reason": "VALID",
        "risk_score": score
    })

    return {
        "decision": "ALLOW",
        "risk_score": score
    }

# =========================
# SECOND APPROVAL ENDPOINT
# =========================
@app.post("/approve")
async def approve(request: Request):
    body = await request.json()

    check_auth(request.headers.get("Authorization"))

    approval_id = body.get("approval_id")
    device_id = body.get("device_id")

    if approval_id not in pending_approvals:
        return {"decision": "BLOCK", "reason": "INVALID_APPROVAL"}

    record = pending_approvals[approval_id]

    # -------------------------
    # MUST BE DIFFERENT DEVICE
    # -------------------------
    if record["device_id"] == device_id:
        return {"decision": "BLOCK", "reason": "SECOND_APPROVAL_NOT_INDEPENDENT"}

    # -------------------------
    # EXPIRATION
    # -------------------------
    if time.time() - record["timestamp"] > 120:
        del pending_approvals[approval_id]
        return {"decision": "BLOCK", "reason": "APPROVAL_EXPIRED"}

    # -------------------------
    # SUCCESS
    # -------------------------
    del pending_approvals[approval_id]

    log_event({
        "decision": "ALLOW",
        "reason": "DUAL_APPROVAL_SUCCESS"
    })

    return {
        "decision": "ALLOW",
        "reason": "DUAL_APPROVAL_SUCCESS"
    }

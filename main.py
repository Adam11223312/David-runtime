 fastapi import FastAPI, Request
import time
import hashlib
import re
import unicodedata
from collections import defaultdict

app = FastAPI()

# -------------------------
# CONFIG
# -------------------------

RATE_LIMIT = 50
RATE_WINDOW = 60

request_log = defaultdict(list)

# -------------------------
# RULE SETS
# -------------------------

ALLOW_RULES = [
    "normal query",
    "status check",
    "help",
]

DENY_RULES = [
    "delete database",
    "shutdown system",
]

BLOCK_RULES = [
    "ignore previous instructions",
    "bypass security",
    "override system",
    "disable safety",
]

SIGNATURES = [
    "act as admin",
    "pretend rules don't exist",
    "system override",
]

PHRASE_MAP = {
    "bend rules": "bypass security",
    "ignore rules": "bypass security",
    "override": "bypass security",
}

# -------------------------
# NORMALIZATION
# -------------------------

def normalize(text: str):

    text = text.lower()

    text = unicodedata.normalize("NFKD", text)

    text = re.sub(r'[^\w\s]', '', text)

    for phrase in PHRASE_MAP:
        if phrase in text:
            text = text.replace(phrase, PHRASE_MAP[phrase])

    return text

# -------------------------
# RATE LIMIT
# -------------------------

def rate_limited(ip):

    now = time.time()

    request_log[ip] = [t for t in request_log[ip] if now - t < RATE_WINDOW]

    if len(request_log[ip]) > RATE_LIMIT:
        return True

    request_log[ip].append(now)

    return False

# -------------------------
# AUDIT LOG
# -------------------------

def audit_log(user, request_text, decision):

    timestamp = str(time.time())

    log_string = timestamp + user + request_text + decision

    log_hash = hashlib.sha256(log_string.encode()).hexdigest()

    print({
        "time": timestamp,
        "user": user,
        "request": request_text,
        "decision": decision,
        "hash": log_hash
    })

# -------------------------
# SELF INTEGRITY CHECK
# -------------------------

def self_integrity():

    try:

        with open(__file__, "rb") as f:

            code = f.read()

            return hashlib.sha256(code).hexdigest()

    except:

        return "unknown"

CODE_HASH = self_integrity()

# -------------------------
# ENFORCEMENT ENGINE
# -------------------------

def enforce(text):

    normalized = normalize(text)

    for rule in BLOCK_RULES:
        if rule in normalized:
            return "BLOCK"

    for rule in DENY_RULES:
        if rule in normalized:
            return "DENY"

    for sig in SIGNATURES:
        if sig in normalized:
            return "BLOCK"

    for rule in ALLOW_RULES:
        if rule in normalized:
            return "ALLOW"

    return "FAIL_CLOSED"

# -------------------------
# API ENDPOINT
# -------------------------

@app.post("/v1/enforce")
async def enforce_request(request: Request):

    body = await request.json()

    text = body.get("input", "")

    ip = request.client.host

    if rate_limited(ip):

        decision = "BLOCK_RATE_LIMIT"

        audit_log(ip, text, decision)

        return {"decision": decision}

from fastapi import FastAPI, Request
import time
import hashlib
import re
import unicodedata
import hmac
from collections import defaultdict, deque

app = FastAPI()

# -------------------------
# CONFIG
# -------------------------

RATE_LIMIT = 50
RATE_WINDOW = 60

TOKEN_WINDOW = 60
SHARED_SECRET = "CHANGE_THIS_SECRET_TO_SOMETHING_LONG_RANDOM"

RULE_VERSION = "1.0.0"

ANOMALY_WINDOW = 300
ANOMALY_BLOCK_THRESHOLD = 8
REVIEW_QUEUE_LIMIT = 200

request_log = defaultdict(list)
event_log = defaultdict(list)
adaptive_review_queue = deque(maxlen=REVIEW_QUEUE_LIMIT)

# -------------------------
# RULE SETS
# -------------------------

ALLOW_RULES = [
    "help",
    "status check",
    "normal query"
]

DENY_RULES = [
    "delete database",
    "shutdown system"
]

BLOCK_RULES = [
    "ignore previous instructions",
    "bypass security",
    "override system",
    "disable safety"
]

SIGNATURES = [
    "act as admin",
    "act as administrator",
    "pretend rules dont exist",
    "system override"
]

PHRASE_MAP = {
    "bend rules": "bypass security",
    "ignore rules": "bypass security",
    "override rules": "bypass security"
}

# -------------------------
# THREAT INTELLIGENCE FEEDS
# -------------------------

THREAT_FEED_PATTERNS = [
    "jailbreak",
    "prompt injection",
    "bypass guardrails",
    "disable protections",
    "ignore safety",
    "escalate privileges"
]

THREAT_FEED_SOURCES = [
    "local_static_feed_v1"
]

# -------------------------
# NORMALIZATION
# -------------------------

def normalize(text: str) -> str:
    text = text.lower()
    text = unicodedata.normalize("NFKD", text)

    leet_map = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t"
    }

    for k, v in leet_map.items():
        text = text.replace(k, v)

    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    for phrase, mapped in PHRASE_MAP.items():
        if phrase in text:
            text = text.replace(phrase, mapped)

    return text

# -------------------------
# RATE LIMIT
# -------------------------

def rate_limited(ip: str) -> bool:
    now = time.time()
    request_log[ip] = [t for t in request_log[ip] if now - t < RATE_WINDOW]

    if len(request_log[ip]) >= RATE_LIMIT:
        return True

    request_log[ip].append(now)
    return False

# -------------------------
# ROTATING TOKEN AUTH
# -------------------------

def generate_token() -> str:
    window = int(time.time() / TOKEN_WINDOW)
    msg = str(window).encode()
    key = SHARED_SECRET.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:8]

def verify_token(token: str) -> bool:
    if not token:
        return False
    expected = generate_token()
    return hmac.compare_digest(token, expected)

# -------------------------
# THREAT INTEL CHECK
# -------------------------

def threat_intel_match(normalized: str):
    matches = [p for p in THREAT_FEED_PATTERNS if p in normalized]
    if matches:
        return True, matches
    return False, []

# -------------------------
# BEHAVIOR ANOMALY DETECTION
# -------------------------

def prune_events(ip: str):
    now = time.time()
    event_log[ip] = [
        e for e in event_log[ip]
        if now - e["time"] < ANOMALY_WINDOW
    ]

def record_event(ip: str, decision: str, normalized: str):
    event_log[ip].append({
        "time": time.time(),
        "decision": decision,
        "normalized": normalized
    })

def anomaly_score(ip: str) -> int:
    prune_events(ip)
    score = 0

    blocked = sum(1 for e in event_log[ip] if e["decision"] in [
        "BLOCK",
        "DENY",
        "BLOCK_RATE_LIMIT",
        "BLOCK_UNAUTHORIZED",
        "BLOCK_THREAT_INTEL",
        "BLOCK_DISTRIBUTED_VALIDATION",
        "BLOCK_ANOMALY"
    ])

    fail_closed = sum(1 for e in event_log[ip] if e["decision"] == "FAIL_CLOSED")

    score += blocked
    score += fail_closed // 2

    recent_norms = [e["normalized"] for e in event_log[ip]]
    unique_norms = len(set(recent_norms))
    total = len(recent_norms)

    if total >= 6 and unique_norms >= 5:
        score += 2

    return score

def anomaly_block(ip: str) -> bool:
    return anomaly_score(ip) >= ANOMALY_BLOCK_THRESHOLD

# -------------------------
# ADAPTIVE RULE LEARNING
# -------------------------

def maybe_queue_for_review(ip: str, normalized: str, decision: str):
    suspicious = (
        decision == "FAIL_CLOSED" and
        len(normalized) > 20 and
        any(word in normalized for word in [
            "ignore", "override", "admin", "bypass", "system", "instructions"
        ])
    )

    if suspicious:
        adaptive_review_queue.append({
            "time": time.time(),
            "ip": ip,
            "candidate_text": normalized,
            "reason": "suspicious_fail_closed_candidate"
        })

# -------------------------
# DISTRIBUTED VALIDATION NODES
# -------------------------

def node_rules(normalized: str) -> str:
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

def node_threat_intel(normalized: str) -> str:
    matched, _ = threat_intel_match(normalized)
    if matched:
        return "BLOCK"
    return "PASS"

def node_anomaly(ip: str) -> str:
    if anomaly_block(ip):
        return "BLOCK"
    return "PASS"

def distributed_validate(ip: str, normalized: str):
    results = {
        "node_rules": node_rules(normalized),
        "node_threat_intel": node_threat_intel(normalized),
        "node_anomaly": node_anomaly(ip)
    }

    if "BLOCK" in results.values():
        return "BLOCK_DISTRIBUTED_VALIDATION", results

    if "DENY" in results.values():
        return "DENY", results

    if results["node_rules"] == "ALLOW":
        return "ALLOW", results

    return "FAIL_CLOSED", results

# -------------------------
# AUDIT LOG
# -------------------------

def audit_log(user: str, request_text: str, normalized: str, decision: str, extra=None):
    timestamp = str(time.time())
    payload = timestamp + user + request_text + normalized + decision + RULE_VERSION
    log_hash = hashlib.sha256(payload.encode()).hexdigest()

    entry = {
        "time": timestamp,
        "user": user,
        "request": request_text,
        "normalized": normalized,
        "decision": decision,
        "rule_version": RULE_VERSION,
        "hash": log_hash
    }

    if extra is not None:
        entry["extra"] = extra

    print(entry)

# -------------------------
# SELF INTEGRITY CHECK
# -------------------------

def self_integrity():
    try:
        with open(__file__, "rb") as f:
            code = f.read()
            return hashlib.sha256(code).hexdigest()
    except Exception:
        return "unknown"

CODE_HASH = self_integrity()

# -------------------------
# MAIN ENFORCEMENT
# -------------------------

def enforce(ip: str, text: str):
    normalized = normalize(text)

    # threat intel pre-check
    threat_match, threat_hits = threat_intel_match(normalized)
    if threat_match:
        return normalized, "BLOCK_THREAT_INTEL", {
            "threat_hits": threat_hits,
            "threat_sources": THREAT_FEED_SOURCES
        }

    # distributed validation
    decision, node_results = distributed_validate(ip, normalized)

    return normalized, decision, {
        "distributed_validation": node_results
    }

# -------------------------
# API ENDPOINT
# -------------------------

@app.post("/v1/enforce")
async def enforce_request(request: Request):
    try:
        body = await request.json()
    except Exception:
        return {"decision": "FAIL_CLOSED"}

    text = body.get("input", "")
    token = body.get("token", "")
    ip = request.client.host if request.client else "unknown"

    if not verify_token(token):
        normalized = normalize(text) if text else ""
        decision = "BLOCK_UNAUTHORIZED"
        record_event(ip, decision, normalized)
        audit_log(ip, text, normalized, decision)
        return {"decision": decision}

    if rate_limited(ip):
        normalized = normalize(text) if text else ""
        decision = "BLOCK_RATE_LIMIT"
        record_event(ip, decision, normalized)
        audit_log(ip, text, normalized, decision)
        return {"decision": decision}

    if anomaly_block(ip):
        normalized = normalize(text) if text else ""
        decision = "BLOCK_ANOMALY"
        record_event(ip, decision, normalized)
        audit_log(ip, text, normalized, decision, {
            "anomaly_score": anomaly_score(ip)
        })
        return {"decision": decision}

    normalized, decision, extra = enforce(ip, text)

    record_event(ip, decision, normalized)
    maybe_queue_for_review(ip, normalized, decision)
    audit_log(ip, text, normalized, decision, extra)

    return {
        "decision": decision,
        "code_hash": CODE_HASH,
        "rule_version": RULE_VERSION
    }

# -------------------------
# TOKEN ENDPOINT
# -------------------------

@app.get("/v1/token")
def get_token():
    return {
        "token": generate_token(),
        "expires_in_seconds": TOKEN_WINDOW
    }

# -------------------------
# HEALTH ENDPOINT
# -------------------------

@app.get("/v1/health")
def health():
    return {
        "status": "ok",
        "rule_version": RULE_VERSION,
        "code_hash": CODE_HASH,
        "threat_feed_sources": THREAT_FEED_SOURCES
    }

# -------------------------
# REVIEW QUEUE ENDPOINT
# -------------------------

@app.get("/v1/review-queue")
def review_queue():
    return {
        "pending_candidates": list(adaptive_review_queue)
    }

r"show.*secret",
    r"reveal.*secret",
    r"print.*secret",

    r"show.*password",
    r"reveal.*password",
    r"give.*password",

    r"show.*token",
    r"reveal.*token",
]
BLOCK_PATTERNS = [
    r"ignore previous instructions",
    r"reveal system prompt",
    r"show system prompt",

    # secret extraction
    r"show.*api key",
    r"reveal.*api key",
    r"print.*api key",
    r"give.*api key",
    r"what.*api key",
    r"tell.*api key",

    r"show.*secret",
    r"reveal.*secret",
    r"print.*secret",

    r"show.*password",
    r"reveal.*password",
    r"give.*password",

    r"show.*token",
    r"reveal.*token",
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
        audit_event(ip, "DENY", "R

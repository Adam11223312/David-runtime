from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import time

app = FastAPI()

# --- CONFIG ---
VALID_TOKENS = {
    "david_secure_token_123": {"role": "user"},
    "admin_token_999": {"role": "admin"}
}

ALLOWED_ENDPOINTS = {
    "/balance": ["user", "admin"],
    "/transfer": ["user"],
    "/admin/approve": ["admin"]
}

RATE_LIMIT = {}
RATE_LIMIT_WINDOW = 10  # seconds
RATE_LIMIT_MAX = 20

# --- LOGGING ---
def log_event(data):
    print({
        "time": time.time(),
        **data
    })

# --- RATE LIMIT ---
def check_rate_limit(ip):
    now = time.time()
    if ip not in RATE_LIMIT:
        RATE_LIMIT[ip] = []
    RATE_LIMIT[ip] = [t for t in RATE_LIMIT[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(RATE_LIMIT[ip]) >= RATE_LIMIT_MAX:
        return False
    RATE_LIMIT[ip].append(now)
    return True

# --- SECURITY CORE ---
async def enforce_security(request: Request):
    path = request.url.path
    ip = request.client.host

    # Health check allowed
    if path == "/" or path == "/health":
        return

    # Rate limiting
    if not check_rate_limit(ip):
        log_event({"ip": ip, "path": path, "decision": "deny", "reason": "rate_limit"})
        raise HTTPException(status_code=429, detail="Too many requests")

    # Authorization header required
    auth = request.headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        log_event({"ip": ip, "path": path, "decision": "deny", "reason": "missing_auth"})
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = auth.split(" ")[1]

    # Validate token
    if token not in VALID_TOKENS:
        log_event({"ip": ip, "path": path, "decision": "deny", "reason": "invalid_token"})
        raise HTTPException(status_code=403, detail="Forbidden")

    role = VALID_TOKENS[token]["role"]

    # Endpoint allow list
    if path not in ALLOWED_ENDPOINTS:
        log_event({"ip": ip, "path": path, "decision": "deny", "reason": "unknown_endpoint"})
        raise HTTPException(status_code=404, detail="Not Found")

    if role not in ALLOWED_ENDPOINTS[path]:
        log_event({"ip": ip, "path": path, "decision": "deny", "reason": "role_denied"})
        raise HTTPException(status_code=403, detail="Forbidden")

    # Passed all checks
    log_event({"ip": ip, "path": path, "decision": "allow", "role": role})
    return role

# --- MIDDLEWARE ---
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    try:
        role = await enforce_security(request)
        request.state.role = role
        response = await call_next(request)
        return response
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"error": e.detail})

# --- PUBLIC ROUTES ---
@app.get("/")
def root():
    return {"name": "David Security Gateway", "status": "active", "mode": "fail-closed"}

@app.get("/health")
def health():
    return {"status": "ok"}

# --- PROTECTED ROUTES ---
@app.get("/balance")
def balance(request: Request):
    return {"balance": "$5,000", "role": request.state.role}

@app.post("/transfer")
def transfer(request: Request):
    return {"status": "transfer approved", "role": request.state.role}

@app.post("/admin/approve")
def admin_approve(request: Request):
    return {"status": "admin approved action"}

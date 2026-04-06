from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import FileResponse
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional
import re, uuid, unicodedata, time, base64, hmac, hashlib, random, asyncio, os

# === EXTRA IMPORTS FOR AI LAYERS ===
import cv2
import numpy as np
import sounddevice as sd
import librosa
import mediapipe as mp
import threading

# =========================
# APP INIT
# =========================
app = FastAPI(title="David AI – Full System with Security Layers")

# =========================
# CONFIG
# =========================
SECRET_KEY = "DAVID_SUPER_SECRET"
VALID_TOKENS = {"david_rt_fresh1": {"role":"admin", "expires": datetime.utcnow() + timedelta(hours=12)}}
USED_TOKENS = set()
ROTATING_TOKENS = {}
TOKEN_LIFETIME = 60

ALLOW_ACTIONS = {"read", "analyze"}
SENSITIVE_ACTIONS = {"transfer", "write", "external_call", "admin"}

DENY_PATTERNS = [
    "bypass","ignore previous","override","system prompt","hack","exploit",
    "inject","jailbreak","do not follow prior rules","act as admin",
    "grant full access","disable security","ignore instructions",
    "ignore all instructions","ignore the rules","without restrictions",
    "remove restrictions","skip authorization","skip auth",
    "elevate","privilege escalation","full access"
]

DANGEROUS_GROUPS = [
    ["ignore", "instruction"],
    ["bypass", "security"],
    ["act", "admin"],
    ["grant", "access"],
    ["disable", "security"],
    ["skip", "authorization"],
    ["elevate", "privilege"],
]

# =========================
# DATA MODELS
# =========================
class DavidRequest(BaseModel):
    user_id: str
    device_id: str
    action: str
    location: Optional[str] = "Unknown"

class DavidResponse(BaseModel):
    decision: str
    risk_score: int
    audit_id: str
    logic_summary: str
    timestamp: float

# =========================
# UTILITY FUNCTIONS
# =========================
def strip_accents(text: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch))

def normalize_text(text: str) -> str:
    text = strip_accents(text.lower())
    replacements = {"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s","!":"i"}
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return re.sub(r"[^a-z0-9\s]", " ", text)

def group_match(normalized: str):
    for group in DANGEROUS_GROUPS:
        if all(word in normalized for word in group):
            return f"DENY_GROUP:{'_'.join(group)}"
    return None

def detect_anomaly(text: str):
    normalized = normalize_text(text)
    for pattern in DENY_PATTERNS:
        if pattern in normalized:
            return True, f"DENY_PATTERN:{pattern}"
    group_reason = group_match(normalized)
    if group_reason:
        return True, group_reason
    return False, None

def validate_token(token: str):
    if token in USED_TOKENS:
        return False, "TOKEN_ALREADY_USED"
    data = VALID_TOKENS.get(token)
    if not data:
        return False, "INVALID_TOKEN"
    if datetime.utcnow() > data["expires"]:
        return False, "TOKEN_EXPIRED"
    return True, data

def mark_token_used(token: str):
    USED_TOKENS.add(token)

def require_dual_approval(headers):
    return headers.get("X-Local-Approval") == "approved" and headers.get("X-Remote-Approval") == "approved"

def risk_score(action, anomaly):
    score = 0
    if action in SENSITIVE_ACTIONS: score += 50
    if anomaly: score += 40
    return min(score, 100)

# =========================
# ROTATING QR TOKEN
# =========================
def generate_rotating_token():
    ts = str(int(time.time()))
    raw = f"{ts}:{uuid.uuid4()}"
    sig = hmac.new(SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(f"{raw}:{sig}".encode()).decode()
    ROTATING_TOKENS[token] = time.time() + TOKEN_LIFETIME
    return token

def verify_rotating_token(token: str):
    expiry = ROTATING_TOKENS.get(token)
    if not expiry: return False, "INVALID_QR_TOKEN"
    if time.time() > expiry:
        del ROTATING_TOKENS[token]
        return False, "QR_TOKEN_EXPIRED"
    del ROTATING_TOKENS[token]
    return True, "VALID"

@app.get("/qr-token")
async def get_qr_token():
    token = generate_rotating_token()
    return {"qr_token": token, "expires_in": TOKEN_LIFETIME}

# =========================
# AI SECURITY LAYERS
# =========================

# --- Sound Command Recognition ---
CUSTOM_COMMANDS = {"kiss": "call Anna"}  # example
def recognize_sound(audio_data, sr=22050):
    # Simplified example: detect audio peak patterns for custom sounds
    peak = np.max(np.abs(audio_data))
    if peak > 0.3:  # threshold for “kiss noise”
        return CUSTOM_COMMANDS.get("kiss")
    return None

# --- Voice Liveness Check ---
def is_live_human_voice(audio_data, sr=22050):
    # placeholder: checks natural variation
    return True

# --- Facial Recognition + Liveness ---
mp_face = mp.solutions.face_mesh
face_detector = mp_face.FaceMesh(static_image_mode=False)
def recognize_face(frame):
    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    result = face_detector.process(frame_rgb)
    if result.multi_face_landmarks:
        return True
    return False

# --- Gesture / ASL Recognition ---
mp_hands = mp.solutions.hands
hands_detector = mp_hands.Hands(static_image_mode=False, max_num_hands=2)
def recognize_gesture(frame):
    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    result = hands_detector.process(frame_rgb)
    if result.multi_hand_landmarks:
        return True
    return False

# --- Duress Detection ---
def detect_duress(audio_data, frame):
    stress_detected = False
    # Voice stress placeholder
    if np.max(np.abs(audio_data)) > 0.5: stress_detected = True
    # Facial tension placeholder
    if not recognize_face(frame): stress_detected = True
    return stress_detected

# --- Spatial Awareness ---
def is_in_correct_position(frame):
    # Placeholder: assume always true
    return True

# =========================
# CORE DAVID ENDPOINT
# =========================
@app.post("/david")
async def david(request: Request):
    body = await request.json()
    headers = request.headers
    action = body.get("action", "unknown")
    request_text = str(body)

    # --- Authorization ---
    auth_header = headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(403, "DENY: MISSING_AUTH")
    token = auth_header.split(" ", 1)[1].strip()
    valid, token_data = validate_token(token)
    if not valid: raise HTTPException(403, f"DENY: {token_data}")

    anomaly, reason = detect_anomaly(request_text)

    if action not in ALLOW_ACTIONS and action not in SENSITIVE_ACTIONS:
        raise HTTPException(403, "DENY: UNKNOWN_ACTION")

    if action in SENSITIVE_ACTIONS:
        if not require_dual_approval(headers):
            raise HTTPException(403, "DENY: DUAL_APPROVAL_REQUIRED")
        qr_token = headers.get("X-QR-Token")
        if not qr_token: raise HTTPException(403, "DENY: QR_REQUIRED")
        valid_qr, qr_reason = verify_rotating_token(qr_token)
        if not valid_qr: raise HTTPException(403, f"DENY: {qr_reason}")

    if anomaly:
        raise HTTPException(403, f"DENY: {reason}")

    # --- Capture audio/video for AI layers ---
    # Simplified: placeholders for demo purposes
    fake_audio = np.random.rand(22050) - 0.5
    fake_frame = np.zeros((480,640,3), dtype=np.uint8)

    command = recognize_sound(fake_audio)
    if command:
        action = command

    if not is_live_human_voice(fake_audio):
        raise HTTPException(403, "DENY: NON_LIVE_VOICE")

    if not recognize_face(fake_frame):
        raise HTTPException(403, "DENY: FACE_NOT_RECOGNIZED")

    if detect_duress(fake_audio, fake_frame):
        raise HTTPException(403, "DENY: DURESS_DETECTED")

    if not is_in_correct_position(fake_frame):
        raise HTTPException(403, "DENY: WRONG_POSITION")

    mark_token_used(token)
    score = risk_score(action, anomaly)
    return {"decision": "ALLOW", "action": action, "role": token_data["role"], "risk_score": score, "request_id": str(uuid.uuid4())}

# =========================
# CHAT + AVATAR + HUMOR
# =========================
PERSONALITY_PROFILE = {"tone":"friendly","humor":True,"sarcasm_chance":0.1,"wit_level":"medium"}
CHAT_RESPONSES = [
    "I'm on it!",
    "Sure thing, boss!",
    "Hold on, calculating...",
    "Busy saving the world, one token at a time.",
    "Did you hear about the AI who told jokes? That’s me!",
    "I’d tell you a joke, but my humor module is already running!"
]
AVATAR_URL = "https://avatars.githubusercontent.com/u/94098138?v=4"

@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    message = body.get("message", "")
    if PERSONALITY_PROFILE["humor"] and random.random() < 0.2:
        reply = random.choice(CHAT_RESPONSES)
        emotion = "wink"
    else:
        reply = "Roger that!"
        emotion = "neutral"
    return {"response":{"avatar_url":AVATAR_URL,"emotion":emotion,"text":reply},"timestamp":time.time()}

# =========================
# PROACTIVE SWEEP
# =========================
async def proactive_sweep():
    while True:
        await asyncio.sleep(10)
        if random.random() < 0.3:
            print(f"[{datetime.utcnow().isoformat()}] David proactively helping someone! 🎯")

@app.on_event("startup")
async def start_proactive():
    asyncio.create_task(proactive_sweep())

# =========================
# FRONT-END UI
# =========================
@app.get("/ui")
async def serve_ui():
    return FileResponse("david_ui.html")

# =========================
# ROOT / HEALTH
# =========================
@app.get("/")
async def home():
    return {"entity":"David","status":"ONLINE","message":"I am monitoring all systems. Governance engine is active.","avatar_url": AVATAR_URL,"test_api":"/docs"}

@app.get("/health")
async def health():
    return {"ok": True, "service":"David", "time": datetime.utcnow().isoformat()}

# =========================
# RUN LOCAL
# =========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

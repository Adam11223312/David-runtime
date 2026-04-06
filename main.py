from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional
import re, uuid, unicodedata, time, base64, hmac, hashlib, random, asyncio

# =========================
# APP INIT
# =========================
app = FastAPI(title="David AI – Full System Live")

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
    "grant full access","disable security","ignore instructions","ignore all instructions",
    "ignore the rules","without restrictions","remove restrictions","skip authorization",
    "skip auth","elevate","privilege escalation","full access"
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
# AI SECURITY LAYERS (SIMULATED)
# =========================
CUSTOM_COMMANDS = {"kiss": "call Anna"}  # example

def recognize_sound(audio_data):
    peak = max(audio_data) if audio_data else 0
    if peak > 0.3:
        return CUSTOM_COMMANDS.get("kiss")
    return None

def is_live_human_voice(audio_data):
    return True

def detect_duress(audio_data, video_frame):
    stress_detected = False
    if audio_data and max(audio_data) > 0.5:
        stress_detected = True
    if video_frame is None:
        stress_detected = True
    return stress_detected

def is_in_correct_position(video_frame):
    return True

# =========================
# DAVID ENDPOINT
# =========================
@app.post("/david")
async def david(request: Request):
    body = await request.json()
    headers = request.headers
    action = body.get("action", "unknown")
    request_text = str(body)

    auth_header = headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(403, "DENY: MISSING_AUTH")
    token = auth_header.split(" ",1)[1].strip()
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

    fake_audio = [random.random()-0.5 for _ in range(22050)]
    fake_frame = None
    command = recognize_sound(fake_audio)
    if command:
        action = command

    if not is_live_human_voice(fake_audio):
        raise HTTPException(403, "DENY: NON_LIVE_VOICE")
    if detect_duress(fake_audio, fake_frame):
        raise HTTPException(403, "DENY: DURESS_DETECTED")
    if not is_in_correct_position(fake_frame):
        raise HTTPException(403, "DENY: WRONG_POSITION")

    mark_token_used(token)
    score = risk_score(action, anomaly)
    return {"decision":"ALLOW","action":action,"role":token_data["role"],"risk_score":score,"request_id":str(uuid.uuid4())}

# =========================
# CHAT + AVATAR + HUMOR
# =========================
PERSONALITY_PROFILE = {"tone":"friendly","humor":True,"sarcasm_chance":0.1,"wit_level":"medium"}
CHAT_RESPONSES = [
    "I'm on it!","Sure thing, boss!","Hold on, calculating...",
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
# FRONT-END UI (3D AVATAR)
# =========================
DAVID_UI_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>David Avatar</title>
<style>body { margin:0; overflow:hidden; }</style>
</head>
<body>
<script src="https://cdn.jsdelivr.net/npm/three@0.162.0/build/three.min.js"></script>
<script>
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight,0.1,1000);
const renderer = new THREE.WebGLRenderer();
renderer.setSize(window.innerWidth, window.innerHeight);
document.body.appendChild(renderer.domElement);

const geometry = new THREE.SphereGeometry(1,32,32);
const material = new THREE.MeshStandardMaterial({color:0x00ff00});
const avatar = new THREE.Mesh(geometry, material);
scene.add(avatar);

const light = new THREE.PointLight(0xffffff,1,100);
light.position.set(10,10,10);
scene.add(light);

camera.position.z = 5;
function animate(){
  requestAnimationFrame(animate);
  avatar.rotation.y += 0.01;
  renderer.render(scene,camera);
}
animate();
</script>
</body>
</html>
"""

@app.get("/ui", response_class=HTMLResponse)
async def serve_ui():
    return DAVID_UI_HTML

# =========================
# ROOT / HEALTH
# =========================
@app.get("/")
async def home():
    return {"entity":"David","status":"ONLINE","message":"Monitoring all systems. Governance engine active.","avatar_url": AVATAR_URL,"test_api":"/docs"}

@app.get("/health")
async def health():
    return {"ok": True, "service":"David", "time": datetime.utcnow().isoformat()}

# =========================
# RUN LOCAL
# =========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

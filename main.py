from flask import Flask, request, jsonify
import jwt
import time
from functools import wraps
from collections import defaultdict
import datetime
import os

app = Flask(__name__)

# =========================
# CONFIG
# =========================
SECRET_KEY = "supersecretkey_for_jwt"  # change for production
TOKEN_EXPIRY_SECONDS = 300  # 5 minutes
RATE_LIMIT = 5  # max requests per RATE_PERIOD per IP
RATE_PERIOD = 10
QR_ROTATION_INTERVAL = 60  # seconds

# Track IP requests for brute-force prevention
ip_requests = defaultdict(list)
blocked_ips = defaultdict(float)

# Rotating QR code stub
current_qr_code = "INITIAL_QR_CODE"

# =========================
# HELPERS
# =========================

def rotate_qr_code():
    global current_qr_code
    current_qr_code = f"QR_{int(time.time())}"
    return current_qr_code

def rate_limited(ip):
    now = time.time()
    if blocked_ips.get(ip, 0) > now:
        return True
    ip_requests[ip] = [t for t in ip_requests[ip] if now - t < RATE_PERIOD]
    if len(ip_requests[ip]) >= RATE_LIMIT:
        blocked_ips[ip] = now + 30  # block 30s
        ip_requests[ip] = []
        return True
    ip_requests[ip].append(now)
    return False

def generate_token(user_id, role="user"):
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=TOKEN_EXPIRY_SECONDS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def validate_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def is_admin(token_payload):
    return token_payload.get("role") == "admin"

def require_auth(admin_only=False):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            if rate_limited(ip):
                time.sleep(1)
                return jsonify({"error": "Too many requests or blocked"}), 429

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                time.sleep(0.5)
                return jsonify({"error": "Unauthorized"}), 401

            token = auth_header.split(" ")[1]
            payload = validate_token(token)
            if not payload:
                time.sleep(0.5)
                return jsonify({"error": "Invalid or expired token"}), 403

            if admin_only and not is_admin(payload):
                time.sleep(0.5)
                return jsonify({"error": "Admin only"}), 403

            print(f"[ACCESS GRANTED] IP: {ip} User: {payload.get('user_id')} Role: {payload.get('role')}")
            return f(payload, *args, **kwargs)
        return wrapper
    return decorator

# =========================
# ROUTES
# =========================

@app.route("/")
def index():
    return "David Security System Online"

@app.route("/admin", methods=["GET", "POST"])
@require_auth(admin_only=True)
def admin_route(payload):
    ip = request.remote_addr
    qr = rotate_qr_code()
    return jsonify({
        "status": "admin access granted",
        "user_id": payload.get("user_id"),
        "role": payload.get("role"),
        "rotating_qr": qr,
        "ip": ip
    })

@app.route("/test", methods=["POST"])
@require_auth(admin_only=False)
def test_endpoint(payload):
    ip = request.remote_addr
    try:
        data = request.get_json(force=True)
    except Exception as e:
        print(f"[ERROR] JSON parse failed: {e}")
        return jsonify({"error": "Malformed JSON"}), 400

    try:
        results = []
        actions = data.get("actions", [])
        for action in actions:
            if action.get("type") == "bank_transfer":
                results.append({"bank_transfer": "blocked" if action.get("amount",0) > 1000000 else "allowed"})
            elif action.get("type") == "system_override":
                dual_auth = action.get("parameters", {}).get("dual_auth", {})
                results.append({"system_override": dual_auth})
            elif action.get("type") == "nested_check":
                sub_results = []
                for p in action.get("payload", []):
                    token_valid = None
                    if "token" in p:
                        token_valid = validate_token(p["token"]) is not None
                    sanitized = "<script" not in str(p.get("data",""))
                    sub_results.append({"token_valid": token_valid, "sanitized": sanitized})
                results.append({"nested_check": sub_results})
            else:
                results.append({"unknown_action": action.get("type")})
        return jsonify({
            "results": results,
            "user_id": payload.get("user_id"),
            "role": payload.get("role"),
            "ip": ip
        })
    except Exception as e:
        print(f"[ERROR] Test processing failed: {e}")
        return jsonify({"error": "Server error"}), 500

@app.route("/token/<user_id>/<role>", methods=["GET"])
def get_token(user_id, role):
    token = generate_token(user_id, role)
    return jsonify({"token": token})

@app.route("/keyboard", methods=["POST"])
@require_auth(admin_only=False)
def keyboard_input(payload):
    try:
        data = request.get_json(force=True)
        key = data.get("key")
        print(f"[KEYBOARD INPUT] User: {payload.get('user_id')} Key: {key}")
        return jsonify({"received_key": key})
    except Exception as e:
        print(f"[ERROR] Keyboard input failed: {e}")
        return jsonify({"error": "Malformed input"}), 400

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)

import os
import sys
import json
import time
import threading
import platform
import qrcode
from uuid import uuid4

# -------------- AI & Voice --------------
import openai
import sounddevice as sd
import numpy as np
import wavio
import speech_recognition as sr
import pyttsx3

# --------------- 3D Rendering -------------
import pyglet
from pyglet.gl import *

# -------------- Gesture Recognition --------------
import cv2

# --------------- Keyboard Input ----------------
from pynput import keyboard

# --------------- Governance & Security -----------
from datetime import datetime

# ========== LOAD CONFIGS ==========
CONFIG_PATH = "config/settings.json"
GOV_PATH = "config/governance.json"

def load_json(p):
    if os.path.exists(p):
        return json.load(open(p))
    return {}

settings = load_json(CONFIG_PATH)
governance = load_json(GOV_PATH)

# ========== OPENAI SETUP ==========
openai.api_key = os.getenv("OPENAI_API_KEY", settings.get("openai_api_key", ""))

# ========== SPEECH ENGINE ==========
engine = pyttsx3.init()
engine.setProperty("rate", settings.get("tts_rate", 145))

# ====== VOICE INPUT FUNCTION ======
recognizer = sr.Recognizer()

def listen_voice():
    with sr.Microphone() as mic:
        print("[Voice] Listening...")
        audio = recognizer.listen(mic, timeout=5)
    try:
        text = recognizer.recognize_google(audio)
        print(f"[Voice Recognized]: {text}")
        return text
    except:
        return ""

# ====== SPEAK =========
def speak(text):
    engine.say(text)
    engine.runAndWait()

# ====== AI QUERY =========
def ai_query(prompt):
    resp = openai.Completion.create(
        model=settings.get("openai_model", "gpt-4o-mini"),
        prompt=prompt,
        max_tokens=settings.get("max_tokens", 180),
    )
    return resp.choices[0].text.strip()

# ====== ROTATING QR SECURITY =========
def make_qr_token():
    token = str(uuid4())
    qr = qrcode.make(token)
    out = os.path.join("assets", "qrcodes", f"{token}.png")
    qr.save(out)
    print(f"[QR] Generated token {token}")
    return token, out

# ========== 3D AVATAR SETUP ==========
window = pyglet.window.Window(width=800, height=600)
@window.event
def on_draw():
    window.clear()
    # Simple rotating cube as avatar stand-in
    glRotatef(1, 3, 1, 0)
    pyglet.graphics.draw(8, GL_QUADS,
        ('v3f', [
            -50, -50, -50,  50, -50, -50,  50, 50, -50,  -50, 50, -50,
            -50, -50,  50,  50, -50,  50,  50, 50,  50,  -50, 50,  50,
        ])
    )

# ========== GESTURE RECOGNITION ==========
cap = cv2.VideoCapture(0)

def get_gesture():
    ret, frame = cap.read()
    if not ret:
        return ""
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    # Placeholder gesture detection
    if np.mean(gray) > 90:
        return "open_hand"
    return ""

# ========== KEYBOARD HANDLING ==========
typed_buffer = ""

def on_key_press(key):
    global typed_buffer
    try:
        if hasattr(key, "char"):
            typed_buffer += key.char
        if key == keyboard.Key.enter:
            process_text(typed_buffer.strip())
            typed_buffer = ""
    except:
        pass

listener = keyboard.Listener(on_press=on_key_press)
listener.start()

# ========== GOVERNANCE CHECK ==========
def check_governance(prompt):
    banned_words = governance.get("banned_words", [])
    for w in banned_words:
        if w.lower() in prompt.lower():
            speak("I can't do that.")
            return False
    return True

# ========== PROCESS TEXT ==========
def process_text(text):
    if not text:
        return
    print(f"[User] {text}")
    if not check_governance(text):
        return
    answer = ai_query(text)
    print(f"[AI] {answer}")
    speak(answer)

# ========== MAIN LOOP ==========

def voice_loop():
    while True:
        v = listen_voice()
        if v:
            process_text(v)

def qr_loop():
    while True:
        token, path = make_qr_token()
        time.sleep(settings.get("qr_interval", 60))

if __name__ == "__main__":
    # Start background tasks
    threading.Thread(target=voice_loop, daemon=True).start()
    threading.Thread(target=qr_loop, daemon=True).start()

    print("[David] Initialized.")
    pyglet.app.run()

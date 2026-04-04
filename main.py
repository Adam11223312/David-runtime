# main.py - David AI Conversational Full System (No visuals)

import threading
import time
import pyttsx3
import keyboard
import os
import random

try:
    import qrcode
    from PIL import Image
except ImportError:
    os.system(f"{os.sys.executable} -m pip install qrcode[pil] pillow")
    import qrcode
    from PIL import Image

# -----------------------
# Voice Setup
# -----------------------
VOICE_RATE = 150
engine = pyttsx3.init()
engine.setProperty('rate', VOICE_RATE)

def speak(text):
    engine.say(text)
    engine.runAndWait()

# -----------------------
# Keyboard Listener
# -----------------------
def listen_keyboard():
    print("Press ESC to exit David.")
    while True:
        if keyboard.is_pressed('esc'):
            print("Exiting David...")
            os._exit(0)
        time.sleep(0.05)

# -----------------------
# QR Code Generator
# -----------------------
QR_CODE_DIR = "qrcodes"
if not os.path.exists(QR_CODE_DIR):
    os.makedirs(QR_CODE_DIR)

def generate_qr(data="David AI Operational"):
    try:
        filename = os.path.join(QR_CODE_DIR, f"qr_{int(time.time())}.png")
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)
        print(f"Generated QR code: {filename}")
    except Exception as e:
        print("QR generation error:", e)

def qr_loop():
    while True:
        generate_qr()
        time.sleep(10)

# -----------------------
# Conversational Personality
# -----------------------
def david_response(user_input):
    user_input_lower = user_input.lower()
    responses = []

    # Humor / wit
    if "joke" in user_input_lower:
        jokes = [
            "Why did the AI cross the road? To optimize traffic, of course!",
            "I would tell you a joke about algorithms, but it's still running..."
        ]
        responses.append(random.choice(jokes))
    
    # Greetings
    if any(word in user_input_lower for word in ["hi", "hello", "hey"]):
        responses.append("Hey there! David at your service.")
    
    # Accessibility / special phrases
    if "blinding noise" in user_input_lower:
        responses.append("I hear you! Activating hand-gesture alert mode.")
    
    # Default fallback
    if not responses:
        # Add some human-like responses
        fallback = [
            f"Interesting, tell me more about '{user_input}'",
            f"Hmm, I think I understand, can you expand on that?",
            f"Ah, got it! You said: '{user_input}'"
        ]
        responses.append(random.choice(fallback))
    
    # Pick one response
    return random.choice(responses)

# -----------------------
# Main Loop
# -----------------------
def main():
    threading.Thread(target=listen_keyboard, daemon=True).start()
    threading.Thread(target=qr_loop, daemon=True).start()

    speak("Hello! I am David, your intelligent assistant. Let's chat.")

    while True:
        user_input = input("You: ")
        if user_input.strip() != "":
            response = david_response(user_input)
            print("David:", response)
            speak(response)

if __name__ == "__main__":
    main()o

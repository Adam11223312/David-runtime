# main.py - David AI Ready-to-Run

import os
import sys
import threading
import time

# -----------------------
# Safe imports
# -----------------------
try:
    import qrcode
except ImportError:
    print("QR code module missing. Installing...")
    os.system(f"{sys.executable} -m pip install qrcode[pil] pillow")
    import qrcode

try:
    from PIL import Image
except ImportError:
    print("PIL missing. Installing...")
    os.system(f"{sys.executable} -m pip install pillow")
    from PIL import Image

try:
    import pyttsx3  # Voice engine
except ImportError:
    print("pyttsx3 missing. Installing...")
    os.system(f"{sys.executable} -m pip install pyttsx3")
    import pyttsx3

try:
    import keyboard  # QWERTY input
except ImportError:
    print("keyboard module missing. Installing...")
    os.system(f"{sys.executable} -m pip install keyboard")
    import keyboard

try:
    import cv2  # For avatar/face display
except ImportError:
    print("opencv missing. Installing...")
    os.system(f"{sys.executable} -m pip install opencv-python")
    import cv2

# -----------------------
# Global Settings
# -----------------------
VOICE_RATE = 150
QR_CODE_DIR = "qrcodes"
AVATAR_IMAGE = "avatar.png"  # replace with your face/avatar

if not os.path.exists(QR_CODE_DIR):
    os.makedirs(QR_CODE_DIR)

# -----------------------
# Voice Engine Setup
# -----------------------
engine = pyttsx3.init()
engine.setProperty('rate', VOICE_RATE)

def speak(text):
    engine.say(text)
    engine.runAndWait()

# -----------------------
# QR Code Generator
# -----------------------
def generate_qr(data, filename=None):
    if not filename:
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
    return filename

# -----------------------
# Avatar Display (OpenCV)
# -----------------------
def show_avatar():
    if not os.path.exists(AVATAR_IMAGE):
        print("Avatar image not found. Please add your avatar.png in the folder.")
        return
    img = cv2.imread(AVATAR_IMAGE)
    cv2.imshow("David AI", img)
    cv2.waitKey(1)  # Required to refresh the window

# -----------------------
# Keyboard Listener Thread
# -----------------------
def listen_keyboard():
    print("Keyboard listener started. Press ESC to exit.")
    while True:
        try:
            if keyboard.is_pressed('esc'):
                print("Exiting...")
                os._exit(0)
            # Add custom key interactions here
        except:
            pass
        time.sleep(0.05)

# -----------------------
# Main Loop
# -----------------------
def main():
    # Start keyboard listener in a thread
    threading.Thread(target=listen_keyboard, daemon=True).start()

    speak("Hello! I am David, ready to assist you.")

    while True:
        show_avatar()
        # Example QR code generation
        qr_file = generate_qr("David AI Operational")
        print(f"Generated QR code: {qr_file}")
        speak("QR code updated.")
        time.sleep(10)  # Rotate QR code every 10 seconds

if __name__ == "__main__":
    main()

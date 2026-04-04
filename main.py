# main.py - David AI Minimal (Siri-style dot)

import threading
import time
import pyttsx3
import keyboard

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
# Main Loop
# -----------------------
def main():
    threading.Thread(target=listen_keyboard, daemon=True).start()

    speak("Hello! I am David, ready to assist you.")

    while True:
        # Minimal dot-style interaction (just voice)
        user_input = input("You: ")
        if user_input.strip() != "":
            response = f"You said: {user_input}"
            print("David: " + response)
            speak(response)

if __name__ == "__main__":
    main()

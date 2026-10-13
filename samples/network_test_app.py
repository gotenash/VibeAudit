import urllib.request
import time
import socket

print("Test app running: connecting to github.com...")
try:
    req = urllib.request.Request(
        "https://api.github.com/zen",
        headers={"User-Agent": "VibeAuditTest"}
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        content = response.read().decode()
        print(f"Response from GitHub: {content.strip()}")
except Exception as e:
    print(f"Error during request: {e}")

time.sleep(2)
print("Test app finished.")

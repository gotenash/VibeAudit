"""
Helper utilities for port binding and fullscreen app launching.
"""
import os
import sys
import time
import socket
import threading
import subprocess
import tempfile
import webbrowser

PORT = 5173

def find_available_port(start_port: int = PORT, max_attempts: int = 15) -> int:
    for p in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", p))
                return p
        except OSError:
            continue
    return start_port

def _get_browser_candidates() -> list:
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
    ]
    try:
        import winreg
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for app_key in [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe"
            ]:
                try:
                    with winreg.OpenKey(root, app_key) as k:
                        val, _ = winreg.QueryValueEx(k, "")
                        if val and val not in candidates:
                            candidates.insert(0, val)
                except (OSError, FileNotFoundError):
                    pass
    except (ImportError, AttributeError):
        pass
    return candidates

def launch_fullscreen_app(url: str) -> bool:
    """
    Lance l'application dans une fenetre autonome plein ecran / maximisee.
    Utilise le mode Application (--app) de Chrome/Edge pour masquer la barre d'adresse
    et les onglets, donnant une vraie experience d'application de bureau native.
    """
    browser_exe = next((p for p in _get_browser_candidates() if os.path.isfile(p)), None)
    if browser_exe:
        try:
            profile_dir = os.path.join(tempfile.gettempdir(), "vibe_audit_profile")
            cmd = [
                browser_exe,
                f"--app={url}",
                "--start-maximized",
                f"--user-data-dir={profile_dir}",
                "--no-first-run",
                "--no-default-browser-check"
            ]
            proc = subprocess.Popen(cmd)

            def _watch_exit():
                proc.wait()
                time.sleep(0.4)
                os._exit(0)

            threading.Thread(target=_watch_exit, daemon=True).start()
            return True
        except (subprocess.SubprocessError, OSError):
            pass

    try:
        webbrowser.open(url)
        return True
    except (webbrowser.Error, OSError):
        return False

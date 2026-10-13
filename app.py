"""
Vibe Audit Web Application Server.
Provides REST API endpoints and serves the modern interactive dashboard.
"""
import os
import sys
import io
import json
import urllib.parse
import threading
import time
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import psutil

# Sécurisation en mode fenêtré sans console (--noconsole / GUI)
if sys.stdout is None:
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()

# Add current directory to path (PyInstaller onedir & onefile safe)
def get_base_dir():
    if getattr(sys, "frozen", False):
        if hasattr(sys, "_MEIPASS"):
            meipass = Path(sys._MEIPASS)
            if (meipass / "static").exists():
                return meipass
        exe_dir = Path(sys.executable).parent
        if (exe_dir / "static").exists():
            return exe_dir
        if (exe_dir / "_internal" / "static").exists():
            return exe_dir / "_internal"
        if hasattr(sys, "_MEIPASS"):
            return Path(sys._MEIPASS)
        return exe_dir
    return Path(__file__).resolve().parent

BASE_DIR = get_base_dir()
sys.path.insert(0, str(BASE_DIR))

from engine.rules import get_all_rules_metadata, ALL_RULES
from engine.scanner import Scanner
from engine.report_generator import ReportGenerator
from engine.tech_detector import TechDetector
from engine.dynamic_network_audit import DynamicNetworkAuditor, extract_static_domains
from engine.launcher import launch_fullscreen_app, find_available_port

PORT = 5173

# Dynamic Network Audit Global State
active_dynamic_auditor = None
dynamic_audit_state = {
    "is_running": False,
    "start_time": None,
    "timeout": 0,
    "static_urls": [],
    "last_report": None
}
dynamic_lock = threading.Lock()

class VibeAuditHandler(BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _serve_static(self, path: str):
        if path == "/" or path == "":
            file_to_serve = BASE_DIR / "static" / "index.html"
        else:
            rel_file = path.lstrip("/")
            file_to_serve = (BASE_DIR / "static" / rel_file).resolve()
            if not str(file_to_serve).startswith(str((BASE_DIR / "static").resolve())):
                self.send_error(403, "Access denied")
                return

        if not file_to_serve.exists() or not file_to_serve.is_file():
            self.send_error(404, f"Fichier introuvable: {path}")
            return

        content_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".ico": "image/x-icon",
        }
        suffix = file_to_serve.suffix.lower()
        content_type = content_types.get(suffix, "text/plain")

        content = file_to_serve.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _handle_api_get(self, path: str):
        if path == "/api/tests":
            self.send_json({"tests": get_all_rules_metadata()})
        elif path == "/api/samples":
            self.send_json({"samples": [
                {
                    "id": "chaos_saas",
                    "name": "🔥 Vibe Chaos SaaS (Prototype Vibe-Coded)",
                    "description": "Comprend tous les pièges classiques : clés OpenAI hardcodées, failles SQL, eval(), dépendances fantômes et .env exposé.",
                    "path": str(BASE_DIR / "samples" / "vibe_chaos_saas")
                },
                {
                    "id": "hardened_app",
                    "name": "🛡️ Hardened Production App (Qualité & Rigueur)",
                    "description": "Architecture propre, secrets en variables d'environnement, requêtes préparées, tests unitaires et .gitignore rigoureux.",
                    "path": str(BASE_DIR / "samples" / "hardened_app")
                }
            ]})
        elif path == "/api/dynamic/processes":
            self._handle_dynamic_processes()
        elif path == "/api/dynamic/status":
            self._handle_dynamic_status()
        else:
            self.send_error(404, "Endpoint introuvable")

    def _handle_dynamic_processes(self):
        procs = []
        skip_prefixes = ("svchost", "system", "idle", "conhost", "registry", "smss", "csrss", "wininit", "services", "lsass")
        try:
            for p in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    name = p.info["name"] or ""
                    if name.lower().endswith(".exe") and not name.lower().startswith(skip_prefixes):
                        procs.append({"pid": p.info["pid"], "name": name, "exe": p.info["exe"] or ""})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.Error, OSError):
            pass
        procs.sort(key=lambda x: (0 if "openpeek" in x["name"].lower() else 1, x["name"].lower()))
        self.send_json({"processes": procs[:40]})

    def _handle_dynamic_status(self):
        with dynamic_lock:
            auditor = active_dynamic_auditor
            st = dict(dynamic_audit_state)

        if auditor:
            report = auditor.generate_report()
            report["static_detected_urls"] = st.get("static_urls", [])
            elapsed = time.time() - st["start_time"] if st.get("start_time") else 0
            self.send_json({
                "is_running": auditor.is_running,
                "elapsed": round(elapsed, 1),
                "timeout": st.get("timeout", 0),
                "report": report,
                "timeline": auditor.timeline[-60:]
            })
        else:
            self.send_json({
                "is_running": False,
                "elapsed": 0,
                "timeout": 0,
                "report": st.get("last_report"),
                "timeline": []
            })

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            return self._handle_api_get(path)
        self._serve_static(path)

    def _read_json_payload(self):
        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len) if content_len > 0 else b""
        if not post_data:
            return {}
        try:
            return json.loads(post_data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json({"error": "Format JSON invalide"}, status=400)
            return None

    def _handle_audit_post(self, payload: dict):
        target_path = payload.get("target_path", "").strip()
        enabled_rules = payload.get("enabled_rules", None)
        rule_configs = payload.get("rule_configs", {})

        if not target_path:
            self.send_json({"error": "Veuillez spécifier un chemin de projet à auditer."}, status=400)
            return

        try:
            scanner = Scanner(target_path)
            context = scanner.build_context()
            results = scanner.run_audit(enabled_rule_ids=enabled_rules, rule_configs=rule_configs)
            tech_stack = TechDetector.detect(context)
            report = ReportGenerator.generate(
                results=results,
                target_dir=str(scanner.target_dir),
                total_files=len(context.code_files),
                total_lines=context.total_lines,
                tech_stack=tech_stack
            )
            self.send_json(report)
        except Exception as e:
            self.send_json({"error": f"Erreur pendant l'analyse : {str(e)}"}, status=500)

    def _handle_export_post(self, payload: dict):
        report_data = payload.get("report")
        if not report_data:
            self.send_json({"error": "Aucune donnée de rapport reçue"}, status=400)
            return
        markdown_content = ReportGenerator.to_markdown(report_data)
        self.send_json({"markdown": markdown_content})

    def _handle_dynamic_start_post(self, payload: dict):
        global active_dynamic_auditor, dynamic_audit_state
        exe_path = payload.get("exe_path", "").strip() or None
        target_pid = payload.get("pid", None)
        if target_pid is not None:
            try:
                target_pid = int(target_pid)
            except (ValueError, TypeError):
                target_pid = None
        timeout = int(payload.get("timeout", 15))
        args_str = payload.get("args", "")
        custom_args = args_str.split() if args_str else []

        if not exe_path and not target_pid:
            self.send_json({"error": "Veuillez spécifier un exécutable ou un PID valide."}, status=400)
            return
        if exe_path and not os.path.isfile(exe_path):
            self.send_json({"error": f"L'exécutable '{exe_path}' est introuvable sur le disque."}, status=400)
            return

        with dynamic_lock:
            if active_dynamic_auditor and active_dynamic_auditor.is_running:
                active_dynamic_auditor.stop()

            static_urls = extract_static_domains(exe_path) if exe_path else []
            try:
                auditor = DynamicNetworkAuditor(exe_path=exe_path, pid=target_pid, args=custom_args)
                auditor.start()
                active_dynamic_auditor = auditor
                dynamic_audit_state.update({
                    "is_running": True,
                    "start_time": time.time(),
                    "timeout": timeout,
                    "static_urls": static_urls,
                    "last_report": None
                })
            except Exception as e:
                self.send_json({"error": f"Impossible de démarrer l'audit : {str(e)}"}, status=500)
                return

        if timeout > 0:
            def auto_stop():
                time.sleep(timeout)
                with dynamic_lock:
                    if active_dynamic_auditor == auditor and auditor.is_running:
                        auditor.stop()
                        dynamic_audit_state["is_running"] = False
                        rep = auditor.generate_report()
                        rep["static_detected_urls"] = dynamic_audit_state["static_urls"]
                        dynamic_audit_state["last_report"] = rep
            threading.Thread(target=auto_stop, daemon=True).start()

        proc_name = "Unknown"
        try:
            if auditor.target_process:
                proc_name = auditor.target_process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass

        self.send_json({
            "status": "started",
            "pid": auditor.target_process.pid if auditor.target_process else target_pid,
            "process_name": proc_name,
            "timeout": timeout,
            "static_urls_count": len(static_urls)
        })

    def _handle_dynamic_stop_post(self):
        global active_dynamic_auditor, dynamic_audit_state
        with dynamic_lock:
            auditor = active_dynamic_auditor
            if auditor and auditor.is_running:
                auditor.stop()
                dynamic_audit_state["is_running"] = False
                rep = auditor.generate_report()
                rep["static_detected_urls"] = dynamic_audit_state.get("static_urls", [])
                dynamic_audit_state["last_report"] = rep
                self.send_json({"status": "stopped", "report": rep})
            elif dynamic_audit_state.get("last_report"):
                self.send_json({"status": "already_stopped", "report": dynamic_audit_state["last_report"]})
            else:
                self.send_json({"status": "no_active_audit", "report": None})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        payload = self._read_json_payload()
        if payload is None:
            return

        if path == "/api/audit":
            return self._handle_audit_post(payload)
        elif path == "/api/export":
            return self._handle_export_post(payload)
        elif path == "/api/dynamic/start":
            return self._handle_dynamic_start_post(payload)
        elif path == "/api/dynamic/stop":
            return self._handle_dynamic_stop_post()
        elif path == "/api/shutdown":
            self.send_json({"status": "shutting_down"})
            threading.Thread(target=lambda: (time.sleep(0.3), os._exit(0)), daemon=True).start()
            return

        self.send_error(404, "Endpoint introuvable")

def run_server(port=None, open_browser=True):
    # Configure utf-8 stdout on Windows if possible
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, io.UnsupportedOperation, OSError):
            pass

    actual_port = find_available_port(PORT if port is None else port)
    server = ThreadingHTTPServer(("0.0.0.0", actual_port), VibeAuditHandler)
    url = f"http://localhost:{actual_port}"

    print("==================================================")
    print(f"[+] VIBE AUDIT Web App is running at:")
    print(f"    {url}")
    print("==================================================")

    if open_browser:
        def _open():
            time.sleep(0.6)
            launch_fullscreen_app(url)
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArret du serveur...")
if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()

    auto_open = "--no-browser" not in sys.argv
    try:
        run_server(open_browser=auto_open)
    except Exception as e:
        import tempfile
        import traceback
        try:
            with open(os.path.join(tempfile.gettempdir(), "vibe_audit_crash.log"), "w", encoding="utf-8") as f:
                f.write(traceback.format_exc())
        except OSError:
            pass

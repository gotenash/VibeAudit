import os
import sys
import time
import socket
import threading
import subprocess
import json
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import io
import psutil

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, OSError, io.UnsupportedOperation):
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError, io.UnsupportedOperation):
            pass

KNOWN_SIGNATURES = {
    "telemetry": [
        "telemetry", "analytics", "stats", "metrics", "sentry.io",
        "segment.io", "mixpanel", "doubleclick", "google-analytics",
        "msedge.net", "data.microsoft.com", "vortex.data.microsoft.com",
        "watson.telemetry.microsoft.com"
    ],
    "cloud_ai": [
        "api.openai.com", "anthropic.com", "generativelanguage.googleapis.com",
        "cohere.ai", "mistral.ai", "openrouter.ai", "groq.com", "huggingface.co"
    ],
    "code_distribution": [
        "github.com", "githubusercontent.com", "api.github.com",
        "gitlab.com", "npmjs.org", "pypi.org", "github"
    ],
    "cdn_infrastructure": [
        "cloudflare.com", "cloudfront.net", "fastly.net", "akamaitechnologies.com",
        "azureedge.net", "1e100.net", "google.com", "googleapis.com", "microsoft"
    ]
}

def extract_static_domains(exe_path):
    """Extraction statique des domaines et URLs présents dans les binaires."""
    domains = set()
    try:
        import re
        with open(exe_path, "rb") as f:
            data = f.read()

        pattern = rb"https?://[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,6}(?:/[a-zA-Z0-9\.\-_~%]*)*"
        matches = re.findall(pattern, data)
        for m in matches:
            s = m.decode("latin1", errors="ignore")
            if "." in s and not s.endswith(".") and len(s) < 80 and not s.startswith("http://www.w3.org"):
                domains.add(s)
    except (OSError, UnicodeDecodeError):
        pass
    return sorted(list(domains))

def is_private_ip(ip):
    """Vérifie si une adresse IP est privée ou locale."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 0:
            return True
    except (ValueError, IndexError):
        pass
    return False

def classify_target(host_or_ip, org="", asname=""):
    """Classifie une destination réseau selon les signatures connues."""
    search_str = f"{host_or_ip} {org} {asname}".lower()
    for category, signatures in KNOWN_SIGNATURES.items():
        for sig in signatures:
            if sig in search_str:
                return category
    return "unknown_external"


class DynamicNetworkAuditor:
    """
    Moteur d'analyse dynamique des flux réseau pour exécutables Windows (.exe).
    Surveille le processus cible et l'ensemble de son arbre de processus enfants (ex: WebView2, helper tools).
    """

    def __init__(self, exe_path=None, pid=None, args=None, cwd=None, poll_interval=0.05):
        self.exe_path = os.path.abspath(exe_path) if exe_path else None
        self.target_pid = pid
        self.args = args or []
        self.cwd = cwd or os.getcwd()
        self.poll_interval = poll_interval
        self.is_running = False
        self.target_process = None
        self.monitored_pids = set()
        
        # Enregistrement des événements réseau
        self.connections = {}
        self.dns_cache = {}
        self.ip_meta_cache = {}
        self.timeline = []
        self.io_stats = {}
        self.resolver_pool = ThreadPoolExecutor(max_workers=8)
        self._lock = threading.Lock()

    def _enrich_ip(self, ip):
        """Résolution DNS inverse et enrichissement ASN / Organisation."""
        if ip in self.ip_meta_cache:
            return self.ip_meta_cache[ip]

        if is_private_ip(ip):
            res = {"hostname": "localhost/lan", "org": "LAN", "country": "Local", "asname": ""}
            self.ip_meta_cache[ip] = res
            return res

        hostname = ip
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            hostname = name
        except (socket.herror, socket.gaierror, OSError):
            pass

        org = ""
        country = ""
        asname = ""

        # Requête d'enrichissement IP via service public léger
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,org,asname"
            req = urllib.request.Request(url, headers={"User-Agent": "VibeAudit/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    org = data.get("org", "")
                    country = data.get("country", "")
                    asname = data.get("asname", "")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            pass

        cat = classify_target(hostname, org=org, asname=asname)

        meta = {
            "hostname": hostname,
            "org": org,
            "country": country,
            "asname": asname,
            "category": cat
        }
        self.ip_meta_cache[ip] = meta
        return meta

    def _track_process_tree(self):
        """Récupère récursivement tous les PIDs de l'arbre de processus."""
        if not self.target_process:
            return set()

        pids = set()
        try:
            if self.target_process.is_running():
                pids.add(self.target_process.pid)
                for child in self.target_process.children(recursive=True):
                    try:
                        if child.is_running():
                            pids.add(child.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        with self._lock:
            self.monitored_pids = pids
        return pids

    def _update_process_io(self, proc, pid: int, proc_name: str):
        try:
            io = proc.io_counters()
            self.io_stats[pid] = {
                "name": proc_name,
                "read_bytes": io.read_bytes,
                "write_bytes": io.write_bytes
            }
        except (psutil.Error, OSError, AttributeError):
            pass

    def _inspect_connection(self, pid: int, proc_name: str, conn):
        if not conn.raddr:
            return

        r_ip, r_port = conn.raddr.ip, conn.raddr.port
        if is_private_ip(r_ip):
            return

        conn_key = (pid, conn.laddr.ip, conn.laddr.port, r_ip, r_port, conn.type)

        with self._lock:
            now = datetime.now()
            if conn_key in self.connections:
                self.connections[conn_key]["last_seen"] = now.strftime("%H:%M:%S.%f")[:-3]
                self.connections[conn_key]["status"] = conn.status
                return

            event = {
                "first_seen": now.strftime("%H:%M:%S.%f")[:-3],
                "last_seen": now.strftime("%H:%M:%S.%f")[:-3],
                "pid": pid,
                "process_name": proc_name,
                "proto": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote_ip": r_ip,
                "remote_port": r_port,
                "status": conn.status,
                "hostname": r_ip,
                "org": "En cours...",
                "country": "",
                "asname": "",
                "category": "pending"
            }
            self.connections[conn_key] = event
            self.timeline.append(dict(event))

            def async_lookup(k=conn_key, ip=r_ip):
                info = self._enrich_ip(ip)
                with self._lock:
                    if k in self.connections:
                        self.connections[k].update(info)

            self.resolver_pool.submit(async_lookup)

    def _poll_connections(self):
        """Boucle de polling à haute fréquence pour capturer les connexions actives."""
        while self.is_running:
            pids = self._track_process_tree()
            if not pids:
                break

            for pid in list(pids):
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                    self._update_process_io(proc, pid, proc_name)
                    for conn in proc.net_connections(kind="inet"):
                        self._inspect_connection(pid, proc_name, conn)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            time.sleep(self.poll_interval)

    def start(self):
        """Lance l'exécutable cible ou s'attache à un PID existant, et démarre la surveillance."""
        if self.target_pid:
            try:
                self.target_process = psutil.Process(self.target_pid)
                if not self.exe_path:
                    self.exe_path = self.target_process.exe()
                print(f"\n[VIBE AUDIT] Connexion au processus existant PID: {self.target_pid} ({self.target_process.name()})")
                print(f"[VIBE AUDIT] Cible: {self.exe_path}")
            except psutil.NoSuchProcess:
                raise ValueError(f"Aucun processus avec le PID {self.target_pid} n'a été trouvé.")
        else:
            if not self.exe_path or not os.path.isfile(self.exe_path):
                raise FileNotFoundError(f"L'exécutable '{self.exe_path}' est introuvable.")

            cmd = [self.exe_path] + self.args
            print(f"\n[VIBE AUDIT] Démarrage de l'analyse dynamique...")
            print(f"[VIBE AUDIT] Cible: {self.exe_path}")
            print(f"[VIBE AUDIT] Lancement du processus en cours...")

            proc_sub = subprocess.Popen(cmd, cwd=self.cwd)
            self.target_process = psutil.Process(proc_sub.pid)
            print(f"[VIBE AUDIT] Processus initial lancé avec PID: {self.target_process.pid}")

        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._poll_connections, daemon=True)
        self.monitor_thread.start()
        print(f"[VIBE AUDIT] Surveillance active (arbre des processus & sockets distants).")

    def stop(self):
        """Arrête la surveillance et attend la fin des résolutions."""
        self.is_running = False
        if hasattr(self, "monitor_thread"):
            self.monitor_thread.join(timeout=2.0)
        self.resolver_pool.shutdown(wait=True)

    def wait_or_interactive(self, timeout=None):
        """Attend la fin du processus ou un timeout tout en affichant les flux en direct."""
        print("[INFO] L'application est en cours d'exécution.")
        print("[INFO] Vous pouvez interagir avec l'application (clics, navigation, options).")
        print("[INFO] Les connexions sortantes détectées s'affichent ci-dessous en temps réel.\n")

        displayed_conns = set()
        start_time = time.time()

        try:
            while self.target_process and self.target_process.is_running():
                if timeout and (time.time() - start_time) > timeout:
                    print(f"\n[INFO] Timeout de {timeout}s atteint.")
                    break

                with self._lock:
                    for k, conn in list(self.connections.items()):
                        if k not in displayed_conns:
                            displayed_conns.add(k)
                            host = conn.get("hostname", conn["remote_ip"])
                            org_info = f" ({conn.get('org')})" if conn.get('org') and conn.get('org') != "En cours..." else ""
                            print(f"  ⚡ [{conn['first_seen']}] [{conn['process_name']} PID:{conn['pid']}] -> {conn['proto']} {conn['remote_ip']}:{conn['remote_port']} -> {host}{org_info} [{conn['status']}]")

                time.sleep(0.2)

        except KeyboardInterrupt:
            print("\n[INFO] Arrêt demandé par l'utilisateur.")

        self.stop()

    def generate_report(self):
        """Génère une synthèse complète d'audit réseau."""
        unique_targets = {}
        total_connections = len(self.connections)
        categories_count = {}

        for conn in self.connections.values():
            ip = conn["remote_ip"]
            info = self.ip_meta_cache.get(ip, {})
            host = info.get("hostname", conn.get("hostname", ip))
            org = info.get("org", conn.get("org", ""))
            country = info.get("country", conn.get("country", ""))
            cat = info.get("category", classify_target(host, org=org))

            categories_count[cat] = categories_count.get(cat, 0) + 1

            key = (ip, conn["remote_port"], conn["process_name"])
            if key not in unique_targets:
                unique_targets[key] = {
                    "ip": ip,
                    "port": conn["remote_port"],
                    "process_name": conn["process_name"],
                    "hostname": host,
                    "org": org,
                    "country": country,
                    "category": cat,
                    "protocol": conn["proto"],
                    "first_seen": conn["first_seen"],
                    "last_seen": conn["last_seen"]
                }

        has_telemetry = categories_count.get("telemetry", 0) > 0
        has_unknown = categories_count.get("unknown_external", 0) > 0
        is_offline = total_connections == 0

        if is_offline:
            verdict = "VERIFIED_OFFLINE"
            verdict_desc = "Aucun flux réseau sortant détecté. L'application respecte un fonctionnement 100% local."
            score_vibe = 100
        elif has_unknown:
            verdict = "EXTERNAL_UNVERIFIED_TRAFFIC"
            verdict_desc = "L'application contacte des serveurs tiers ou adresses IP non catégorisés."
            score_vibe = 65
        elif has_telemetry:
            verdict = "TELEMETRY_DETECTED"
            verdict_desc = "L'application émet de la télémétrie ou des métriques vers des services cloud connus."
            score_vibe = 80
        else:
            verdict = "STANDARD_ONLINE_TRAFFIC"
            verdict_desc = "Trafic réseau sortant standard vers des infrastructures identifiées."
            score_vibe = 90

        return {
            "exe_path": self.exe_path,
            "audit_timestamp": datetime.now().isoformat(),
            "total_connections": total_connections,
            "unique_destinations": list(unique_targets.values()),
            "categories_summary": categories_count,
            "verdict": verdict,
            "verdict_description": verdict_desc,
            "score": score_vibe,
            "processes_monitored": list(self.io_stats.values())
        }

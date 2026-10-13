import ast
import re
import sys
import io
import urllib.request
import urllib.error

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, io.UnsupportedOperation, OSError):
        pass

# 1. Signatures et pondération des risques
SEVERITY_WEIGHTS = {"CRITIQUE": 30, "ÉLEVÉ": 15, "MOYEN": 5, "INFO": 1}

SECRET_RULES = [
    (r"(?i)(api[_-]?key|secret|token|passwd|password)\s*=\s*['\"][a-zA-Z0-9_\-\.]{12,}['\"]", 
     "CRITIQUE", "Secret ou jeton d'authentification codé en dur"),
    (r"ghp_[a-zA-Z0-9]{36}", "CRITIQUE", "Jeton d'accès personnel GitHub (PAT)"),
    (r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----", "CRITIQUE", "Clé privée RSA/SSH exposée")
]

SUSPICIOUS_DOMAINS = ["webhook.site", "ngrok.io", "requestcatcher.com", "pastebin.com"]

class DiagnosticEngine(ast.NodeVisitor):
    def __init__(self, raw_code):
        self.findings = []
        self.raw_code = raw_code.splitlines()

    def add_issue(self, level, title, lineno, detail, recommendation):
        code_snippet = self.raw_code[lineno - 1].strip() if 0 < lineno <= len(self.raw_code) else ""
        self.findings.append({
            "level": level,
            "title": title,
            "line": lineno,
            "snippet": code_snippet,
            "detail": detail,
            "fix": recommendation
        })

    def visit_Call(self, node):
        # Évaluation dynamique
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self.add_issue(
                "CRITIQUE", "Exécution dynamique de code", node.lineno,
                f"L'appel à `{node.func.id}()` permet d'exécuter des chaînes arbitraires sans validation.",
                "Remplacer par un parseur strict (ex: `ast.literal_eval` ou `json.loads`)."
            )

        # Appels système / Shell
        elif isinstance(node.func, ast.Attribute):
            if getattr(node.func.value, "id", None) == "os" and node.func.attr in ("system", "popen"):
                self.add_issue(
                    "ÉLEVÉ", "Exécution de commande shell système", node.lineno,
                    f"L'appel `os.{node.func.attr}()` contourne les protections du runtime.",
                    "Privilégier l'API native de Python ou `subprocess.run(..., shell=False)`."
                )
            
            # Détection d'exfiltration réseau
            elif getattr(node.func.value, "id", None) in ("requests", "httpx", "urllib"):
                self.add_issue(
                    "MOYEN", "Appel réseau externe sortant", node.lineno,
                    f"Requête HTTP via `{node.func.value.id}.{node.func.attr}`.",
                    "Vérifier si le domaine cible est attendu et légitime."
                )

        self.generic_visit(node)

    def visit_Constant(self, node):
        # Analyse des chaînes pour détecter des URL / IP suspectes
        if isinstance(node.value, str):
            for domain in SUSPICIOUS_DOMAINS:
                if domain in node.value:
                    self.add_issue(
                        "CRITIQUE", "Point de terminaison suspect (exfiltration potentielle)", node.lineno,
                        f"URL pointant vers un service de relais temporaire : `{node.value}`.",
                        "Supprimer immédiatement l'URL et vérifier l'intention du script."
                    )
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self._check_pkg(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self._check_pkg(node.module.split(".")[0], node.lineno)
        self.generic_visit(node)

    def _check_pkg(self, pkg, lineno):
        if pkg in sys.stdlib_module_names:
            return
        url = f"https://pypi.org/pypi/{pkg}/json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VibeAudit/1.0"}, method="HEAD")
            with urllib.request.urlopen(req, timeout=1.5):
                pass
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.add_issue(
                    "CRITIQUE", "Package potentiellement halluciné / Typo-squatting", lineno,
                    f"Le package `{pkg}` n'existe pas sur le registre officiel PyPI.",
                    "Ne pas exécuter `pip install` ; vérifier si le modèle n'a pas inventé le module."
                )
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

def audit_code(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        code = f.read()

    engine = DiagnosticEngine(code)

    # Scan des secrets (en ignorant les mocks et suites synthétiques)
    mock_keywords = ["mock", "dummy", "fake", "example", "sample", "fixture", "placeholder", "test"]
    for pattern, level, desc in SECRET_RULES:
        for m in re.finditer(pattern, code):
            lineno = code[:m.start()].count("\n") + 1
            line_str = engine.raw_code[lineno - 1] if 0 < lineno <= len(engine.raw_code) else ""
            if any(k in line_str.lower() for k in mock_keywords):
                continue
            matched_val = m.group(0)
            engine.add_issue(
                level, desc, lineno,
                f"Valeur trouvée : `{matched_val[:25]}...`",
                "Déplacer cette clé dans un fichier `.env` ou une variable d'environnement."
            )

    # Analyse AST
    try:
        tree = ast.parse(code)
        engine.visit(tree)
    except SyntaxError as err:
        engine.add_issue("CRITIQUE", "Erreur syntaxique bloquante", err.lineno or 1, str(err), "Corriger la syntaxe.")

    # Calcul de la note de sécurité (100 = sain, 0 = compromis)
    total_penalty = sum(SEVERITY_WEIGHTS.get(i["level"], 0) for i in engine.findings)
    safety_score = max(0, 100 - total_penalty)

    # Affichage du diagnostic
    print("\n" + "=" * 60)
    print(f"  DIAGNOSTIC DE SÉCURITÉ : {filepath}")
    print("=" * 60)
    print(f"Indice de confiance : {safety_score}/100")
    print(f"Anomalies relevées  : {len(engine.findings)}\n")

    if not engine.findings:
        print("[OK] Aucun signal de compromission ou de fuite identifié.\n")
        return

    for item in engine.findings:
        badge = f"[{item['level']}]"
        print(f"{badge:<11} Ligne {item['line']} : {item['title']}")
        if item["snippet"]:
            print(f"            Extrait : `{item['snippet']}`")
        print(f"            Détail  : {item['detail']}")
        print(f"            Action  : {item['fix']}\n")

def audit_project(dirpath: str):
    from engine.scanner import Scanner
    from engine.report_generator import ReportGenerator
    from engine.tech_detector import TechDetector

    scanner = Scanner(dirpath)
    context = scanner.build_context()
    results = scanner.run_audit()
    tech_stack = TechDetector.detect(context)
    report = ReportGenerator.generate(
        results=results,
        target_dir=str(scanner.target_dir),
        total_files=len(context.code_files),
        total_lines=context.total_lines,
        tech_stack=tech_stack
    )
    md = ReportGenerator.to_markdown(report)
    print(md)

if __name__ == "__main__":
    import os
    if len(sys.argv) < 2:
        print("Usage: python vibe_audit.py <fichier.py | dossier_projet>")
        sys.exit(1)
    target = sys.argv[1]
    if os.path.isdir(target):
        audit_project(target)
    else:
        audit_code(target)
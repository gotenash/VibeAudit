"""
Rule: Detect ghost / hallucinated dependencies and missing package declarations.
"""
import ast
import re
import json
from typing import Set, Dict, List
from .base import BaseAuditRule, RuleResult, Finding, Category, Severity

# Standard library modules in Python (to exclude from ghost dependency detection)
PY_STDLIB = {
    "os", "sys", "re", "json", "time", "datetime", "math", "random", "typing",
    "collections", "itertools", "functools", "pathlib", "subprocess", "logging",
    "urllib", "http", "socket", "threading", "asyncio", "multiprocessing",
    "dataclasses", "enum", "hashlib", "hmac", "base64", "uuid", "shutil", "tempfile",
    "glob", "io", "csv", "sqlite3", "unittest", "traceback", "copy", "contextlib",
    "queue", "signal", "platform", "argparse", "optparse", "warnings", "inspect",
    "ast", "dis", "tokenize", "pickle", "shelve", "xml", "html", "email"
}

# Suspicious / hallucinated library patterns often invented by LLMs
HALLUCINATED_SUSPECTS = {
    "langchain_super", "openai_chat_pro", "python-gemini-client", "easy_gpt4",
    "chatgpt_wrapper_unofficial", "auto_fastapi", "super_react"
}

class GhostDependenciesRule(BaseAuditRule):
    rule_id = "vibe_ghost_deps"
    name = "Dépendances Fantômes & Hallucinations IA"
    category = Category.GHOST_DEPS
    default_severity = Severity.HIGH
    description = "Repère les bibliothèques importées absentes de requirements.txt/package.json, ou les packages inventés par le LLM."
    enabled_by_default = True

    def _parse_declared_deps(self, context) -> tuple:
        declared_python_deps: Set[str] = set()
        declared_js_deps: Set[str] = set()

        if "requirements.txt" in context.root_files:
            for line in (context.read_file("requirements.txt") or "").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    pkg_name = re.split(r"[=><~]", line)[0].strip().lower().replace("-", "_")
                    if pkg_name:
                        declared_python_deps.add(pkg_name)

        if "package.json" in context.root_files:
            try:
                pkg_data = json.loads(context.read_file("package.json") or "{}")
                for k in list(pkg_data.get("dependencies", {}).keys()) + list(pkg_data.get("devDependencies", {}).keys()):
                    declared_js_deps.add(k.lower())
            except (json.JSONDecodeError, AttributeError):
                pass

        return declared_python_deps, declared_js_deps

    def _collect_python_imports(self, context, result) -> Dict[str, List[tuple]]:
        all_imported_python_modules: Dict[str, List[tuple]] = {}
        for file_info in context.code_files:
            result.files_scanned += 1
            if file_info.is_vendor or file_info.extension != ".py":
                continue
            try:
                tree = ast.parse(file_info.content, filename=file_info.rel_path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_mod = alias.name.split(".")[0].lower()
                        all_imported_python_modules.setdefault(top_mod, []).append((file_info.rel_path, node.lineno))
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top_mod = node.module.split(".")[0].lower()
                    all_imported_python_modules.setdefault(top_mod, []).append((file_info.rel_path, node.lineno))
        return all_imported_python_modules

    def _check_python_ghost_modules(self, result, all_imported_python_modules, declared_python_deps, has_python_manifest, local_py_modules):
        known_mappings = {
            "pil": "pillow", "cv2": "opencv_python", "dotenv": "python_dotenv",
            "yaml": "pyyaml", "bs4": "beautifulsoup4", "google": "google_api_python_client",
            "jwt": "pyjwt", "sklearn": "scikit_learn"
        }

        for mod, locations in all_imported_python_modules.items():
            if mod in PY_STDLIB or mod in local_py_modules or mod.startswith("_"):
                continue

            file_p, line_n = locations[0]
            if mod in HALLUCINATED_SUSPECTS:
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    file_path=file_p,
                    line_number=line_n,
                    message=f"Bibliothèque potentiellement hallucinée : '{mod}' semble inexistante sur PyPI",
                    code_snippet=f"import {mod}",
                    ai_rationale="Les LLM inventent parfois des noms de librairies plausibles quand ils n'ont pas la référence exacte.",
                    fix_recommendation=f"Vérifiez l'existence de '{mod}' sur pypi.org ou utilisez la bibliothèque officielle."
                ))
                continue

            if has_python_manifest:
                norm_mod = mod.replace("-", "_")
                mapped_name = known_mappings.get(norm_mod, norm_mod)
                if norm_mod not in declared_python_deps and mapped_name not in declared_python_deps:
                    result.findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        file_path=file_p,
                        line_number=line_n,
                        message=f"Dépendance importée non déclarée : '{mod}' est absent de requirements.txt",
                        code_snippet=f"import {mod}",
                        ai_rationale="L'IA génère du code utilisant une librairie externe sans mettre à jour les manifestes de packaging.",
                        fix_recommendation=f"Ajoutez '{mod}' dans requirements.txt ou installez-le avec pip."
                    ))

    def _check_unused_python_deps(self, result, declared_python_deps, all_imported_python_modules, has_python_manifest):
        if not has_python_manifest or len(declared_python_deps) == 0:
            return

        tool_pkgs = {"pip", "setuptools", "wheel", "pytest", "black", "flake8", "mypy"}
        reverse_mappings = {"pillow": "pil", "opencv_python": "cv2", "python_dotenv": "dotenv"}

        for dep in declared_python_deps:
            if dep in tool_pkgs:
                continue
            dep_norm = dep.replace("-", "_")
            check_mod = reverse_mappings.get(dep_norm, dep_norm)
            if check_mod not in all_imported_python_modules and dep_norm not in all_imported_python_modules:
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.LOW,
                    file_path="requirements.txt",
                    line_number=1,
                    message=f"Dépendance déclarée probablement inutilisée (Bloat) : '{dep}'",
                    code_snippet=dep,
                    ai_rationale="L'IA recommande souvent des listes de packages génériques 'au cas où' sans qu'ils soient utilisés.",
                    fix_recommendation=f"Supprimez '{dep}' si votre projet n'en a pas besoin pour réduire la taille des builds Docker."
                ))

    def scan(self, context) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
        )

        declared_python_deps, _ = self._parse_declared_deps(context)
        all_imported_python_modules = self._collect_python_imports(context, result)

        has_python_manifest = "requirements.txt" in context.root_files or "pyproject.toml" in context.root_files
        local_py_modules = {f.filename.replace(".py", "").lower() for f in context.code_files if f.extension == ".py"}

        self._check_python_ghost_modules(result, all_imported_python_modules, declared_python_deps, has_python_manifest, local_py_modules)
        self._check_unused_python_deps(result, declared_python_deps, all_imported_python_modules, has_python_manifest)

        result.passed = len(result.findings) == 0
        return result

"""
Module: Technology and Language Detector for Vibe Audit.
Analyzes code files, manifests, configuration files, and AST/imports
to automatically identify languages, frameworks, libraries, and tooling.
"""
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Set, Optional

# Extension to language mappings with official brand colors
LANGUAGE_SPECS = {
    ".py": {"name": "Python", "color": "#3572A5", "is_code": True},
    ".js": {"name": "JavaScript", "color": "#F7DF1E", "is_code": True},
    ".mjs": {"name": "JavaScript", "color": "#F7DF1E", "is_code": True},
    ".cjs": {"name": "JavaScript", "color": "#F7DF1E", "is_code": True},
    ".jsx": {"name": "React JSX", "color": "#61DAFB", "is_code": True},
    ".ts": {"name": "TypeScript", "color": "#3178C6", "is_code": True},
    ".tsx": {"name": "React TSX", "color": "#3178C6", "is_code": True},
    ".html": {"name": "HTML", "color": "#E34F26", "is_code": True},
    ".htm": {"name": "HTML", "color": "#E34F26", "is_code": True},
    ".css": {"name": "CSS", "color": "#563D7C", "is_code": True},
    ".scss": {"name": "SCSS", "color": "#C6538C", "is_code": True},
    ".sass": {"name": "Sass", "color": "#A53B70", "is_code": True},
    ".less": {"name": "Less", "color": "#1D365D", "is_code": True},
    ".rs": {"name": "Rust", "color": "#DEA584", "is_code": True},
    ".go": {"name": "Go", "color": "#00ADD8", "is_code": True},
    ".c": {"name": "C", "color": "#555555", "is_code": True},
    ".h": {"name": "C/C++ Header", "color": "#A8B9CC", "is_code": True},
    ".cpp": {"name": "C++", "color": "#F34B7D", "is_code": True},
    ".hpp": {"name": "C++ Header", "color": "#F34B7D", "is_code": True},
    ".cs": {"name": "C#", "color": "#178600", "is_code": True},
    ".java": {"name": "Java", "color": "#B07219", "is_code": True},
    ".php": {"name": "PHP", "color": "#4F5D95", "is_code": True},
    ".rb": {"name": "Ruby", "color": "#701516", "is_code": True},
    ".sh": {"name": "Shell / Bash", "color": "#89E051", "is_code": True},
    ".bash": {"name": "Shell / Bash", "color": "#89E051", "is_code": True},
    ".sql": {"name": "SQL", "color": "#E38C00", "is_code": True},
    ".vue": {"name": "Vue", "color": "#41B883", "is_code": True},
    ".svelte": {"name": "Svelte", "color": "#FF3E00", "is_code": True},
    ".json": {"name": "JSON", "color": "#292929", "is_code": False},
    ".yaml": {"name": "YAML", "color": "#CB171E", "is_code": False},
    ".yml": {"name": "YAML", "color": "#CB171E", "is_code": False},
    ".toml": {"name": "TOML", "color": "#9C4221", "is_code": False},
    ".md": {"name": "Markdown", "color": "#083FA1", "is_code": False},
}

# Catalog of known frameworks, libraries, databases and AI tools
FRAMEWORK_CATALOG = [
    # --- Backend & APIs ---
    {"name": "FastAPI", "category": "Backend / API", "icon": "⚡", "packages": ["fastapi"], "imports": ["fastapi"]},
    {"name": "Flask", "category": "Backend / API", "icon": "🌶️", "packages": ["flask"], "imports": ["flask"]},
    {"name": "Django", "category": "Backend / API", "icon": "🎸", "packages": ["django"], "imports": ["django"]},
    {"name": "Express", "category": "Backend / API", "icon": "🚂", "packages": ["express"], "imports": ["express"]},
    {"name": "NestJS", "category": "Backend / API", "icon": "🦁", "packages": ["@nestjs/core", "@nestjs/common"], "imports": ["@nestjs"]},
    {"name": "Axum", "category": "Backend / API", "icon": "🦀", "packages": ["axum"], "imports": ["axum"]},
    {"name": "Actix Web", "category": "Backend / API", "icon": "🦀", "packages": ["actix-web"], "imports": ["actix_web"]},
    {"name": "Gin", "category": "Backend / API", "icon": "🍸", "packages": ["github.com/gin-gonic/gin"], "imports": ["gin"]},
    {"name": "Tornado", "category": "Backend / API", "icon": "🌪️", "packages": ["tornado"], "imports": ["tornado"]},

    # --- Frontend & UI ---
    {"name": "React", "category": "Frontend / UI", "icon": "⚛️", "packages": ["react", "react-dom"], "imports": ["react", "react-dom"]},
    {"name": "Next.js", "category": "Frontend / UI", "icon": "▲", "packages": ["next"], "imports": ["next"]},
    {"name": "Vue.js", "category": "Frontend / UI", "icon": "💚", "packages": ["vue"], "imports": ["vue"]},
    {"name": "Nuxt", "category": "Frontend / UI", "icon": "⛰️", "packages": ["nuxt"], "imports": ["nuxt"]},
    {"name": "Svelte", "category": "Frontend / UI", "icon": "🔥", "packages": ["svelte"], "imports": ["svelte"]},
    {"name": "Angular", "category": "Frontend / UI", "icon": "🅰️", "packages": ["@angular/core"], "imports": ["@angular"]},
    {"name": "Vite", "category": "Frontend / UI", "icon": "⚡", "packages": ["vite"], "files": ["vite.config.js", "vite.config.ts"]},
    {"name": "TailwindCSS", "category": "Frontend / UI", "icon": "🎨", "packages": ["tailwindcss"], "files": ["tailwind.config.js", "tailwind.config.ts"]},
    {"name": "Bootstrap", "category": "Frontend / UI", "icon": "🅱️", "packages": ["bootstrap"], "imports": ["bootstrap"]},

    # --- Intelligence Artificielle & LLMs ---
    {"name": "OpenAI API / SDK", "category": "Intelligence Artificielle", "icon": "🤖", "packages": ["openai"], "imports": ["openai"], "patterns": [r"sk-[a-zA-Z0-9_\-]{20,}", r"OPENAI_API_KEY", r"api\.openai\.com", r"gpt-4", r"gpt-3\.5"]},
    {"name": "Anthropic Claude", "category": "Intelligence Artificielle", "icon": "🧠", "packages": ["anthropic"], "imports": ["anthropic"], "patterns": [r"ANTHROPIC_API_KEY", r"api\.anthropic\.com", r"claude-3"]},
    {"name": "LangChain", "category": "Intelligence Artificielle", "icon": "🦜", "packages": ["langchain", "langchain-core", "langchain-community"], "imports": ["langchain"]},
    {"name": "LlamaIndex", "category": "Intelligence Artificielle", "icon": "🦙", "packages": ["llama-index", "llama_index"], "imports": ["llama_index"]},
    {"name": "Hugging Face / Transformers", "category": "Intelligence Artificielle", "icon": "🤗", "packages": ["transformers", "huggingface-hub", "@huggingface/inference"], "imports": ["transformers", "huggingface_hub"]},
    {"name": "PyTorch", "category": "Intelligence Artificielle", "icon": "🔥", "packages": ["torch", "torchvision"], "imports": ["torch"]},
    {"name": "TensorFlow", "category": "Intelligence Artificielle", "icon": "🔶", "packages": ["tensorflow"], "imports": ["tensorflow"]},
    {"name": "Ollama SDK", "category": "Intelligence Artificielle", "icon": "🦙", "packages": ["ollama"], "imports": ["ollama"], "patterns": [r"localhost:11434", r"ollama\.chat"]},
    {"name": "CrewAI", "category": "Intelligence Artificielle", "icon": "👥", "packages": ["crewai"], "imports": ["crewai"]},
    {"name": "ChromaDB", "category": "Intelligence Artificielle", "icon": "🔮", "packages": ["chromadb"], "imports": ["chromadb"]},

    # --- Bases de Données & Stockage ---
    {"name": "SQLite", "category": "Bases de Données", "icon": "🗄️", "imports": ["sqlite3", "sqlite"], "files": ["*.db", "*.sqlite", "*.sqlite3"]},
    {"name": "SQLAlchemy", "category": "Bases de Données", "icon": "🔗", "packages": ["sqlalchemy"], "imports": ["sqlalchemy"]},
    {"name": "Prisma", "category": "Bases de Données", "icon": "◬", "packages": ["@prisma/client", "prisma"], "files": ["schema.prisma"]},
    {"name": "PostgreSQL", "category": "Bases de Données", "icon": "🐘", "packages": ["psycopg2", "psycopg2-binary", "asyncpg", "pg"], "imports": ["psycopg2", "asyncpg", "pg"]},
    {"name": "MongoDB / Mongoose", "category": "Bases de Données", "icon": "🍃", "packages": ["pymongo", "mongoose", "mongodb"], "imports": ["pymongo", "mongoose"]},
    {"name": "Redis", "category": "Bases de Données", "icon": "🟥", "packages": ["redis", "ioredis"], "imports": ["redis"]},
    {"name": "Supabase", "category": "Bases de Données", "icon": "⚡", "packages": ["supabase", "@supabase/supabase-js"], "imports": ["supabase"]},
    {"name": "Firebase", "category": "Bases de Données", "icon": "🔥", "packages": ["firebase", "firebase-admin"], "imports": ["firebase"]},

    # --- Desktop & Multiplateforme ---
    {"name": "Tauri", "category": "Desktop / Native", "icon": "🦀", "packages": ["@tauri-apps/api"], "files": ["tauri.conf.json", "src-tauri"]},
    {"name": "Electron", "category": "Desktop / Native", "icon": "⚛️", "packages": ["electron"], "imports": ["electron"]},
    {"name": "PyQt / PySide", "category": "Desktop / Native", "icon": "🖼️", "packages": ["pyqt5", "pyqt6", "pyside2", "pyside6"], "imports": ["PyQt5", "PyQt6", "PySide2", "PySide6"]},
    {"name": "Tkinter", "category": "Desktop / Native", "icon": "🪟", "imports": ["tkinter"]},

    # --- Tests & Qualité ---
    {"name": "Pytest", "category": "Tests & Qualité", "icon": "🧪", "packages": ["pytest"], "imports": ["pytest"]},
    {"name": "Jest", "category": "Tests & Qualité", "icon": "🃏", "packages": ["jest"], "files": ["jest.config.js", "jest.config.ts"]},
    {"name": "Vitest", "category": "Tests & Qualité", "icon": "⚡", "packages": ["vitest"], "files": ["vitest.config.ts", "vitest.config.js"]},
    {"name": "Playwright", "category": "Tests & Qualité", "icon": "🎭", "packages": ["playwright", "@playwright/test"], "imports": ["playwright"]},
    {"name": "Cypress", "category": "Tests & Qualité", "icon": "🌲", "packages": ["cypress"], "files": ["cypress.config.js", "cypress.config.ts"]},

    # --- DevOps & Outils ---
    {"name": "Docker", "category": "DevOps & Déploiement", "icon": "🐳", "files": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"]},
    {"name": "GitHub Actions", "category": "DevOps & Déploiement", "icon": "🐙", "files": [".github/workflows"]},
]

class TechDetector:
    @staticmethod
    def _detect_languages(context: Any) -> tuple:
        lang_stats: Dict[str, Dict[str, Any]] = {}
        total_code_lines = 0

        for f in context.code_files:
            ext = f.extension.lower()
            spec = LANGUAGE_SPECS.get(ext)
            if not spec:
                continue

            lang_name = spec["name"]
            line_count = len(f.content.splitlines()) if f.content else 0

            if lang_name not in lang_stats:
                lang_stats[lang_name] = {
                    "name": lang_name,
                    "color": spec["color"],
                    "is_code": spec["is_code"],
                    "files": 0,
                    "lines": 0,
                }

            lang_stats[lang_name]["files"] += 1
            lang_stats[lang_name]["lines"] += line_count

            if spec["is_code"]:
                total_code_lines += line_count

        code_languages = [s for s in lang_stats.values() if s["is_code"]]
        code_languages.sort(key=lambda x: x["lines"], reverse=True)

        for item in code_languages:
            item["percentage"] = round((item["lines"] / total_code_lines) * 100, 1) if total_code_lines > 0 else 0.0

        primary_language = code_languages[0]["name"] if code_languages else "Inconnu"
        return primary_language, total_code_lines, code_languages

    @staticmethod
    def _collect_manifest_packages(context: Any) -> tuple:
        manifest_packages: Set[str] = set()
        package_managers: Set[str] = set()

        if "requirements.txt" in context.root_files:
            package_managers.add("pip")
            for line in (context.read_file("requirements.txt") or "").splitlines():
                line = line.strip().lower()
                if line and not line.startswith(("#", "-")):
                    pkg = re.split(r"[=><~;]", line)[0].strip()
                    if pkg:
                        manifest_packages.add(pkg)

        if "pyproject.toml" in context.root_files:
            package_managers.add("poetry/pip")
            for line in (context.read_file("pyproject.toml") or "").splitlines():
                if "=" in line:
                    k = line.split("=")[0].strip().strip('"\'').lower()
                    if k:
                        manifest_packages.add(k)

        if "package.json" in context.root_files:
            package_managers.add("npm")
            try:
                data = json.loads(context.read_file("package.json") or "{}")
                for dep_dict in [data.get("dependencies", {}), data.get("devDependencies", {})]:
                    for pkg in dep_dict.keys():
                        manifest_packages.add(pkg.lower())
            except (json.JSONDecodeError, AttributeError):
                pass

        if "Cargo.toml" in context.root_files:
            package_managers.add("cargo")
            for line in (context.read_file("Cargo.toml") or "").splitlines():
                if "=" in line:
                    k = line.split("=")[0].strip().lower()
                    if k:
                        manifest_packages.add(k)

        if "go.mod" in context.root_files:
            package_managers.add("go modules")
            for line in (context.read_file("go.mod") or "").splitlines():
                parts = line.strip().lower().split()
                if parts:
                    manifest_packages.add(parts[0])

        return manifest_packages, package_managers

    @staticmethod
    def _extract_code_imports(context: Any) -> Set[str]:
        code_imports: Set[str] = set()
        for f in context.code_files:
            ext = f.extension.lower()
            content = f.content or ""

            if ext == ".py":
                for m in re.finditer(r"^(?:import|from)\s+([a-zA-Z0-9_]+)", content, re.MULTILINE):
                    code_imports.add(m.group(1).lower())
            elif ext in [".js", ".jsx", ".ts", ".tsx", ".mjs"]:
                for m in re.finditer(r"import\s+.*?from\s+['\"]([^'\"]+)['\"]", content):
                    code_imports.add(m.group(1).split("/")[0].lower())
                for m in re.finditer(r"require\s*\(\s*['\"]([^'\"]+)['\"]", content):
                    code_imports.add(m.group(1).split("/")[0].lower())
            elif ext == ".rs":
                for m in re.finditer(r"use\s+([a-zA-Z0-9_]+)::", content):
                    code_imports.add(m.group(1).lower())

        return code_imports

    @staticmethod
    def _detect_frameworks(context: Any, manifest_packages: Set[str], code_imports: Set[str]) -> List[Dict[str, Any]]:
        detected_frameworks: List[Dict[str, Any]] = []
        seen_frameworks: Set[str] = set()

        for spec in FRAMEWORK_CATALOG:
            name = spec["name"]
            detected_via = []

            for pkg in spec.get("packages", []):
                if pkg.lower() in manifest_packages:
                    detected_via.append("manifeste")
                    break

            for imp in spec.get("imports", []):
                if imp.lower() in code_imports:
                    detected_via.append("import code")
                    break

            for target_file in spec.get("files", []):
                if target_file in context.root_files:
                    detected_via.append("fichier config")
                    break
                elif target_file.startswith("*") and any(f.rel_path.endswith(target_file[1:]) for f in context.code_files):
                    detected_via.append("fichier projet")
                    break
                elif "/" in target_file and any(target_file in f.rel_path for f in context.code_files):
                    detected_via.append("structure")
                    break

            for pat in spec.get("patterns", []):
                if any(re.search(pat, f.content or "") for f in context.code_files):
                    detected_via.append("usage code / API")
                    break

            if detected_via and name not in seen_frameworks:
                seen_frameworks.add(name)
                detected_frameworks.append({
                    "name": name,
                    "category": spec["category"],
                    "icon": spec["icon"],
                    "detected_via": " & ".join(sorted(set(detected_via)))
                })

        return detected_frameworks

    @staticmethod
    def _detect_tools(context: Any) -> List[str]:
        tools: List[str] = []
        if ".env" in context.root_files or any(f.filename.startswith(".env") for f in context.code_files):
            tools.append("Environment Variables (.env)")
        if ".gitignore" in context.root_files:
            tools.append("Git Version Control")
        if "Dockerfile" in context.root_files or any("docker-compose" in f.filename for f in context.code_files):
            tools.append("Docker Containerization")
        if any(".github" in f.rel_path for f in context.code_files):
            tools.append("CI/CD (GitHub Workflows)")
        return tools

    @staticmethod
    def detect(context: Any) -> Dict[str, Any]:
        """
        Scans files, manifests, and AST/imports from ScanContext
        to determine languages breakdown, frameworks, and tools.
        """
        primary_lang, total_lines, languages = TechDetector._detect_languages(context)
        manifest_pkgs, pkg_managers = TechDetector._collect_manifest_packages(context)
        code_imports = TechDetector._extract_code_imports(context)
        frameworks = TechDetector._detect_frameworks(context, manifest_pkgs, code_imports)
        tools = TechDetector._detect_tools(context)

        return {
            "primary_language": primary_lang,
            "total_code_lines": total_lines,
            "languages": languages,
            "frameworks": frameworks,
            "package_managers": sorted(list(pkg_managers)),
            "tools": tools
        }

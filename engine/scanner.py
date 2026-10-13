"""
Scanner and context collector for Vibe Audit.
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from .rules import ALL_RULES, BaseAuditRule
from .rules.base import RuleResult

import fnmatch

IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", "out", "target", "release", ".next", ".nuxt",
    ".cache", ".idea", ".vscode", "coverage", ".pytest_cache",
    "vendor", "vendors", "mediapipe", "third_party", "bower_components",
    ".tauri", ".cargo", "Pods", ".output", "samples", "fixtures"
}

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css",
    ".json", ".yaml", ".yml", ".toml", ".env", ".txt", ".md", ".sh", ".rs", ".go"
}

VENDOR_DIR_SUBSTRINGS = {
    "mediapipe", "node_modules", "vendor", "vendors", "third_party",
    "packages", "libs/vendor", "public/vendor", "public/mediapipe",
    "dist/", "build/", "out/", "target/", ".tauri"
}

IGNORED_FILE_PATTERNS = [
    "*.min.js", "*.min.css", "*.map", "*.chunk.js", "*.bundle.js",
    "*.wasm", "*.wasm_bin.js", "*.binarypb", "*.tflite",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
    "poetry.lock", "Gemfile.lock", "composer.lock"
]

EMSCRIPTEN_WASM_SIGNATURES = [
    'Module["wasmBinary"]', "allocateUTF8", "UTF8ToString", "HEAP32",
    "ENVIRONMENT_IS_WEB", "createExportWrapper", "emscripten_",
    "selfie_segmentation", "MediaPipe"
]

@dataclass
class FileInfo:
    abs_path: Path
    rel_path: str
    filename: str
    extension: str
    content: str
    is_vendor: bool = False

@dataclass
class ScanContext:
    root_path: Path
    code_files: List[FileInfo] = field(default_factory=list)
    root_files: Set[str] = field(default_factory=set)
    total_lines: int = 0

    def read_file(self, rel_path: str) -> Optional[str]:
        target = self.root_path / rel_path
        if target.exists() and target.is_file():
            try:
                return target.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return None
        return None

def parse_gitignore(gitignore_path: Path) -> List[str]:
    patterns = []
    if not gitignore_path.exists() or not gitignore_path.is_file():
        return patterns
    try:
        content = gitignore_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    except Exception:
        pass
    return patterns

def matches_gitignore(rel_path: str, patterns: List[str], is_dir: bool = False) -> bool:
    rel_norm = rel_path.replace("\\", "/").strip("/")
    path_parts = rel_norm.split("/")
    
    for pattern in patterns:
        p = pattern.strip()
        if not p:
            continue
        # Directory pattern ending in /
        dir_only = p.endswith("/")
        if dir_only:
            p = p.rstrip("/")
            if not is_dir and p not in path_parts:
                continue
        
        # Match against full rel path or any subpath
        if p.startswith("/"):
            p_clean = p.lstrip("/")
            if fnmatch.fnmatch(rel_norm, p_clean) or fnmatch.fnmatch(rel_norm, p_clean + "/*"):
                return True
        else:
            if fnmatch.fnmatch(rel_norm, p) or fnmatch.fnmatch(rel_norm, f"*/{p}") or fnmatch.fnmatch(rel_norm, f"*/{p}/*") or any(fnmatch.fnmatch(part, p) for part in path_parts):
                return True
    return False

class Scanner:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir).resolve()

    def build_context(self) -> ScanContext:
        if not self.target_dir.exists() or not self.target_dir.is_dir():
            raise ValueError(f"Le dossier spécifié n'existe pas : {self.target_dir}")

        context = ScanContext(root_path=self.target_dir)

        # Collect root files for easy checking (.env, requirements.txt, etc.)
        for item in self.target_dir.iterdir():
            if item.is_file():
                context.root_files.add(item.name)

        # Parse .gitignore if present
        gitignore_patterns = parse_gitignore(self.target_dir / ".gitignore")

        for root, dirs, files in os.walk(self.target_dir):
            current_dir_path = Path(root)
            rel_dir = str(current_dir_path.relative_to(self.target_dir)).replace("\\", "/")
            if rel_dir == ".":
                rel_dir = ""

            # Filter subdirectories in-place
            valid_dirs = []
            for d in dirs:
                sub_rel = f"{rel_dir}/{d}".lstrip("/")
                d_lower = d.lower()
                if d in IGNORED_DIRS or d.startswith("."):
                    continue
                if any(v in d_lower for v in ["mediapipe", "vendor", "vendors", "third_party"]):
                    continue
                if any(v in sub_rel.lower() for v in ["public/mediapipe", "public/vendor", "dist", "build", "target"]):
                    continue
                if matches_gitignore(sub_rel, gitignore_patterns, is_dir=True):
                    continue
                valid_dirs.append(d)
            dirs[:] = valid_dirs

            for file_name in files:
                ext = Path(file_name).suffix.lower()
                rel_file_path = f"{rel_dir}/{file_name}".lstrip("/")
                rel_lower = rel_file_path.lower()

                # 1. Skip ignored patterns
                if any(fnmatch.fnmatch(file_name, pat) for pat in IGNORED_FILE_PATTERNS):
                    continue

                # 2. Skip files matching .gitignore
                if matches_gitignore(rel_file_path, gitignore_patterns, is_dir=False):
                    continue

                # 3. Skip vendor / mediapipe paths
                if any(v in rel_lower for v in VENDOR_DIR_SUBSTRINGS):
                    continue

                if ext in ALLOWED_EXTENSIONS or file_name.startswith(".env") or file_name in ["Dockerfile", "Makefile"]:
                    file_path = current_dir_path / file_name
                    try:
                        # Skip files larger than 1.5MB (likely bundled or binary assets)
                        if file_path.stat().st_size > 1.5 * 1024 * 1024:
                            continue

                        content = file_path.read_text(encoding="utf-8", errors="replace")
                        
                        # Heuristic check for minified single-line scripts
                        first_line = content[:800].split("\n")[0] if content else ""
                        if len(first_line) > 500 and any(kw in first_line for kw in ["function(", "webpack", "!function", "define(", "sourceMappingURL"]):
                            continue

                        # Check for Emscripten / WASM compiled wrappers
                        is_emscripten = any(sig in content[:3000] for sig in EMSCRIPTEN_WASM_SIGNATURES)
                        if is_emscripten:
                            # Skip Emscripten vendor binaries completely
                            continue

                        lines = len(content.splitlines())
                        # Check average line length (heuristic for minified code)
                        if lines > 0 and (len(content) / lines) > 350:
                            continue

                        context.total_lines += lines

                        context.code_files.append(FileInfo(
                            abs_path=file_path,
                            rel_path=rel_file_path,
                            filename=file_name,
                            extension=ext,
                            content=content,
                            is_vendor=False
                        ))
                    except Exception:
                        continue

        return context

    def run_audit(self, enabled_rule_ids: Optional[List[str]] = None, rule_configs: Optional[Dict[str, Any]] = None) -> List[RuleResult]:
        context = self.build_context()
        rule_configs = rule_configs or {}
        results: List[RuleResult] = []

        target_rule_ids = enabled_rule_ids if enabled_rule_ids is not None else list(ALL_RULES.keys())

        for rule_id in target_rule_ids:
            if rule_id in ALL_RULES:
                rule_cls = ALL_RULES[rule_id]
                rule_inst: BaseAuditRule = rule_cls(config=rule_configs.get(rule_id, {}))
                res = rule_inst.scan(context)
                results.append(res)

        return results

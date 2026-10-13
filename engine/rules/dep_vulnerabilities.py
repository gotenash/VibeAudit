"""
Rule: Detect known vulnerabilities (CVEs) and security risks in declared dependencies.
Queries the OSV.dev (Open Source Vulnerabilities) database in batch mode,
with a robust local offline fallback for known vulnerable packages.
"""
import re
import json
import urllib.request
from typing import List, Dict, Any, Tuple
from .base import BaseAuditRule, RuleResult, Finding, Category, Severity

# Offline signatures for common packages recommended by LLMs in outdated versions
OFFLINE_VULN_PATTERNS = [
    ("requests", r"^(?:0\.|1\.|2\.(?:[0-9]|1[0-9]|2[0-9]|30)\b)", "CVE-2023-32681 (Fuite de session & credentials HTTP)", ">= 2.31.0"),
    ("urllib3", r"^(?:0\.|1\.(?:[0-9]|1[0-9]|2[0-5]|26\.[0-9]|26\.1[0-7])\b)", "CVE-2023-45803 / CVE-2023-43804 (Fuite de headers Cookie & Body injection)", ">= 1.26.18"),
    ("flask", r"^(?:0\.|1\.|2\.(?:[0-1]\.|2\.[0-4]\b))", "CVE-2023-30861 (Cookie session tampering)", ">= 2.2.5"),
    ("jinja2", r"^(?:[0-2]\.|3\.0\.|3\.1\.[0-2]\b)", "CVE-2024-22195 (Injection de template HTML & XSS)", ">= 3.1.3"),
    ("pillow", r"^(?:[0-9]\.|10\.[0-1]\b)", "CVE-2023-50447 (Exécution de code arbitraire via PIL.ImageMath)", ">= 10.2.0"),
    ("lodash", r"^(?:[0-3]\.|4\.(?:[0-9]|1[0-6]|17\.[0-9]|17\.1[0-9]|17\.20)\b)", "CVE-2021-23337 / CVE-2020-8203 (Prototype Pollution)", ">= 4.17.21"),
    ("axios", r"^0\.(?:[0-9]|1[0-9]|2[0-1]\.[0-1]\b)", "CVE-2021-3749 (SSRF & ReDoS via data URLs)", ">= 0.21.2")
]

class DependencyVulnerabilitiesRule(BaseAuditRule):
    rule_id = "vibe_dep_vulnerabilities"
    name = "Vulnérabilités de Dépendances & CVEs (OSV.dev)"
    category = Category.DEPENDENCY_VULNS
    default_severity = Severity.HIGH
    description = "Détecte les failles de sécurité connues (CVEs) dans requirements.txt et package.json via l'API publique OSV.dev."
    enabled_by_default = True

    def _query_osv_batch(self, queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Interroge l'API publique OSV.dev par lot (batch)."""
        if not queries:
            return []
        url = "https://api.osv.dev/v1/querybatch"
        payload = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "VibeAudit/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("results", [])
        except Exception:
            return []

    def _collect_requirements_pkgs(self, context, result, packages_to_check: list):
        if "requirements.txt" not in context.root_files:
            return
        result.files_scanned += 1
        req_content = context.read_file("requirements.txt") or ""
        for lineno, raw_line in enumerate(req_content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith(("#", "-")):
                continue

            if "==" in line:
                parts = line.split("==")
                pkg = parts[0].strip()
                ver = parts[1].split(";")[0].strip()
                packages_to_check.append({
                    "file": "requirements.txt",
                    "lineno": lineno,
                    "raw_line": line,
                    "pkg_name": pkg,
                    "version": ver,
                    "ecosystem": "PyPI"
                })
            elif not any(op in line for op in [">=", "<=", "~=", ">", "<"]):
                pkg = line.split(";")[0].strip()
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.LOW,
                    file_path="requirements.txt",
                    line_number=lineno,
                    code_snippet=line,
                    message=f"Dépendance '{pkg}' non verrouillée sans version précise.",
                    ai_rationale="L'IA omet souvent de figer les versions dans requirements.txt, exposant le projet à des changements d'API incompatibles ou à du typosquatting de packages.",
                    fix_recommendation=f"Verrouiller la version exacte (ex: {pkg}==X.Y.Z) après avoir testé la compatibilité."
                ))

    def _collect_npm_pkgs(self, context, result, packages_to_check: list):
        if "package.json" not in context.root_files:
            return
        result.files_scanned += 1
        pkg_raw = context.read_file("package.json") or "{}"
        try:
            pkg_data = json.loads(pkg_raw)
            all_deps = {}
            all_deps.update(pkg_data.get("dependencies", {}))
            all_deps.update(pkg_data.get("devDependencies", {}))

            for pkg, ver_str in all_deps.items():
                clean_ver = re.sub(r"[^0-9\.]", "", ver_str).split(".")[0:3]
                if len(clean_ver) >= 2:
                    ver = ".".join(clean_ver)
                    packages_to_check.append({
                        "file": "package.json",
                        "lineno": None,
                        "raw_line": f'"{pkg}": "{ver_str}"',
                        "pkg_name": pkg,
                        "version": ver,
                        "ecosystem": "npm"
                    })
        except (json.JSONDecodeError, AttributeError):
            pass

    def _check_osv_vulnerabilities(self, packages_to_check: list, result, reported_packages: set):
        osv_queries = [
            {"package": {"name": p["pkg_name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
            for p in packages_to_check
        ]
        osv_results = self._query_osv_batch(osv_queries)
        if len(osv_results) != len(packages_to_check):
            return

        for idx, res in enumerate(osv_results):
            vulns = res.get("vulns", [])
            if not vulns:
                continue

            pkg_info = packages_to_check[idx]
            pkg_name = pkg_info["pkg_name"]
            reported_packages.add(pkg_name.lower())

            vuln_ids = [v.get("id") for v in vulns[:3] if v.get("id")]
            main_vuln = vulns[0]
            summary = main_vuln.get("summary") or main_vuln.get("details", "")[:120]

            fixed_ver = None
            for aff in main_vuln.get("affected", []):
                for r in aff.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_ver = event["fixed"]
                            break

            fix_advice = f"Mettre à jour '{pkg_name}' vers la version >= {fixed_ver}." if fixed_ver else f"Mettre à jour '{pkg_name}' vers sa dernière version stable."
            severity = Severity.CRITICAL if any("CRITICAL" in str(v.get("severity", [])).upper() for v in vulns) else Severity.HIGH

            vuln_ids_str = ", ".join(vuln_ids)
            msg = f"Vulnérabilité ({vuln_ids_str}) dans {pkg_name}=={pkg_info['version']} : {summary}" if summary else f"{len(vulns)} faille(s) de sécurité ({vuln_ids_str}) répertoriée(s) dans {pkg_name}=={pkg_info['version']}."

            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=severity,
                file_path=pkg_info["file"],
                line_number=pkg_info["lineno"],
                code_snippet=pkg_info["raw_line"],
                message=msg,
                ai_rationale="Les modèles d'IA réutilisent fréquemment de vieux snippets de code avec des versions de bibliothèques obsolètes.",
                fix_recommendation=fix_advice
            ))

    def _check_offline_fallback(self, packages_to_check: list, result, reported_packages: set):
        for pkg_info in packages_to_check:
            pkg_name = pkg_info["pkg_name"].lower()
            if pkg_name in reported_packages:
                continue
            ver = pkg_info["version"]
            for target_pkg, ver_regex, desc, rec in OFFLINE_VULN_PATTERNS:
                if pkg_name == target_pkg and re.search(ver_regex, ver):
                    result.findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        file_path=pkg_info["file"],
                        line_number=pkg_info["lineno"],
                        code_snippet=pkg_info["raw_line"],
                        message=f"Version vulnérable connue de {pkg_name} ({ver}) : {desc}",
                        ai_rationale="Les assistants IA proposent très souvent des versions figées datant de leur période d'entraînement contenant des CVEs publiques.",
                        fix_recommendation=f"Mettre à jour {pkg_name} vers {rec}."
                    ))
                    break

    def scan(self, context) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
        )

        packages_to_check: List[Dict[str, Any]] = []
        self._collect_requirements_pkgs(context, result, packages_to_check)
        self._collect_npm_pkgs(context, result, packages_to_check)

        if not packages_to_check:
            return result

        reported_packages = set()
        self._check_osv_vulnerabilities(packages_to_check, result, reported_packages)
        self._check_offline_fallback(packages_to_check, result, reported_packages)

        result.passed = len(result.findings) == 0
        return result

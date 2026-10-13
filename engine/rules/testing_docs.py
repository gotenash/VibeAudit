"""
Rule: Detect absence of automated tests and low-quality generic AI documentation.
"""
import re
from .base import BaseAuditRule, RuleResult, Finding, Category, Severity

class TestingDocsRule(BaseAuditRule):
    rule_id = "vibe_testing_and_docs"
    name = "Tests Automatisés & Qualité de Documentation"
    category = Category.TESTS_DOCS
    default_severity = Severity.HIGH
    description = "Évalue l'absence totale de tests (le syndrome n°1 du vibe coding) et repère les commentaires IA génériques redondants."
    enabled_by_default = True

    def scan(self, context) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
        )

        test_files = []
        prod_code_lines = 0
        test_code_lines = 0

        CODE_EXTENSIONS = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go", ".c", ".cpp",
            ".cc", ".cxx", ".h", ".hpp", ".cs", ".java", ".kt", ".rb", ".php", ".swift"
        }

        for file_info in context.code_files:
            result.files_scanned += 1
            if file_info.is_vendor:
                continue

            # Only count executable code for test/prod ratio (not css, md, html, json)
            is_code = file_info.extension in CODE_EXTENSIONS
            lines_count = len(file_info.content.splitlines()) if is_code else 0

            # Detect test files accurately
            norm_path = f"/{file_info.rel_path.replace('\\', '/').lower()}"
            is_test = is_code and (
                file_info.filename.lower().startswith("test_") or
                file_info.filename.lower().endswith(("_test.py", ".spec.js", ".test.js", ".spec.ts", ".test.ts")) or
                "/tests/" in norm_path or
                "/__tests__/" in norm_path or
                norm_path.startswith("/tests/")
            )

            if is_test:
                test_files.append(file_info)
                test_code_lines += lines_count
            elif is_code:
                prod_code_lines += lines_count

            # Detect redundant generic AI comments (skip tests and rule definitions)
            if is_test or "engine/rules/" in file_info.rel_path.replace("\\", "/"):
                continue

            generic_ai_comments = [
                r"#\s*import(?:ing)?\s*(?:necessary\s*)?librar(?:y|ies)",
                r"#\s*initialize\s*(?:the\s*)?variables?",
                r"#\s*function\s*to\s*handle",
                r"//\s*define\s*state",
                r"//\s*render\s*component"
            ]
            for pattern in generic_ai_comments:
                m = re.search(pattern, file_info.content, re.IGNORECASE)
                if m:
                    line_no = file_info.content[:m.start()].count("\n") + 1
                    result.findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=Severity.INFO,
                        file_path=file_info.rel_path,
                        line_number=line_no,
                        message="Commentaire IA trivial ou redondant",
                        code_snippet=m.group(0),
                        ai_rationale="Les modèles de génération de code ont tendance à paraphraser le code avec des commentaires évidents sans expliquer les choix métiers.",
                        fix_recommendation="Privilégiez les explications sur le 'Pourquoi' plutôt que de commenter les évidences du 'Quoi'."
                    ))

        # Check total tests presence
        if prod_code_lines > 100 and len(test_files) == 0:
            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=Severity.HIGH,
                file_path="tests/",
                line_number=None,
                message=f"Aucun fichier de test détecté dans le projet ({prod_code_lines} lignes de code sans couverture)",
                code_snippet="0 automated tests found",
                ai_rationale="Le vibe-coding se concentre sur l'itération visuelle immédiate ; l'écriture de tests est presque systématiquement ignorée par défaut.",
                fix_recommendation="Mettez en place une suite de tests élémentaires (ex: pytest ou vitest) pour les chemins critiques."
            ))
        elif prod_code_lines > 300 and test_code_lines < (prod_code_lines * 0.1):
            ratio_pct = int((test_code_lines / max(1, prod_code_lines)) * 100)
            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=Severity.MEDIUM,
                file_path="tests/",
                line_number=None,
                message=f"Couverture apparente très faible : ratio de lignes de test/code de {ratio_pct}% (< 10%)",
                code_snippet=f"Test lines: {test_code_lines} vs Prod lines: {prod_code_lines}",
                ai_rationale="Quelques tests symboliques ont été générés mais la majorité des fonctionnalités récentes ne sont pas testées.",
                fix_recommendation="Ajoutez des tests d'intégration pour couvrir les flux utilisateurs principaux."
            ))

        result.passed = len(result.findings) == 0
        return result

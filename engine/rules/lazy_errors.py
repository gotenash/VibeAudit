"""
Rule: Detect lazy error handling, swallowed exceptions, placeholders, and dummy mock data.
"""
import re
import ast
from .base import BaseAuditRule, RuleResult, Finding, Category, Severity

class LazyErrorsRule(BaseAuditRule):
    rule_id = "vibe_lazy_errors"
    name = "Gestion d'erreurs paresseuse & Code Placeholder"
    category = Category.LAZY_ERRORS
    default_severity = Severity.HIGH
    description = "Détecte les 'except: pass', 'catch(e) {}', placeholders TODO/mock data oubliés par l'IA pour faire marcher le prototype vite."
    enabled_by_default = True

    def _check_python_ast(self, file_info, result, lines: list):
        if file_info.extension != ".py":
            return
        try:
            tree = ast.parse(file_info.content, filename=file_info.rel_path)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                self._check_except_handler(node, file_info, result, lines)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass) and not node.name.startswith("__"):
                    line_no = node.lineno
                    result.findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        file_path=file_info.rel_path,
                        line_number=line_no,
                        message=f"Fonction squelette non implémentée : '{node.name}' contient uniquement 'pass'",
                        code_snippet=f"def {node.name}(...): pass",
                        ai_rationale="L'assistant IA propose l'ébauche de l'architecture mais ne termine pas l'implémentation de la méthode.",
                        fix_recommendation=f"Implémentez la logique de '{node.name}' ou supprimez cette fonction morte."
                    ))

    def _check_except_handler(self, node: ast.ExceptHandler, file_info, result, lines: list):
        is_broad = False
        if node.type is None:
            is_broad = True
        elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            is_broad = True
        elif isinstance(node.type, ast.Tuple):
            is_broad = any(isinstance(elt, ast.Name) and elt.id in ("Exception", "BaseException") for elt in node.type.elts)

        if not is_broad:
            return

        line_no = node.lineno
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else "except: pass"
            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=Severity.HIGH,
                file_path=file_info.rel_path,
                line_number=line_no,
                message="Bloc 'except: pass' silencieux détecté (exception étouffée)",
                code_snippet=snippet,
                ai_rationale="L'IA génère des 'except: pass' pour éviter que le script ne plante pendant les tests rapides, masquant les vrais bugs.",
                fix_recommendation="Logguez l'erreur avec logger.error() et gérez spécifiquement l'exception au lieu d'avaler toutes les erreurs."
            ))
        elif len(node.body) == 1 and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and node.body[0].value.value == "...":
            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=Severity.HIGH,
                file_path=file_info.rel_path,
                line_number=line_no,
                message="Bloc 'except: ...' vide (ellipse)",
                code_snippet="except: ...",
                ai_rationale="L'IA laisse souvent une ellipse comme raccourci de génération.",
                fix_recommendation="Traitez l'erreur explicitement."
            ))

    def _check_js_empty_catch(self, file_info, result, content: str, lines: list):
        if file_info.extension not in [".js", ".ts", ".jsx", ".tsx"]:
            return
        for m in re.finditer(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}", content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else m.group(0)
            if snippet.startswith(("//", "/*", "*")):
                continue
            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=Severity.HIGH,
                file_path=file_info.rel_path,
                line_number=line_no,
                message="Bloc 'catch {}' vide détecté en JavaScript/TypeScript (erreur silencieuse)",
                code_snippet=m.group(0),
                ai_rationale="Le modèle LLM ferme le bloc catch avec {} pour que le code compile sans se préoccuper du crash sous-jacent.",
                fix_recommendation="Ajoutez au minimum console.error(err) ou remontez une alerte à l'utilisateur."
            ))

    def _check_placeholders_and_mocks(self, file_info, result, content: str, lines: list):
        for m in re.finditer(r"(?:const|let|var|mock_)\s*(?:mock|fake|dummy|sample)(?:Data|Users|Products|Items|List)?\s*=\s*\[", content, re.IGNORECASE):
            line_no = content[:m.start()].count("\n") + 1
            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=Severity.LOW,
                file_path=file_info.rel_path,
                line_number=line_no,
                message="Jeu de données simulées (Mock/Dummy) codé en dur",
                code_snippet=lines[line_no - 1].strip() if line_no <= len(lines) else m.group(0),
                ai_rationale="L'IA insère des listes fictives pour prévisualiser l'UI avant le branchement réel de la base de données.",
                fix_recommendation="Connectez votre service à la vraie API / BDD ou isolez ces mocks dans un dossier de tests/fixtures."
            ))

        for m in re.finditer(r"(?://|#|/\*)\s*(?:TODO|FIXME|HACK|IMPLEMENT_LATER|PLACEHOLDER)\b(.*)", content, re.IGNORECASE):
            line_no = content[:m.start()].count("\n") + 1
            comment = m.group(0).strip()
            if len(comment) > 100:
                comment = comment[:100] + "..."
            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=Severity.LOW,
                file_path=file_info.rel_path,
                line_number=line_no,
                message=f"Marqueur incomplet repéré : {comment}",
                code_snippet=comment,
                ai_rationale="L'IA ou le vibecodeur a posé une intention future sans jamais y revenir.",
                fix_recommendation="Vérifiez si cette tâche a été finalisée ou supprimez le marqueur obsolète."
            ))

    def scan(self, context) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
        )

        for file_info in context.code_files:
            result.files_scanned += 1
            if file_info.is_vendor:
                continue

            norm_path = f"/{file_info.rel_path.replace('\\', '/').lower().lstrip('/')}"
            if "/tests/" in norm_path or "/test/" in norm_path or file_info.filename.lower().startswith("test_"):
                continue

            content = file_info.content
            lines = content.splitlines()

            self._check_python_ast(file_info, result, lines)
            self._check_js_empty_catch(file_info, result, content, lines)
            self._check_placeholders_and_mocks(file_info, result, content, lines)

        result.passed = len(result.findings) == 0
        return result

"""
Rule: Detect common security holes introduced by vibe coding (eval, injections, wildcard CORS).
"""
import re
import ast
from .base import BaseAuditRule, RuleResult, Finding, Category, Severity

class SecurityRule(BaseAuditRule):
    rule_id = "vibe_security_holes"
    name = "Failles de Sécurité & Injections Vibe-Coded"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    description = "Repère les appels eval()/exec(), injections SQL par formatage de chaînes, dangerouslySetInnerHTML et CORS trop permissifs."
    enabled_by_default = True

    def _check_python_ast(self, file_info, result, lines: list):
        if file_info.extension != ".py":
            return
        try:
            tree = ast.parse(file_info.content, filename=file_info.rel_path)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call_node(node, file_info, result, lines)

    def _check_call_node(self, node: ast.Call, file_info, result, lines: list):
        # 1.1 Check eval() or exec()
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            line_no = getattr(node, "lineno", 1)
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else f"{node.func.id}()"
            result.findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                category=self.category,
                severity=Severity.CRITICAL,
                file_path=file_info.rel_path,
                line_number=line_no,
                message=f"Usage dangereux du builtin Python '{node.func.id}()' (Exécution de code arbitraire)",
                code_snippet=snippet,
                ai_rationale="L'IA utilise souvent eval()/exec() comme raccourci pour évaluer dynamiquement des expressions sans validation.",
                fix_recommendation="Remplacez eval() par ast.literal_eval() ou json.loads()."
            ))

        # 1.2 Check cursor.execute(f"SELECT ... {var}")
        func_name = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if func_name in ["execute", "executemany"] and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                line_no = node.lineno
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    file_path=file_info.rel_path,
                    line_number=line_no,
                    message="Vulnérabilité d'Injection SQL critique : requête construite avec une f-string",
                    code_snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "cursor.execute(f'...{var}...')",
                    ai_rationale="L'IA concatène souvent directement les variables utilisateur dans la chaîne SQL par commodité.",
                    fix_recommendation="Utilisez des requêtes paramétrées : cursor.execute('SELECT ... WHERE id = %s', (var,))"
                ))

        # 1.3 Check subprocess with shell=True
        subproc_func = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else "")
        if subproc_func in ["Popen", "run", "call", "check_call", "check_output"]:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    line_no = getattr(node, "lineno", 1)
                    result.findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        file_path=file_info.rel_path,
                        line_number=line_no,
                        message="Exécution système dangereuse : 'shell=True' dans subprocess",
                        code_snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "shell=True",
                        ai_rationale="L'IA ajoute shell=True pour contourner des problèmes de PATH ou de syntaxe de commande sous Windows/Linux.",
                        fix_recommendation="Passez vos arguments sous forme de liste ['cmd', 'arg1'] et retirez shell=True."
                    ))

    def _check_js_vulnerabilities(self, file_info, result, content: str, lines: list):
        if file_info.extension not in [".js", ".ts", ".jsx", ".tsx"]:
            return

        for m in re.finditer(r"(?<![\.\w$])eval\s*\(", content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else m.group(0)
            if not snippet.startswith(("//", "/*", "*")):
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    file_path=file_info.rel_path,
                    line_number=line_no,
                    message="Usage dangereux de 'eval()' en JavaScript (Exécution de code arbitraire / XSS)",
                    code_snippet=snippet,
                    ai_rationale="L'IA insère eval() pour parser du JSON laxiste ou évaluer des expressions dynamiques.",
                    fix_recommendation="Utilisez JSON.parse() ou un parseur d'expressions sécurisé sans accès au contexte global."
                ))

        for m in re.finditer(r"\bchild_process\.(?:exec|execSync)\s*\(", content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else m.group(0)
            if not snippet.startswith(("//", "/*", "*")):
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    file_path=file_info.rel_path,
                    line_number=line_no,
                    message="Exécution de commande système via 'child_process.exec()'",
                    code_snippet=snippet,
                    ai_rationale="L'IA utilise child_process.exec pour lancer des binaires locaux sans échappement suffisant.",
                    fix_recommendation="Privilégiez child_process.execFile() ou spawn() avec un tableau d'arguments pour éviter l'injection shell."
                ))

    def _check_xss_and_cors(self, file_info, result, content: str, lines: list):
        if file_info.extension in [".js", ".jsx", ".ts", ".tsx", ".html"]:
            for m in re.finditer(r"dangerouslySetInnerHTML", content):
                line_no = content[:m.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else "dangerouslySetInnerHTML"
                if not snippet.startswith(("//", "/*", "*")):
                    result.findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        file_path=file_info.rel_path,
                        line_number=line_no,
                        message="XSS potentiel : utilisation de 'dangerouslySetInnerHTML'",
                        code_snippet=snippet,
                        ai_rationale="Pour rendre rapidement du markdown ou de l'HTML renvoyé par un LLM, l'IA utilise ce flag sans désinfection.",
                        fix_recommendation="Utilisez une bibliothèque de sanitization comme DOMPurify avant d'injecter du HTML."
                    ))

        if file_info.extension in [".py", ".js", ".ts"]:
            for m in re.finditer(r"(?:allow_origins\s*=\s*\[['\"]\*['\"]\]|origin:\s*['\"]\*(?:['\"]))", content):
                line_no = content[:m.start()].count("\n") + 1
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    file_path=file_info.rel_path,
                    line_number=line_no,
                    message="Configuration CORS ouverte à tous les domaines ('*')",
                    code_snippet=lines[line_no - 1].strip() if line_no <= len(lines) else m.group(0),
                    ai_rationale="L'IA configure un CORS permissif universel pour éviter toute erreur de navigateur pendant le prototypage.",
                    fix_recommendation="Restreignez les origines CORS autorisées aux domaines de production et staging réels."
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
            self._check_js_vulnerabilities(file_info, result, content, lines)
            self._check_xss_and_cors(file_info, result, content, lines)

        result.passed = len(result.findings) == 0
        return result

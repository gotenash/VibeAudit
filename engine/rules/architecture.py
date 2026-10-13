"""
Rule: Detect architectural issues typical of vibe coding (God files, monster functions, deep nesting).
"""
import ast
from .base import BaseAuditRule, RuleResult, Finding, Category, Severity

class ArchitectureRule(BaseAuditRule):
    rule_id = "vibe_architecture_bloat"
    name = "Architecture & Fichiers Monolithiques (God Files)"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    description = "Détecte les fichiers monstres (>500 lignes), les fonctions géantes et l'empilement monolithique typique des ajouts successifs par IA."
    enabled_by_default = True

    @staticmethod
    def _calc_ast_depth(curr_node, current_d: int = 0) -> int:
        max_d = current_d
        for child in ast.iter_child_nodes(curr_node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
                max_d = max(max_d, ArchitectureRule._calc_ast_depth(child, current_d + 1))
            else:
                max_d = max(max_d, ArchitectureRule._calc_ast_depth(child, current_d))
        return max_d

    def _check_file_length(self, file_info, result):
        EXECUTABLE_CODE_EXTENSIONS = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go", ".c", ".cpp",
            ".cc", ".cxx", ".h", ".hpp", ".cs", ".java", ".kt", ".rb", ".php", ".swift"
        }
        if file_info.extension not in EXECUTABLE_CODE_EXTENSIONS:
            return

        line_count = len(file_info.content.splitlines())
        if line_count <= 400:
            return

        if line_count > 1500:
            severity = Severity.HIGH
            title = f"Fichier monolithique critique ('God File') : {line_count} lignes"
            ai_rat = "En vibe-coding, l'accumulation continue de fonctionnalités sans refactorisation produit des fichiers monstres (>1500 lignes), risqués pour la stabilité et très lourds pour le contexte des LLM."
            fix_rec = "Découpez ce composant d'urgence en sous-modules, custom hooks et sous-composants dédiés."
        elif line_count > 800:
            severity = Severity.MEDIUM
            title = f"Fichier volumineux (Refactoring conseillé) : {line_count} lignes"
            ai_rat = "Le fichier dépasse 800 lignes. Bien que courant sur des interfaces complexes, un découpage modulaire faciliterait les tests et la maintenance."
            fix_rec = "Identifiez les sous-panneaux d'UI ou la logique d'état à extraire dans des modules ou hooks séparés."
        else:
            severity = Severity.LOW
            title = f"Composant riche / volumineux (Avertissement léger) : {line_count} lignes"
            ai_rat = "Composant de taille substantielle (400-800 lignes). Toléré pour une vue ou une modale complexe, mais à surveiller."
            fix_rec = "Surveillez la croissance de ce fichier et envisagez d'extraire les éléments secondaires si de nouveaux besoins s'ajoutent."

        result.findings.append(Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
            severity=severity,
            file_path=file_info.rel_path,
            line_number=1,
            message=title,
            code_snippet=f"Total lines: {line_count}",
            ai_rationale=ai_rat,
            fix_recommendation=fix_rec
        ))

    def _check_python_function_nodes(self, file_info, result, max_func_lines: int):
        if file_info.extension != ".py":
            return
        try:
            tree = ast.parse(file_info.content, filename=file_info.rel_path)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            func_start = node.lineno
            func_end = getattr(node, "end_lineno", func_start)
            func_length = func_end - func_start + 1

            if func_length > max_func_lines:
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    file_path=file_info.rel_path,
                    line_number=func_start,
                    message=f"Fonction 'monstre' : '{node.name}' fait {func_length} lignes (seuil : {max_func_lines})",
                    code_snippet=f"def {node.name}(...): [lines {func_start} to {func_end}]",
                    ai_rationale="Les LLM écrivent souvent des fonctions fleuves avec de multiples responsabilités en une seule passe.",
                    fix_recommendation=f"Décomposez '{node.name}' en plusieurs fonctions plus petites et testables individuellement."
                ))

            depth = self._calc_ast_depth(node)
            if depth >= 7:
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.LOW,
                    file_path=file_info.rel_path,
                    line_number=func_start,
                    message=f"Nidification excessive ('Pyramid of Doom') dans '{node.name}' (profondeur : {depth})",
                    code_snippet=f"def {node.name}(...) depth={depth}",
                    ai_rationale="L'enchaînement de conditions et de boucles successives généré par IA produit souvent un code difficile à relire et déboguer.",
                    fix_recommendation="Utilisez des clauses de garde (early return) pour aplanir la structure de la fonction."
                ))

    def scan(self, context) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
        )
        max_func_lines = self.config.get("max_func_lines", 130)

        for file_info in context.code_files:
            result.files_scanned += 1
            if file_info.is_vendor:
                continue
            self._check_file_length(file_info, result)
            self._check_python_function_nodes(file_info, result, max_func_lines)

        result.passed = len(result.findings) == 0
        return result

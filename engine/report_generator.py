"""
Report generator and scoring engine for Vibe Audit.
"""
from typing import List, Dict, Any
from datetime import datetime
from .rules.base import RuleResult, Finding, Severity, Category

SEVERITY_PENALTIES = {
    Severity.CRITICAL.value: 25,
    Severity.HIGH.value: 12,
    Severity.MEDIUM.value: 6,
    Severity.LOW.value: 2,
    Severity.INFO.value: 0,
}

CATEGORY_WEIGHTS = {
    Category.SECRETS.value: 0.25,
    Category.SECURITY.value: 0.20,
    Category.DEPENDENCY_VULNS.value: 0.15,
    Category.ARCHITECTURE.value: 0.15,
    Category.LAZY_ERRORS.value: 0.10,
    Category.TESTS_DOCS.value: 0.10,
    Category.GHOST_DEPS.value: 0.05,
}

class ReportGenerator:
    @staticmethod
    def generate(results: List[RuleResult], target_dir: str, total_files: int, total_lines: int, tech_stack: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        all_findings: List[Finding] = []
        category_findings: Dict[str, List[Finding]] = {cat.value: [] for cat in Category}
        severity_counts = {sev.value: 0 for sev in Severity}

        for r in results:
            for f in r.findings:
                all_findings.append(f)
                category_findings[f.category.value].append(f)
                severity_counts[f.severity.value] += 1

        # Calculate category scores with fair bounded penalties
        category_scores = {}
        for cat in Category:
            cat_findings = category_findings[cat.value]
            cat_penalty = sum(SEVERITY_PENALTIES.get(f.severity.value, 0) for f in cat_findings)
            category_scores[cat.value] = max(0, min(100, 100 - cat_penalty))

        # Balanced multidimensional vibe score based on category weights
        raw_weighted_score = sum(category_scores[cat.value] * CATEGORY_WEIGHTS.get(cat.value, 0.15) for cat in Category)
        vibe_score = round(max(0, min(100, raw_weighted_score)))

        # Safety ceiling: If real CRITICAL issues exist, cap the score at 45
        if severity_counts[Severity.CRITICAL.value] > 0:
            vibe_score = min(vibe_score, 45)
        elif severity_counts[Severity.HIGH.value] >= 5 and vibe_score > 80:
            vibe_score = min(vibe_score, 75)

        # Determine level & badge
        if vibe_score >= 90:
            badge_label = "Production Ready"
            badge_icon = "🚀"
            badge_color = "emerald"
            verdict = "Votre projet présente une rigueur exemplaire rare en vibe-coding. Prêt pour le déploiement."
        elif vibe_score >= 70:
            badge_label = "Solide & Structuré"
            badge_icon = "🛡️"
            badge_color = "cyan"
            verdict = "Bonne base générale sans failles critiques. Priorisez le découpage modulaire et les tests."
        elif vibe_score >= 40:
            badge_label = "Vibe MVP / Dette Masquée"
            badge_icon = "⚠️"
            badge_color = "amber"
            verdict = "Fonctionnel en surface mais criblé de dette technique, d'erreurs avalées ou de dépendances floues."
        else:
            badge_label = "Vibe Fragile / Prototype Instable"
            badge_icon = "💀"
            badge_color = "rose"
            verdict = "Attention critique : présence probable de secrets en clair, d'injections ou d'instabilité majeure."

        # Prioritized action checklist
        action_plan = []
        critical_and_high = [f for f in all_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        for idx, item in enumerate(critical_and_high[:6], 1):
            action_plan.append({
                "step": idx,
                "file": item.file_path,
                "line": item.line_number,
                "title": item.message,
                "action": item.fix_recommendation,
                "severity": item.severity.value
            })

        return {
            "timestamp": datetime.now().isoformat(),
            "target_dir": target_dir,
            "stats": {
                "total_files": total_files,
                "total_lines": total_lines,
                "total_rules_run": len(results),
                "total_findings": len(all_findings),
                "severity_counts": severity_counts,
            },
            "score": {
                "vibe_score": vibe_score,
                "badge_label": badge_label,
                "badge_icon": badge_icon,
                "badge_color": badge_color,
                "verdict": verdict,
                "category_scores": category_scores,
            },
            "tech_stack": tech_stack or {},
            "action_plan": action_plan,
            "rule_results": [r.to_dict() for r in results],
        }

    @staticmethod
    def to_markdown(report_data: Dict[str, Any]) -> str:
        score_info = report_data["score"]
        stats = report_data["stats"]
        tech_stack = report_data.get("tech_stack", {})
        lines = [
            f"# Rapport d'Audit Vibe Coding : {report_data['target_dir']}",
            f"*Généré le {report_data['timestamp']} par Vibe Audit*\n",
            f"## Score Global : **{score_info['vibe_score']}/100** — {score_info['badge_icon']} {score_info['badge_label']}",
            f"> {score_info['verdict']}\n",
            "### Métriques du projet",
            f"- **Fichiers scannés** : {stats['total_files']}",
            f"- **Lignes de code totales** : {stats['total_lines']}",
            f"- **Anomalies trouvées** : {stats['total_findings']} (Critiques: {stats['severity_counts']['CRITICAL']}, Hautes: {stats['severity_counts']['HIGH']}, Moyennes: {stats['severity_counts']['MEDIUM']})\n",
        ]

        if tech_stack:
            lines.append("### 🛠️ Stack Technologique & Langages")
            if tech_stack.get("languages"):
                lines.append("#### Répartition des Langages")
                lines.append("| Langage | Fichiers | Lignes de Code | Part (%) |")
                lines.append("| :--- | :---: | :---: | :---: |")
                for lang in tech_stack["languages"]:
                    lines.append(f"| **{lang['name']}** | {lang['files']} | {lang['lines']} | {lang['percentage']}% |")
                lines.append("")

            if tech_stack.get("frameworks"):
                lines.append("#### Frameworks & Bibliothèques Détectés")
                by_cat: Dict[str, List[str]] = {}
                for f in tech_stack["frameworks"]:
                    by_cat.setdefault(f["category"], []).append(f"{f['icon']} **{f['name']}** *({f['detected_via']})*")
                for cat, items in by_cat.items():
                    lines.append(f"- **{cat}** : {', '.join(items)}")
                lines.append("")

            if tech_stack.get("package_managers"):
                lines.append(f"- **Gestionnaire(s) de paquets** : {', '.join(f'`{pm}`' for pm in tech_stack['package_managers'])}")

            if tech_stack.get("tools"):
                lines.append(f"- **Environnement & Outils** : {', '.join(tech_stack['tools'])}")
            lines.append("")

        lines.append("### Scores par Catégorie")
        for cat, val in score_info["category_scores"].items():
            lines.append(f"- **{cat}** : {val}/100")

        lines.append("\n### Plan d'action prioritaire")
        for act in report_data.get("action_plan", []):
            loc = f" (`{act['file']}:{act['line']}`)" if act['line'] else f" (`{act['file']}`)"
            lines.append(f"{act['step']}. **[{act['severity']}]** {act['title']}{loc}\n   - *Correction conseillée* : {act['action']}")

        lines.append("\n### Détail des anomalies")
        for r in report_data.get("rule_results", []):
            if not r["passed"]:
                lines.append(f"\n#### Règle : {r['rule_name']} ({len(r['findings'])} anomalies)")
                for f in r["findings"]:
                    line_str = f":{f['line_number']}" if f.get('line_number') else ""
                    lines.append(f"- **[{f['severity']}]** `{f['file_path']}{line_str}` — {f['message']}")
                    if f.get("code_snippet"):
                        lines.append(f"  ```\n  {f['code_snippet']}\n  ```")
                    if f.get("fix_recommendation"):
                        lines.append(f"  💡 *Conseil* : {f['fix_recommendation']}")

        return "\n".join(lines)

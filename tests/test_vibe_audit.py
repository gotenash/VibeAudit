"""
Automated unit tests for Vibe Audit Engine.
Covers scanner, rules, tech stack detection, and report generation.
"""
import unittest
import tempfile
import json
from pathlib import Path

from engine.scanner import Scanner, ScanContext, FileInfo, matches_gitignore, parse_gitignore
from engine.tech_detector import TechDetector
from engine.report_generator import ReportGenerator
from engine.launcher import find_available_port
from engine.rules.base import Severity, Category, RuleResult, Finding
from engine.rules.secrets import SecretsRule
from engine.rules.ghost_deps import GhostDependenciesRule
from engine.rules.lazy_errors import LazyErrorsRule
from engine.rules.architecture import ArchitectureRule
from engine.rules.security import SecurityRule
from engine.rules.testing_docs import TestingDocsRule
from engine.rules.dep_vulnerabilities import DependencyVulnerabilitiesRule


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Create mock project files
        (self.root / "app.py").write_text("print('hello world')", encoding="utf-8")
        (self.root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        (self.root / ".gitignore").write_text("dist/\n*.pyc\n", encoding="utf-8")

        sub = self.root / "src"
        sub.mkdir()
        (sub / "main.py").write_text("x = 10", encoding="utf-8")

        # Ignored dir
        node_mod = self.root / "node_modules"
        node_mod.mkdir()
        (node_mod / "dummy.js").write_text("var x = 1;", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_build_context_collects_valid_files(self):
        scanner = Scanner(str(self.root))
        ctx = scanner.build_context()

        rel_paths = [f.rel_path for f in ctx.code_files]
        self.assertIn("app.py", rel_paths)
        self.assertIn("requirements.txt", rel_paths)
        self.assertIn("src/main.py", rel_paths)
        self.assertNotIn("node_modules/dummy.js", rel_paths)

    def test_gitignore_matching(self):
        patterns = ["dist/", "*.pyc", "/secret.key"]
        self.assertTrue(matches_gitignore("dist/app.exe", patterns))
        self.assertTrue(matches_gitignore("test.pyc", patterns))
        self.assertTrue(matches_gitignore("secret.key", patterns))
        self.assertFalse(matches_gitignore("src/main.py", patterns))


class TestTechDetector(unittest.TestCase):
    def test_language_and_framework_detection(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.root_files = {"requirements.txt"}
        ctx.code_files = [
            FileInfo(
                abs_path=Path("app.py"),
                rel_path="app.py",
                filename="app.py",
                extension=".py",
                content="import os\nfrom openai import OpenAI\nclient = OpenAI()\n"
            ),
            FileInfo(
                abs_path=Path("script.js"),
                rel_path="script.js",
                filename="script.js",
                extension=".js",
                content="console.log('hello');\n"
            )
        ]

        tech = TechDetector.detect(ctx)
        self.assertEqual(tech["primary_language"], "Python")
        self.assertTrue(any(f["name"] == "OpenAI API / SDK" for f in tech["frameworks"]))
        self.assertIn("pip", tech["package_managers"])


class TestAuditRules(unittest.TestCase):
    def test_secrets_rule_detection(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("bad.py"),
                rel_path="bad.py",
                filename="bad.py",
                extension=".py",
                content="API_KEY = 'sk-proj-aB9xL2pQ8zY1wK3vM7nJ5tF4rE6gH0jD'\n"
            )
        ]
        rule = SecretsRule()
        res = rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("OpenAI" in f.message for f in res.findings))

    def test_lazy_errors_rule_catches_broad_except_pass(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("lazy.py"),
                rel_path="lazy.py",
                filename="lazy.py",
                extension=".py",
                content="try:\n    risky()\nexcept Exception:\n    pass\n"
            )
        ]
        rule = LazyErrorsRule()
        res = rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("except: pass" in f.message.lower() for f in res.findings))

    def test_lazy_errors_rule_allows_specific_pass(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("safe.py"),
                rel_path="safe.py",
                filename="safe.py",
                extension=".py",
                content="try:\n    os.kill(pid, 0)\nexcept OSError:\n    pass\n"
            )
        ]
        rule = LazyErrorsRule()
        res = rule.scan(ctx)
        self.assertTrue(res.passed)

    def test_security_rule_catches_eval_and_sql_injection(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("vuln.py"),
                rel_path="vuln.py",
                filename="vuln.py",
                extension=".py",
                content="eval(user_input)\ncursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
            )
        ]
        rule = SecurityRule()
        res = rule.scan(ctx)
        self.assertFalse(res.passed)
        messages = [f.message for f in res.findings]
        self.assertTrue(any("eval()" in m for m in messages))
        self.assertTrue(any("Injection SQL" in m for m in messages))

    def test_ghost_deps_rule_catches_unregistered_imports(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.root_files = {"requirements.txt"}
        # read_file returns empty string (no declared deps)
        ctx.read_file = lambda p: ""
        ctx.code_files = [
            FileInfo(
                abs_path=Path("main.py"),
                rel_path="main.py",
                filename="main.py",
                extension=".py",
                content="import fastapi\n"
            )
        ]
        rule = GhostDependenciesRule()
        res = rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("fastapi" in f.message for f in res.findings))

    def test_architecture_rule_flags_monster_function(self):
        ctx = ScanContext(root_path=Path("."))
        long_body = "\n".join([f"    x_{i} = {i}" for i in range(150)])
        ctx.code_files = [
            FileInfo(
                abs_path=Path("big.py"),
                rel_path="big.py",
                filename="big.py",
                extension=".py",
                content=f"def monster_func():\n{long_body}\n"
            )
        ]
        rule = ArchitectureRule()
        res = rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("Fonction 'monstre'" in f.message for f in res.findings))

    def test_dep_vulnerabilities_offline_patterns(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.root_files = {"requirements.txt"}
        ctx.read_file = lambda p: "flask==0.12.0\n"
        rule = DependencyVulnerabilitiesRule()
        res = rule.scan(ctx)
        # Should detect offline pattern for vulnerable flask
        self.assertTrue(any("flask" in f.message.lower() for f in res.findings))


class TestReportGenerator(unittest.TestCase):
    def test_score_calculation_clean_project(self):
        results = [
            RuleResult(rule_id="r1", rule_name="Test R1", category=Category.SECRETS, passed=True),
            RuleResult(rule_id="r2", rule_name="Test R2", category=Category.SECURITY, passed=True),
            RuleResult(rule_id="r3", rule_name="Test R3", category=Category.LAZY_ERRORS, passed=True),
            RuleResult(rule_id="r4", rule_name="Test R4", category=Category.ARCHITECTURE, passed=True),
            RuleResult(rule_id="r5", rule_name="Test R5", category=Category.TESTS_DOCS, passed=True),
        ]
        report = ReportGenerator.generate(
            results=results,
            target_dir="/mock/project",
            total_files=5,
            total_lines=250,
            tech_stack={"primary_language": "Python"}
        )
        self.assertGreaterEqual(report["score"]["vibe_score"], 90)
        self.assertEqual(report["score"]["badge_label"], "Production Ready")

    def test_markdown_export(self):
        results = [RuleResult(rule_id="r1", rule_name="Test", category=Category.SECRETS, passed=True)]
        report = ReportGenerator.generate(results, "/mock", 1, 10)
        md = ReportGenerator.to_markdown(report)
        self.assertIn("Rapport d'Audit Vibe Coding", md)
        self.assertIn("Score", md)


class TestLauncher(unittest.TestCase):
    def test_port_binding(self):
        port = find_available_port(5173, max_attempts=5)
        self.assertGreaterEqual(port, 5173)


if __name__ == "__main__":
    unittest.main()

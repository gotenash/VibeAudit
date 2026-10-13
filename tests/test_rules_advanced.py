"""
Advanced unit test suite for Vibe Audit rules, scanners, and report generators.
Provides deep functional testing of every security and hygiene check.
"""
import unittest
from pathlib import Path

from engine.scanner import ScanContext, FileInfo
from engine.rules.base import Severity, Category, RuleResult, Finding
from engine.rules.secrets import SecretsRule, calculate_shannon_entropy, is_sequential_or_synthetic
from engine.rules.ghost_deps import GhostDependenciesRule
from engine.rules.lazy_errors import LazyErrorsRule
from engine.rules.architecture import ArchitectureRule
from engine.rules.security import SecurityRule
from engine.rules.testing_docs import TestingDocsRule
from engine.rules.dep_vulnerabilities import DependencyVulnerabilitiesRule
from engine.report_generator import ReportGenerator
from engine.tech_detector import TechDetector


class TestSecretsRuleDeep(unittest.TestCase):
    def setUp(self):
        self.rule = SecretsRule()

    def test_anthropic_key_detection(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("config.py"),
                rel_path="config.py",
                filename="config.py",
                extension=".py",
                content="CLAUDE_KEY = 'sk-ant-api03-9F8dE7cBA21Z0yXwVuTsRqPoNmLkJiH'\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("Anthropic" in f.message for f in res.findings))

    def test_aws_credentials_detection(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("aws.py"),
                rel_path="aws.py",
                filename="aws.py",
                extension=".py",
                content="AWS_ACCESS = 'AKIAIOSFODNN7PQR89TX'\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("AWS" in f.message for f in res.findings))

    def test_github_pat_detection(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("ci.py"),
                rel_path="ci.py",
                filename="ci.py",
                extension=".py",
                content="GH_TOKEN = 'ghp_aB9xL2pQ8zY1wK3vM7nJ5tF4rE6gH0jD9kLm'\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("GitHub" in f.message for f in res.findings))

    def test_database_connection_string_leak(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("db.py"),
                rel_path="db.py",
                filename="db.py",
                extension=".py",
                content="URI = 'postgres://admin_user:super_secret_p@ss99@db.prod.internal:5432/core'\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("Base de données" in f.message for f in res.findings))

    def test_synthetic_entropy_filter(self):
        self.assertTrue(is_sequential_or_synthetic("1234567890abcdef"))
        self.assertTrue(is_sequential_or_synthetic("aaaaaaaaaaaaaaaa"))
        self.assertFalse(is_sequential_or_synthetic("aB9xL2pQ8zY1wK3vM7nJ5tF4rE6gH0jD"))
        self.assertGreater(calculate_shannon_entropy("aB9xL2pQ8zY1wK3vM7nJ5tF4rE6gH0jD"), 3.5)


class TestSecurityRuleDeep(unittest.TestCase):
    def setUp(self):
        self.rule = SecurityRule()

    def test_subprocess_shell_true_flagged(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("exec.py"),
                rel_path="exec.py",
                filename="exec.py",
                extension=".py",
                content="import subprocess\nsubprocess.run('ls -la', shell=True)\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("shell=True" in f.message for f in res.findings))

    def test_dangerously_set_inner_html(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("view.jsx"),
                rel_path="view.jsx",
                filename="view.jsx",
                extension=".jsx",
                content="function Comp({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("dangerouslySetInnerHTML" in f.message for f in res.findings))

    def test_wildcard_cors_flagged(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("api.py"),
                rel_path="api.py",
                filename="api.py",
                extension=".py",
                content="allow_origins = ['*']\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("CORS" in f.message for f in res.findings))


class TestLazyErrorsDeep(unittest.TestCase):
    def setUp(self):
        self.rule = LazyErrorsRule()

    def test_js_empty_catch_block(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("fetch.ts"),
                rel_path="fetch.ts",
                filename="fetch.ts",
                extension=".ts",
                content="try { await doSomething(); } catch (e) {}\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("catch {}" in f.message for f in res.findings))

    def test_todo_and_placeholder_comments(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("todo.py"),
                rel_path="todo.py",
                filename="todo.py",
                extension=".py",
                content="# TODO: finish billing logic later\ndef bill(): pass\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("TODO" in f.message for f in res.findings))


class TestArchitectureRuleDeep(unittest.TestCase):
    def setUp(self):
        self.rule = ArchitectureRule()

    def test_nested_pyramid_of_doom(self):
        ctx = ScanContext(root_path=Path("."))
        nested_code = (
            "def deep_func():\n"
            "    if True:\n"
            "        for i in range(1):\n"
            "            if i == 0:\n"
            "                while False:\n"
            "                    try:\n"
            "                        with open('x') as f:\n"
            "                            if f:\n"
            "                                print('deep')\n"
            "                    except OSError:\n"
            "                        pass\n"
        )
        ctx.code_files = [
            FileInfo(
                abs_path=Path("deep.py"),
                rel_path="deep.py",
                filename="deep.py",
                extension=".py",
                content=nested_code
            )
        ]
        res = self.rule.scan(ctx)
        self.assertFalse(res.passed)
        self.assertTrue(any("Pyramid of Doom" in f.message for f in res.findings))


class TestTestingDocsRule(unittest.TestCase):
    def setUp(self):
        self.rule = TestingDocsRule()

    def test_generic_ai_comments_flagged(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.code_files = [
            FileInfo(
                abs_path=Path("ai_gen.py"),
                rel_path="ai_gen.py",
                filename="ai_gen.py",
                extension=".py",
                content="# importing necessary libraries\nimport os\n# initialize the variables\nx = 1\n"
            )
        ]
        res = self.rule.scan(ctx)
        self.assertTrue(any("Commentaire IA trivial" in f.message for f in res.findings))


class TestTechDetectorDeep(unittest.TestCase):
    def test_docker_and_ci_detection(self):
        ctx = ScanContext(root_path=Path("."))
        ctx.root_files = {"Dockerfile", ".gitignore"}
        ctx.code_files = [
            FileInfo(
                abs_path=Path(".github/workflows/ci.yml"),
                rel_path=".github/workflows/ci.yml",
                filename="ci.yml",
                extension=".yml",
                content="name: CI\n"
            )
        ]
        tech = TechDetector.detect(ctx)
        self.assertIn("Docker Containerization", tech["tools"])
        self.assertIn("CI/CD (GitHub Workflows)", tech["tools"])
        self.assertIn("Git Version Control", tech["tools"])


class TestReportGeneratorEdgeCases(unittest.TestCase):
    def test_critical_ceiling_score_cap(self):
        findings = [
            Finding(
                rule_id="r_crit",
                rule_name="Crit",
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                file_path="app.py",
                line_number=1,
                message="Critical Exploit"
            )
        ]
        res = [RuleResult(rule_id="r_crit", rule_name="Crit", category=Category.SECURITY, findings=findings, passed=False)]
        rep = ReportGenerator.generate(res, "/app", 1, 100)
        self.assertLessEqual(rep["score"]["vibe_score"], 45)


if __name__ == "__main__":
    unittest.main()

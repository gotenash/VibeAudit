"""
Base classes and types for Vibe Audit rules.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Category(str, Enum):
    SECRETS = "SECRETS"
    GHOST_DEPS = "GHOST_DEPS"
    LAZY_ERRORS = "LAZY_ERRORS"
    ARCHITECTURE = "ARCHITECTURE"
    SECURITY = "SECURITY"
    TESTS_DOCS = "TESTS_DOCS"
    DEPENDENCY_VULNS = "DEPENDENCY_VULNS"

@dataclass
class Finding:
    rule_id: str
    rule_name: str
    category: Category
    severity: Severity
    file_path: str
    line_number: Optional[int]
    message: str
    code_snippet: Optional[str] = None
    ai_rationale: Optional[str] = None  # Pourquoi l'IA a tendance à faire cette erreur
    fix_recommendation: Optional[str] = None  # Comment corriger

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "message": self.message,
            "code_snippet": self.code_snippet,
            "ai_rationale": self.ai_rationale,
            "fix_recommendation": self.fix_recommendation,
        }

@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    category: Category
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    passed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "passed": len(self.findings) == 0,
        }

class BaseAuditRule:
    rule_id: str = "base_rule"
    name: str = "Base Rule"
    category: Category = Category.ARCHITECTURE
    default_severity: Severity = Severity.MEDIUM
    description: str = "Base rule description"
    enabled_by_default: bool = True

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "name": self.name,
            "category": self.category.value,
            "default_severity": self.default_severity.value,
            "description": self.description,
            "enabled_by_default": self.enabled_by_default,
        }

    def scan(self, context: Any) -> RuleResult:
        """
        To be implemented by each rule.
        context provides files, ASTs, manifests, etc.
        """
        raise NotImplementedError

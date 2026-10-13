"""
Rule registry for Vibe Audit.
"""
from typing import Dict, Type
from .base import BaseAuditRule, Category, Severity
from .secrets import SecretsRule
from .ghost_deps import GhostDependenciesRule
from .lazy_errors import LazyErrorsRule
from .architecture import ArchitectureRule
from .security import SecurityRule
from .testing_docs import TestingDocsRule
from .dep_vulnerabilities import DependencyVulnerabilitiesRule

ALL_RULES: Dict[str, Type[BaseAuditRule]] = {
    SecretsRule.rule_id: SecretsRule,
    GhostDependenciesRule.rule_id: GhostDependenciesRule,
    DependencyVulnerabilitiesRule.rule_id: DependencyVulnerabilitiesRule,
    LazyErrorsRule.rule_id: LazyErrorsRule,
    ArchitectureRule.rule_id: ArchitectureRule,
    SecurityRule.rule_id: SecurityRule,
    TestingDocsRule.rule_id: TestingDocsRule,
}

def get_all_rules_metadata():
    metadata = []
    for rule_cls in ALL_RULES.values():
        instance = rule_cls()
        metadata.append(instance.get_metadata())
    return metadata

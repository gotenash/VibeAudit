"""
Rule: Detect hardcoded API keys, tokens, and uncommitted secrets in vibe-coded projects.
"""
import re
from typing import List
from .base import BaseAuditRule, RuleResult, Finding, Category, Severity

# Patterns for secrets commonly leaked in vibe-coding
SECRET_PATTERNS = [
    (
        r"sk-(?:proj-)?[a-zA-Z0-9_-]{20,}",
        "Clé API OpenAI détectée",
        Severity.CRITICAL,
        "Les LLM injectent souvent directement 'sk-...' dans le code quand le vibecodeur demande un exemple rapide d'appel d'API.",
        "Déplacez la clé dans une variable d'environnement (ex: os.getenv('OPENAI_API_KEY')) et ajoutez .env au .gitignore."
    ),
    (
        r"sk-ant-[a-zA-Z0-9_-]{20,}",
        "Clé API Anthropic (Claude) détectée",
        Severity.CRITICAL,
        "L'IA a collé ou incité à coller un token de session ou d'API en dur.",
        "Utilisez os.environ.get('ANTHROPIC_API_KEY') ou un gestionnaire de secrets."
    ),
    (
        r"AIza[0-9A-Za-z-_]{35}",
        "Clé API Google / Gemini détectée",
        Severity.CRITICAL,
        "Clé Google AI générée et insérée en dur dans le script par inadvertance.",
        "Stockez cette clé dans les variables d'environnement (GEMINI_API_KEY)."
    ),
    (
        r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "Clé d'accès AWS IAM détectée",
        Severity.CRITICAL,
        "Risque immédiat de compromission cloud si ce dépôt est public.",
        "Révoquez immédiatement cette clé sur la console AWS et utilisez un rôle IAM ou AWS Vault."
    ),
    (
        r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,}",
        "Token GitHub Personal Access (PAT)",
        Severity.CRITICAL,
        "Token GitHub exposé donnant un accès potentiel en écriture à vos dépôts.",
        "Révoquez le token et utilisez GitHub Actions Secrets."
    ),
    (
        r"(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+",
        "Chaîne de connexion Base de données avec mot de passe en clair",
        Severity.HIGH,
        "L'IA génère souvent un URI de connexion 'postgres://<user>:<password>@...' complet pour faire fonctionner l'app sans configuration préalable.",
        "Extrayez la chaîne de connexion dans DATABASE_URL dans un fichier .env non versionné."
    ),
    (
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "Clé privée RSA / SSH codée en clair",
        Severity.CRITICAL,
        "Clé cryptographique privée présente directement dans les sources.",
        "Ne committez jamais de clés privées. Utilisez des certificats gérés ou SSH agent."
    ),
    (
        r"(?:password|secret|api_key|apiKey|token)\s*[:=]\s*['\"][a-zA-Z0-9@#$%^&+=_\-]{8,}['\"]",
        "Variable de secret / mot de passe potentiellement codée en dur",
        Severity.MEDIUM,
        "Les prototypes vibe-codés contiennent souvent des identifiants d'admin factices ou réels déclarés en clair.",
        "Vérifiez s'il s'agit d'un vrai secret et remplacez-le par une variable d'environnement."
    )
]

import math
import re
from typing import List
from .base import BaseAuditRule, RuleResult, Finding, Category, Severity

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())

def is_sequential_or_synthetic(payload: str) -> bool:
    if len(payload) < 8:
        return False
    
    # 1. Direct ascending or descending ASCII sequences (e.g. 123456, abcdef)
    consecutive_asc = sum(1 for i in range(len(payload) - 1) if ord(payload[i+1]) - ord(payload[i]) == 1)
    consecutive_desc = sum(1 for i in range(len(payload) - 1) if ord(payload[i+1]) - ord(payload[i]) == -1)
    if max(consecutive_asc, consecutive_desc) / (len(payload) - 1) > 0.55:
        return True

    # 2. Interleaved sequences (e.g. 7a8b9c0d1e2f3g4h5i6j alternating numbers and alphabet)
    even = payload[0::2]
    odd = payload[1::2]
    if len(even) >= 4 and len(odd) >= 4:
        even_seq = sum(1 for i in range(len(even)-1) if (ord(even[i+1]) - ord(even[i])) in (1, -9, 0))
        odd_seq = sum(1 for i in range(len(odd)-1) if (ord(odd[i+1]) - ord(odd[i])) in (1, -25, 0))
        if (even_seq / (len(even) - 1) > 0.6) and (odd_seq / (len(odd) - 1) > 0.6):
            return True

    # 3. Low character diversity (e.g. repetition of few chars like xxxxxxxx or 000000)
    if len(set(payload)) / len(payload) < 0.35:
        return True

    # 4. Low Shannon entropy
    entropy = calculate_shannon_entropy(payload)
    if len(payload) >= 16 and entropy < 2.7:
        return True

    return False

def is_test_or_mock_context(line: str, matched_str: str, file_rel_path: str) -> bool:
    line_lower = line.lower()
    path_lower = f"/{file_rel_path.lower().replace('\\', '/').lstrip('/')}"

    # Exclude rule definition files themselves
    if "/engine/rules/" in path_lower:
        return True

    # Check mock variable or field names
    mock_keywords = [
        "mock", "dummy", "fake", "example", "sample", "fixture",
        "placeholder", "testkey", "testtoken", "fakekey", "faketoken",
        "dummykey", "your-key", "your_key", "sk-test", "redact",
        "user:password", "username:password", "user:pass"
    ]
    if any(k in line_lower for k in mock_keywords):
        return True

    # Check if context is a mock/test file
    if any(k in path_lower for k in ["/tests/", "/test/", "/spec/", "/mocks/", "/fixtures/"]) or "test_" in path_lower:
        return True

    # Extract token payload without vendor prefix
    clean_payload = re.sub(r"^(?:sk-(?:proj-)?|sk-ant-|AIza|(?:AKIA|ABIA|ACCA|ASIA)|ghp_|github_pat_)", "", matched_str)
    if is_sequential_or_synthetic(clean_payload):
        return True

    return False

class SecretsRule(BaseAuditRule):
    rule_id = "vibe_hardcoded_secrets"
    name = "Détection des Secrets & Clés API en clair"
    category = Category.SECRETS
    default_severity = Severity.CRITICAL
    description = "Repère les clés OpenAI, Anthropic, Google, AWS, tokens GitHub et chaînes de connexion BDD hardcodées."
    enabled_by_default = True

    def scan(self, context) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
        )

        for file_info in context.code_files:
            result.files_scanned += 1
            content = file_info.content
            lines = content.splitlines()

            # Ignore minified files or package-lock files
            if file_info.is_vendor or file_info.filename in ["package-lock.json", "yarn.lock"]:
                continue

            for pattern, label, severity, rationale, fix in SECRET_PATTERNS:
                for idx, line in enumerate(lines, 1):
                    # Skip comment-only documentation mentions unless realistic
                    if len(line.strip()) > 300: # skip gigantic minified lines to avoid false positives
                        continue

                    match = re.search(pattern, line)
                    if match:
                        matched_str = match.group(0)

                        # Filter out mocks, dummies, unit tests, and synthetic sequences
                        if is_test_or_mock_context(line, matched_str, file_info.rel_path):
                            continue

                        matched_snippet = line.strip()
                        # Obfuscate secret in the reported snippet for security
                        masked_str = matched_str[:7] + "..." + matched_str[-4:] if len(matched_str) > 12 else "****"
                        safe_snippet = matched_snippet.replace(matched_str, masked_str)

                        result.findings.append(Finding(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            category=self.category,
                            severity=severity,
                            file_path=file_info.rel_path,
                            line_number=idx,
                            message=f"{label} à la ligne {idx}",
                            code_snippet=safe_snippet,
                            ai_rationale=rationale,
                            fix_recommendation=fix
                        ))

        # Check if .env is committed or missing from .gitignore
        if ".env" in context.root_files and ".gitignore" in context.root_files:
            gitignore_content = context.read_file(".gitignore") or ""
            if ".env" not in gitignore_content:
                result.findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    file_path=".env",
                    line_number=1,
                    message="Le fichier .env existe mais n'est pas mentionné dans .gitignore !",
                    code_snippet=".env present in repository root without .gitignore exclusion",
                    ai_rationale="Lors du vibe coding, l'utilisateur crée un .env sur conseil de l'IA mais oublie d'ajouter .gitignore.",
                    fix_recommendation="Ajoutez '.env' et '.env.local' dans votre .gitignore immédiatement."
                ))

        result.passed = len(result.findings) == 0
        return result

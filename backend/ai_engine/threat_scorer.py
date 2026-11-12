"""
AI Threat Scorer & Defense Evaluator
Evaluates attack traffic, assigns threat probabilities, and detects defense blind spots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .features import extract_features
from .patterns import (
    COMMAND_INJECTION,
    CRLF_INJECTION,
    DOUBLE_ENCODED,
    FILE_INCLUSION,
    LOG4SHELL,
    OPEN_REDIRECT,
    PATH_TRAVERSAL,
    SQLI,
    SSRF,
    XSS,
    XXE_INJECTION,
)


@dataclass
class DefenseEvaluation:
    """
    Result of evaluating an attack payload against the defensive AI/rule engine.
    """
    threat_score: float              # 0.0 (benign) to 1.0 (malicious)
    severity: str                    # INFO, LOW, MEDIUM, HIGH, CRITICAL
    defense_verdict: str             # "CAUGHT_BY_AI" or "STEALTH_BYPASS"
    matched_rules: list[str] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)
    remediation_patch: str = ""


class AIThreatEngine:
    """
    Evaluates HTTP requests and attack payloads using a blended model of:
    - ModSecurity CRS pattern recognition
    - Shannon entropy & lexical anomaly heuristics
    """

    RULES = [
        ("LOG4SHELL", LOG4SHELL, 0.95),
        ("COMMAND_INJECTION", COMMAND_INJECTION, 0.90),
        ("SQL_INJECTION", SQLI, 0.85),
        ("XXE_INJECTION", XXE_INJECTION, 0.82),
        ("XSS", XSS, 0.80),
        ("FILE_INCLUSION", FILE_INCLUSION, 0.75),
        ("SSRF", SSRF, 0.70),
        ("CRLF_INJECTION", CRLF_INJECTION, 0.65),
        ("PATH_TRAVERSAL", PATH_TRAVERSAL, 0.60),
        ("OPEN_REDIRECT", OPEN_REDIRECT, 0.55),
    ]

    @classmethod
    def evaluate(
        cls,
        uri: str,
        payload: str = "",
        test_type: str = "general",
        is_attack: bool = True
    ) -> DefenseEvaluation:
        """
        Evaluate an HTTP request against the AI defense engine.
        """
        target_text = f"{uri} {payload}"
        features = extract_features(uri, payload)

        matched_rules: list[str] = []
        highest_score = 0.0

        for rule_name, pattern, score in cls.RULES:
            if pattern.search(target_text):
                matched_rules.append(rule_name)
                if score > highest_score:
                    highest_score = score

        # Boost score if double encoding or high special character ratio is present
        if DOUBLE_ENCODED.search(target_text):
            matched_rules.append("DOUBLE_ENCODING")
            highest_score = max(highest_score, 0.60)

        entropy = features.get("combined_entropy", 0.0)
        if isinstance(entropy, (int, float)) and entropy > 4.5:
            matched_rules.append("HIGH_ENTROPY_ANOMALY")
            highest_score = min(highest_score + 0.10, 1.0) if highest_score > 0 else 0.45

        # Classify severity based on composite threat score
        if highest_score >= 0.80:
            severity = "CRITICAL"
        elif highest_score >= 0.65:
            severity = "HIGH"
        elif highest_score >= 0.40:
            severity = "MEDIUM"
        elif highest_score > 0:
            severity = "LOW"
        else:
            severity = "INFO"

        # Determine defense status:
        # If it was an intentional attack (e.g. from the fuzzer):
        # - Caught if threat score >= 0.60 or matched rules found
        # - Stealth Bypass if the attack succeeded but score < 0.60 (e.g. BOLA/IDOR logic flaws)
        if is_attack:
            if highest_score >= 0.60 or len(matched_rules) > 0:
                verdict = "CAUGHT_BY_AI"
            else:
                verdict = "STEALTH_BYPASS"
        else:
            verdict = "BENIGN_TRAFFIC"

        # Auto-generate contextual remediation advice
        remediation = cls._generate_remediation(matched_rules, test_type, verdict)

        return DefenseEvaluation(
            threat_score=round(highest_score, 2),
            severity=severity,
            defense_verdict=verdict,
            matched_rules=matched_rules,
            features=features,
            remediation_patch=remediation
        )

    @classmethod
    def _generate_remediation(cls, matched_rules: list[str], test_type: str, verdict: str) -> str:
        """
        Generate defensive code patches and mitigations.
        """
        if "SQL_INJECTION" in matched_rules or test_type == "sqli":
            return (
                "# Remediation: Parameterized Queries (FastAPI/SQLAlchemy)\n"
                "# DO NOT concatenate strings: db.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
                "# USE bound parameters:\n"
                "stmt = select(User).where(User.id == bindparam('uid'))\n"
                "result = db.execute(stmt, {'uid': user_input}).scalars().first()"
            )
        elif verdict == "STEALTH_BYPASS" or test_type == "idor":
            return (
                "# Remediation: Multi-Tenant Authorization Check (BOLA/IDOR)\n"
                "# Ensure resource ownership is checked against the authenticated user:\n"
                "def get_user_resource(resource_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):\n"
                "    resource = db.query(Order).filter(Order.id == resource_id, Order.owner_id == current_user.id).first()\n"
                "    if not resource:\n"
                "        raise HTTPException(status_code=404, detail='Resource not found')\n"
                "    return resource"
            )
        elif test_type == "rate_limit":
            return (
                "# Remediation: Rate Limiting with slowapi\n"
                "from slowapi import Limiter\n"
                "from slowapi.util import get_remote_address\n"
                "limiter = Limiter(key_func=get_remote_address)\n"
                "@router.get('/endpoint')\n"
                "@limiter.limit('20/minute')\n"
                "async def protected_endpoint(request: Request): ..."
            )
        elif test_type == "auth":
            return (
                "# Remediation: JWT Verification Enforcement\n"
                "# Enforce algorithm whitelist and signature validation:\n"
                "payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options={'verify_signature': True, 'verify_exp': True})"
            )
        return "Implement input validation using Pydantic schemas and strict typing."


"""Static-analysis metadata endpoints."""

from fastapi import APIRouter

from app.static_analysis.engine import ADVANCED_STATIC_ANALYZER_VERSION, RULESET_VERSION
from app.static_analysis.rules import CODE_RULES

router = APIRouter(prefix="/static-analysis", tags=["Static Analysis"])


@router.get("/rules")
def list_static_rules() -> dict:
    """Return public deterministic rule metadata without implementation secrets."""
    return {
        "analyzer_version": ADVANCED_STATIC_ANALYZER_VERSION,
        "ruleset_version": RULESET_VERSION,
        "rules": [
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "category": rule.category,
                "standards": {
                    "cwe": list(rule.cwe),
                    "maswe": list(rule.maswe),
                    "attack": list(rule.attack),
                },
            }
            for rule in CODE_RULES
        ],
        "limitations": [
            "Rule presence is deterministic static evidence; exploitability and runtime execution require validation."
        ],
    }

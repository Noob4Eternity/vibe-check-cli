"""Finding model — SHARED contract, frozen at minute 0."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import json


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: Severity) -> bool:
        return self == other or self.__lt__(other)


class Category(Enum):
    """Finding category types."""
    SECRET = "secret"
    HALLUCINATED_DEPENDENCY = "hallucinated_dependency"
    HALLUCINATED_IMPORT = "hallucinated_import"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    SAST = "sast"
    COMPLIANCE_GDPR = "compliance_gdpr"
    COMPLIANCE_SOC2 = "compliance_soc2"
    PROMPT_INJECTION = "prompt_injection"
    CODE_QUALITY = "code_quality"
    IAC_SECURITY = "iac_security"
    LLM_REVIEW = "llm_review"
    VIBE_FINGERPRINT = "vibe_fingerprint"
    FRAMEWORK_SPECIFIC = "framework_specific"
    COST_EFFICIENCY = "cost_efficiency"


# Map categories to scoring groups
CATEGORY_GROUP = {
    Category.SECRET: "secrets",
    Category.HALLUCINATED_DEPENDENCY: "dependencies",
    Category.VULNERABLE_DEPENDENCY: "dependencies",
    Category.SAST: "sast",
    Category.COMPLIANCE_GDPR: "compliance",
    Category.COMPLIANCE_SOC2: "compliance",
    Category.PROMPT_INJECTION: "prompt_injection",
    Category.CODE_QUALITY: "code_quality",
    Category.IAC_SECURITY: "iac_security",
    Category.LLM_REVIEW: "llm_review",
    Category.VIBE_FINGERPRINT: "code_quality",
    Category.COST_EFFICIENCY: "cost_efficiency",
}


@dataclass
class Finding:
    """A single audit finding."""
    title: str
    severity: Severity
    category: Category
    description: str
    remediation: str
    tool: str
    id: str = field(default_factory=lambda: f"VA-{uuid.uuid4().hex[:8].upper()}")
    file: Optional[str] = None
    line: Optional[int] = None
    ai_prompt: str = ""
    evidence: str = ""
    cwe: Optional[str] = None
    compliance_ref: Optional[str] = None
    confidence: float = 1.0

    def to_dict(self) -> dict:
        """Serialize to dict with enum values as strings."""
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        """Deserialize from dict."""
        data = data.copy()
        data["severity"] = Severity(data["severity"])
        data["category"] = Category(data["category"])
        return cls(**data)

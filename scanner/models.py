from enum import Enum
from datetime import datetime, timezone
from hashlib import sha256

from pydantic import BaseModel, Field
from scanner.redaction import redact_text, redact_url


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class Endpoint(BaseModel):
    url: str
    method: str
    path: str
    requires_auth: bool = False
    parameters: list[dict] = Field(default_factory=list)
    request_body_schema: dict | None = None
    response_schemas: dict | None = None
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    deprecated: bool = False
    security: list[dict] | None = None


class DiscoveryResult(BaseModel):
    endpoints: list[Endpoint]
    source: str
    specification_url: str | None = None
    attempts: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    def model_post_init(self, __context) -> None:
        self.specification_url = redact_url(self.specification_url)
        self.attempts = [redact_text(item) or item for item in self.attempts]


class Finding(BaseModel):
    severity: Severity
    title: str
    endpoint: str = "UNKNOWN"

    method: str = "UNKNOWN"

    owasp: str | None = None
    owasp_category: str | None = None
    description: str | None = None
    recommendation: str | None = None
    remediation: str | None = None
    confidence: str = "low"
    verification_status: str = "potential"
    evidence: str | None = None
    response_status: int | None = None
    check_id: str | None = None
    finding_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context) -> None:
        self.endpoint = redact_url(self.endpoint) or self.endpoint
        self.title = redact_text(self.title) or self.title
        self.description = redact_text(self.description)
        self.recommendation = redact_text(self.recommendation)
        self.remediation = redact_text(self.remediation)
        self.evidence = redact_text(self.evidence)
        if self.recommendation is None and self.remediation is not None:
            self.recommendation = self.remediation
        elif self.remediation is None and self.recommendation is not None:
            self.remediation = self.recommendation

        if self.owasp is None and self.owasp_category is not None:
            self.owasp = self.owasp_category
        elif self.owasp_category is None and self.owasp is not None:
            self.owasp_category = self.owasp
        if self.finding_id is None:
            identity = "|".join((self.check_id or "", self.title, self.endpoint, self.method, self.owasp or ""))
            self.finding_id = sha256(identity.encode("utf-8")).hexdigest()[:16]


class ScanResult(BaseModel):
    target: str
    endpoints_scanned: int
    findings: list[Finding]
    unreachable_endpoints: int = 0
    discovery_source: str = "Unknown"
    specification_url: str | None = None
    security_score: float = 100
    risk_level: str = "LOW"
    scan_mode: str = "passive"
    discovery_attempts: list[str] = Field(default_factory=list)
    discovery_limitations: list[str] = Field(default_factory=list)
    scan_status: str = "complete"
    scan_started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_completed_at: datetime | None = None
    errors: list[str] = Field(default_factory=list)

    def model_post_init(self, __context) -> None:
        self.target = redact_url(self.target) or self.target
        self.specification_url = redact_url(self.specification_url)
        self.discovery_attempts = [redact_text(item) or item for item in self.discovery_attempts]
        self.discovery_limitations = [redact_text(item) or item for item in self.discovery_limitations]
        self.errors = [redact_text(item) or item for item in self.errors]

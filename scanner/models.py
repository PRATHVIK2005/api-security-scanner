from enum import Enum
from pydantic import BaseModel


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
    parameters: list[dict] = []
    request_body_schema: dict | None = None
    response_schemas: dict | None = None
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: list[str] = []
    deprecated: bool = False
    security: list[dict] | None = None


class DiscoveryResult(BaseModel):
    endpoints: list[Endpoint]
    source: str
    specification_url: str | None = None
    


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

    def model_post_init(self, __context) -> None:
        if self.recommendation is None and self.remediation is not None:
            self.recommendation = self.remediation
        elif self.remediation is None and self.recommendation is not None:
            self.remediation = self.recommendation

        if self.owasp is None and self.owasp_category is not None:
            self.owasp = self.owasp_category
        elif self.owasp_category is None and self.owasp is not None:
            self.owasp_category = self.owasp


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
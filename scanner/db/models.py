from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_url = Column(String(1024), nullable=False)
    scan_date = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    security_score = Column(Float, nullable=False, default=100.0)
    risk_level = Column(String(50), nullable=False, default="LOW")
    scan_mode = Column(String(50), nullable=False, default="passive")
    findings_count = Column(Integer, nullable=False, default=0)
    endpoints_scanned = Column(Integer, nullable=False, default=0)
    unreachable_endpoints = Column(Integer, nullable=False, default=0)
    discovery_source = Column(String(50), nullable=True, default="Unknown")
    specification_url = Column(String(1024), nullable=True)
    scan_status = Column(String(20), nullable=False, default="complete", server_default="complete")
    scan_started_at = Column(DateTime, nullable=True)
    scan_completed_at = Column(DateTime, nullable=True)
    scan_errors = Column(Text, nullable=False, default="[]", server_default="[]")
    discovery_attempts = Column(Text, nullable=False, default="[]", server_default="[]")
    discovery_limitations = Column(Text, nullable=False, default="[]", server_default="[]")

    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="Finding.id",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target_url} score={self.security_score}>"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    severity = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    endpoint = Column(String(1024), nullable=False)
    method = Column(String(20), nullable=False, default="UNKNOWN")
    owasp = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    confidence = Column(String(20), nullable=False, default="low", server_default="low")
    verification_status = Column(String(30), nullable=False, default="potential", server_default="potential")
    evidence = Column(Text, nullable=True)
    response_status = Column(Integer, nullable=True)
    check_id = Column(String(100), nullable=True)
    finding_id = Column(String(64), nullable=True)
    finding_timestamp = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding id={self.id} scan_id={self.scan_id} severity={self.severity} title={self.title}>"

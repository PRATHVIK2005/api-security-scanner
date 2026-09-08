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

    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding id={self.id} scan_id={self.scan_id} severity={self.severity} title={self.title}>"

"""Scan history service layer for API Security Scanner."""

from datetime import datetime, timezone
from sqlalchemy.orm import Session, joinedload
from scanner.db.models import Scan, Finding
from scanner.db.session import get_session_factory
from scanner.models import ScanResult


def save_scan(
    result: ScanResult,
    mode: str = "passive",
    session: Session | None = None,
) -> Scan:
    """
    Persist a completed ScanResult and its findings to SQLite.
    Can accept an existing session or manage its own.
    """
    own_session = False
    if session is None:
        SessionLocal = get_session_factory()
        session = SessionLocal()
        own_session = True

    try:
        scan_record = Scan(
            target_url=result.target,
            scan_date=datetime.now(timezone.utc),
            security_score=float(result.security_score),
            risk_level=str(result.risk_level).upper(),
            scan_mode=str(mode).lower(),
            findings_count=len(result.findings),
            endpoints_scanned=int(getattr(result, "endpoints_scanned", 0)),
            unreachable_endpoints=int(getattr(result, "unreachable_endpoints", 0)),
            discovery_source=getattr(result, "discovery_source", "Unknown"),
            specification_url=getattr(result, "specification_url", None),
        )

        for item in result.findings:
            severity_str = (
                item.severity.value
                if hasattr(item.severity, "value")
                else str(item.severity)
            )
            finding_record = Finding(
                severity=severity_str.upper(),
                title=item.title,
                endpoint=item.endpoint,
                method=getattr(item, "method", "UNKNOWN") or "UNKNOWN",
                owasp=item.owasp,
                description=item.description,
                recommendation=item.recommendation,
            )
            scan_record.findings.append(finding_record)

        session.add(scan_record)
        session.commit()
        session.refresh(scan_record)
        return scan_record

    except Exception:
        session.rollback()
        raise
    finally:
        if own_session:
            session.close()


def get_all_scans(session: Session | None = None) -> list[Scan]:
    """Retrieve all scans ordered from newest to oldest."""
    own_session = False
    if session is None:
        SessionLocal = get_session_factory()
        session = SessionLocal()
        own_session = True

    try:
        return (
            session.query(Scan)
            .order_by(Scan.scan_date.desc(), Scan.id.desc())
            .all()
        )
    finally:
        if own_session:
            session.close()


def get_scan_by_id(scan_id: int, session: Session | None = None) -> Scan | None:
    """Retrieve a specific scan by its ID with all associated findings."""
    own_session = False
    if session is None:
        SessionLocal = get_session_factory()
        session = SessionLocal()
        own_session = True

    try:
        return (
            session.query(Scan)
            .options(joinedload(Scan.findings))
            .filter(Scan.id == scan_id)
            .first()
        )
    finally:
        if own_session:
            session.close()


def count_severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity level."""
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    for f in findings:
        sev = str(f.severity).upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts[sev] = 1
    return counts


def compare_scans(
    scan1_id: int,
    scan2_id: int,
    session: Session | None = None,
) -> dict | None:
    """
    Compare two scans and calculate score, findings, and severity differences.
    Returns comparison dictionary or None if either scan does not exist.
    """
    own_session = False
    if session is None:
        SessionLocal = get_session_factory()
        session = SessionLocal()
        own_session = True

    try:
        s1 = (
            session.query(Scan)
            .options(joinedload(Scan.findings))
            .filter(Scan.id == scan1_id)
            .first()
        )
        s2 = (
            session.query(Scan)
            .options(joinedload(Scan.findings))
            .filter(Scan.id == scan2_id)
            .first()
        )

        if not s1 or not s2:
            return None

        score_diff = round(float(s2.security_score) - float(s1.security_score), 1)
        findings_diff = int(s2.findings_count) - int(s1.findings_count)

        s1_counts = count_severity_breakdown(s1.findings)
        s2_counts = count_severity_breakdown(s2.findings)

        severity_diff = {
            "CRITICAL": s2_counts.get("CRITICAL", 0) - s1_counts.get("CRITICAL", 0),
            "HIGH": s2_counts.get("HIGH", 0) - s1_counts.get("HIGH", 0),
            "MEDIUM": s2_counts.get("MEDIUM", 0) - s1_counts.get("MEDIUM", 0),
            "LOW": s2_counts.get("LOW", 0) - s1_counts.get("LOW", 0),
        }

        # Determine overall security status
        if score_diff > 0 or (score_diff == 0 and findings_diff < 0):
            status = "IMPROVED"
            status_text = "Security posture has improved."
        elif score_diff < 0 or (score_diff == 0 and findings_diff > 0):
            status = "WORSENED"
            status_text = "Security posture has worsened."
        else:
            status = "UNCHANGED"
            status_text = "Security posture is unchanged."

        return {
            "scan1": s1,
            "scan2": s2,
            "score_diff": score_diff,
            "findings_diff": findings_diff,
            "scan1_severity": s1_counts,
            "scan2_severity": s2_counts,
            "severity_diff": severity_diff,
            "status": status,
            "status_text": status_text,
        }
    finally:
        if own_session:
            session.close()

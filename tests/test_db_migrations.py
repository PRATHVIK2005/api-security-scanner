from datetime import datetime, timezone

from sqlalchemy import create_engine, inspect, text

from scanner.db.session import init_db
from scanner.history import get_scan_by_id, save_scan
from scanner.models import Finding, ScanResult, Severity


def test_additive_sqlite_migration_preserves_legacy_scan_and_finding():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(
            text("""
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY, target_url VARCHAR(1024) NOT NULL,
                scan_date DATETIME NOT NULL, security_score FLOAT NOT NULL,
                risk_level VARCHAR(50) NOT NULL, scan_mode VARCHAR(50) NOT NULL,
                findings_count INTEGER NOT NULL, endpoints_scanned INTEGER NOT NULL,
                unreachable_endpoints INTEGER NOT NULL, discovery_source VARCHAR(50),
                specification_url VARCHAR(1024)
            )
        """)
        )
        connection.execute(
            text("""
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, severity VARCHAR(50) NOT NULL,
                title VARCHAR(255) NOT NULL, endpoint VARCHAR(1024) NOT NULL,
                method VARCHAR(20) NOT NULL, owasp VARCHAR(255), description TEXT, recommendation TEXT
            )
        """)
        )
        connection.execute(
            text("""
            INSERT INTO scans VALUES (1, 'http://127.0.0.1', :date, 90, 'LOW', 'passive', 1, 1, 0, 'legacy', NULL)
        """),
            {"date": datetime.now(timezone.utc)},
        )
        connection.execute(
            text("""
            INSERT INTO findings VALUES (1, 1, 'LOW', 'Old finding', 'http://127.0.0.1/x', 'GET', NULL, NULL, NULL)
        """)
        )

    init_db(engine)
    scan_columns = {column["name"] for column in inspect(engine).get_columns("scans")}
    finding_columns = {column["name"] for column in inspect(engine).get_columns("findings")}
    assert {"scan_status", "scan_errors", "scan_started_at"} <= scan_columns
    assert {"confidence", "verification_status", "finding_id", "evidence"} <= finding_columns
    scan = get_scan_by_id(
        1, session=__import__("sqlalchemy.orm", fromlist=["sessionmaker"]).sessionmaker(bind=engine)()
    )
    assert scan.target_url == "http://127.0.0.1"
    assert scan.findings[0].title == "Old finding"
    assert scan.scan_status == "complete"
    engine.dispose()


def test_scan_review_metadata_survives_history_round_trip():
    engine = create_engine("sqlite:///:memory:")
    init_db(engine)
    from sqlalchemy.orm import sessionmaker

    session = sessionmaker(bind=engine)()
    result = ScanResult(
        target="http://127.0.0.1",
        endpoints_scanned=1,
        findings=[
            Finding(
                severity=Severity.MEDIUM,
                title="Potential risk",
                endpoint="http://127.0.0.1/object",
                confidence="low",
                verification_status="potential",
                evidence="Authorization: Bearer abc.def.ghi",
                check_id="test.check",
            )
        ],
        scan_status="partial",
        scan_started_at=datetime.now(timezone.utc),
        scan_completed_at=datetime.now(timezone.utc),
        errors=["GET endpoint: request failed (ConnectError)"],
        discovery_attempts=["http://127.0.0.1/openapi.json: HTTP 404"],
        discovery_limitations=["Fallback coverage is incomplete."],
    )
    saved = save_scan(result, session=session)
    loaded = get_scan_by_id(saved.id, session=session)
    assert loaded.scan_status == "partial"
    assert "ConnectError" in loaded.scan_errors
    assert "HTTP 404" in loaded.discovery_attempts
    assert loaded.findings[0].confidence == "low"
    assert loaded.findings[0].verification_status == "potential"
    assert "abc.def.ghi" not in (loaded.findings[0].evidence or "")
    assert loaded.findings[0].finding_id == result.findings[0].finding_id
    session.close()
    engine.dispose()

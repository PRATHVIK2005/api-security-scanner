import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from scanner.engine import scan
from scanner.models import Finding as ModelFinding, ScanMode, ScanResult, Severity
from scanner.db.session import init_db
from scanner.history import save_scan, get_all_scans, get_scan_by_id, compare_scans
from scanner.reports.json_report import generate_json_report
from scanner.reports.html_report import generate_html_report
from scanner.reports.pdf_report import generate_pdf_report
from scanner.validation import validate_target_url, InvalidURLError

logger = logging.getLogger("api_security_scanner.web")


def scan_record_to_result(scan_record) -> ScanResult:
    """Convert an existing SQLite Scan record with findings into a ScanResult model for report generation."""
    findings = []
    for f in scan_record.findings:
        sev_str = str(f.severity).upper() if f.severity else "INFO"
        try:
            sev_enum = Severity(sev_str)
        except ValueError:
            sev_enum = Severity.INFO

        findings.append(
            ModelFinding(
                severity=sev_enum,
                title=f.title,
                endpoint=f.endpoint,
                method=f.method or "UNKNOWN",
                owasp=f.owasp,
                description=f.description,
                recommendation=f.recommendation,
            )
        )

    endpoints_scanned = getattr(scan_record, "endpoints_scanned", 0)
    if not endpoints_scanned:
        unique_endpoints = len(set(f.endpoint for f in scan_record.findings))
        endpoints_scanned = unique_endpoints if unique_endpoints > 0 else 1

    discovery_src = getattr(scan_record, "discovery_source", None) or f"Database Archive (Scan #{scan_record.id})"
    spec_url = getattr(scan_record, "specification_url", None)
    unreachable = getattr(scan_record, "unreachable_endpoints", 0)
    scan_mode = getattr(scan_record, "scan_mode", "passive")

    return ScanResult(
        target=scan_record.target_url,
        endpoints_scanned=endpoints_scanned,
        findings=findings,
        unreachable_endpoints=unreachable,
        discovery_source=discovery_src,
        specification_url=spec_url,
        security_score=scan_record.security_score,
        risk_level=scan_record.risk_level,
        scan_mode=scan_mode,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database and tables exist
    try:
        init_db()
    except Exception as e:
        logger.error(f"Error initializing SQLite database: {e}")
    yield


app = FastAPI(
    title="API Security Scanner",
    description="OWASP API Security Scanner for Developers",
    lifespan=lifespan,
)



app.mount(
    "/static",
    StaticFiles(directory="web/static"),
    name="static",
)

templates = Jinja2Templates(
    directory="web/templates",
)


@app.get(
    "/",
    response_class=HTMLResponse,
)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={},
    )


@app.post(
    "/scan",
    response_class=HTMLResponse,
)
def run_scan(
    request: Request,
    url: str = Form(...),
    mode: str = Form("passive"),
    token: str | None = Form(None),
):
    try:
        validated_url = validate_target_url(url)
    except InvalidURLError as e:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "selected_url": url,
                "selected_mode": mode,
                "error": str(e),
            },
        )

    try:
        scan_mode = ScanMode(mode.lower())
    except ValueError:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "selected_url": url,
                "selected_mode": mode,
                "error": (
                    f"Invalid scan mode '{mode}'. "
                    "Use 'passive' or 'active'."
                ),
            },
        )

    clean_token = (
        token.strip()
        if token and token.strip()
        else None
    )

    # Security: track only whether a token was supplied.
    # Never echo the raw token back to the user.
    token_provided = clean_token is not None

    try:
        result = scan(
            url=validated_url,
            mode=scan_mode,
            token=clean_token,
        )

    except Exception:
        logger.exception(
            "Scan failed for target: %s",
            url,
        )

        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "selected_url": url,
                "selected_mode": mode,
                "error": (
                    "The scan could not be completed. "
                    "Please verify the target and try again."
                ),
            },
            status_code=500,
        )

    # Persist scan result to SQLite history
    saved_scan_id = None

    try:
        saved_scan = save_scan(
            result,
            mode=scan_mode.value,
        )
        saved_scan_id = saved_scan.id

    except Exception:
        logger.exception(
            "Database error while saving scan result"
        )

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "result": result,
            "selected_url": url,
            "selected_mode": mode,
            # Never pass the raw token back.
            "token_provided": token_provided,
            "saved_scan_id": saved_scan_id,
        },
    )


@app.get(
    "/history",
    response_class=HTMLResponse,
)
def view_history(request: Request):
    scans = get_all_scans()
    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={
            "scans": scans,
        },
    )


@app.get(
    "/history/{scan_id}",
    response_class=HTMLResponse,
)
def view_scan_details(request: Request, scan_id: int):
    scan_record = get_scan_by_id(scan_id)
    if not scan_record:
        raise HTTPException(
            status_code=404,
            detail=f"Scan with ID {scan_id} not found in database.",
        )

    return templates.TemplateResponse(
        request=request,
        name="scan_details.html",
        context={
            "scan": scan_record,
        },
    )


@app.get("/history/{scan_id}/export/{export_format}")
def export_scan_report(scan_id: int, export_format: str):
    scan_record = get_scan_by_id(scan_id)
    if not scan_record:
        raise HTTPException(
            status_code=404,
            detail=f"Scan with ID {scan_id} not found in database.",
        )

    scan_result = scan_record_to_result(scan_record)
    fmt = export_format.lower().strip()

    if fmt == "pdf":
        pdf_bytes = generate_pdf_report(scan_result)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="scan_{scan_id}_report.pdf"'
            },
        )
    elif fmt == "html":
        html_content = generate_html_report(scan_result)
        return Response(
            content=html_content,
            media_type="text/html; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="scan_{scan_id}_report.html"'
            },
        )
    elif fmt == "json":
        json_content = generate_json_report(scan_result)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="scan_{scan_id}_report.json"'
            },
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format '{export_format}'. Supported formats: pdf, html, json.",
        )


@app.get(
    "/compare",
    response_class=HTMLResponse,
)
def compare_scans_route(
    request: Request,
    scan1: int = Query(..., description="First scan ID to compare"),
    scan2: int = Query(..., description="Second scan ID to compare"),
):
    comparison = compare_scans(scan1, scan2)
    if not comparison:
        raise HTTPException(
            status_code=404,
            detail=f"Could not compare scans #{scan1} and #{scan2}. One or both scans do not exist.",
        )

    return templates.TemplateResponse(
        request=request,
        name="compare.html",
        context={
            "comparison": comparison,
        },
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "API Security Scanner Dashboard",
    }
import logging
import ipaddress
import threading
import time
import json
import hmac
import os
import secrets
from datetime import datetime, timezone
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form, HTTPException, Query, Response, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from urllib.parse import urlparse

from scanner.engine import scan
from scanner.models import Finding as ModelFinding, ScanMode, ScanResult, Severity
from scanner.db.session import init_db
from scanner.history import save_scan, get_all_scans, get_scan_by_id, compare_scans
from scanner.reports.json_report import generate_json_report
from scanner.reports.html_report import generate_html_report
from scanner.reports.pdf_report import generate_pdf_report
from scanner.reports.sarif_report import generate_sarif_report
from scanner.validation import validate_target_url, InvalidURLError
from scanner.redaction import redact_text, redact_url

logger = logging.getLogger("api_security_scanner.web")
_scan_slots = threading.BoundedSemaphore(1)
_scan_times: dict[str, deque[float]] = defaultdict(deque)
_scan_rate_lock = threading.Lock()


def _dashboard_target_allowed(url: str) -> bool:
    """The dashboard is intentionally restricted to loopback targets."""
    hostname = (urlparse(url).hostname or "").lower()
    try:
        is_loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = False
    return is_loopback


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
                confidence=getattr(f, "confidence", "low") or "low",
                verification_status=getattr(f, "verification_status", "potential") or "potential",
                evidence=getattr(f, "evidence", None),
                response_status=getattr(f, "response_status", None),
                check_id=getattr(f, "check_id", None),
                finding_id=getattr(f, "finding_id", None),
                timestamp=getattr(f, "finding_timestamp", None) or datetime.now(timezone.utc),
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
        scan_status=getattr(scan_record, "scan_status", "complete") or "complete",
        scan_started_at=getattr(scan_record, "scan_started_at", None) or scan_record.scan_date,
        scan_completed_at=getattr(scan_record, "scan_completed_at", None) or scan_record.scan_date,
        errors=_json_list(getattr(scan_record, "scan_errors", "[]")),
        discovery_attempts=_json_list(getattr(scan_record, "discovery_attempts", "[]")),
        discovery_limitations=_json_list(getattr(scan_record, "discovery_limitations", "[]")),
    )


def _json_list(value: str | None) -> list[str]:
    try:
        loaded = json.loads(value or "[]")
        return [(redact_text(str(item)) or str(item)) for item in loaded] if isinstance(loaded, list) else []
    except (TypeError, ValueError):
        return []


def _sanitize_scan_record_for_display(scan_record) -> None:
    """Redact records created by pre-hardening versions before rendering history."""
    scan_record.target_url = redact_url(scan_record.target_url) or scan_record.target_url
    for finding in scan_record.findings:
        finding.endpoint = redact_url(finding.endpoint) or finding.endpoint
        for field in ("title", "description", "recommendation", "evidence"):
            value = getattr(finding, field, None)
            if value is not None:
                setattr(finding, field, redact_text(value))


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
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("API_SCANNER_DASHBOARD_SESSION_SECRET") or secrets.token_urlsafe(48),
    session_cookie="api_scanner_session",
    max_age=1800,
    same_site="strict",
    https_only=os.getenv("API_SCANNER_DASHBOARD_HTTPS", "0") == "1",
)

_login_attempts: dict[str, deque[float]] = defaultdict(deque)
_login_rate_lock = threading.Lock()


def _auth_configured() -> bool:
    username = os.getenv("API_SCANNER_DASHBOARD_USERNAME", "")
    password = os.getenv("API_SCANNER_DASHBOARD_PASSWORD", "")
    session_secret = os.getenv("API_SCANNER_DASHBOARD_SESSION_SECRET", "")
    return bool(
        username
        and len(username) <= 128
        and len(password) >= 12
        and len(password) <= 1024
        and len(session_secret) >= 32
    )


def require_auth(request: Request):
    issued = request.session.get("authenticated_at")
    if not _auth_configured() or not isinstance(issued, int) or int(time.time()) - issued > 1800:
        raise HTTPException(status_code=401, detail="Authentication required.")


async def require_csrf(request: Request):
    require_auth(request)
    token = request.headers.get("x-csrf-token")
    if not token:
        form = await request.form()
        token = str(form.get("csrf_token", ""))
    if not token or not hmac.compare_digest(token, str(request.session.get("csrf_token", ""))):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")


@app.middleware("http")
async def enforce_local_dashboard(request: Request, call_next):
    """Deny non-loopback clients and browser cross-site scan submissions."""
    client_host = request.client.host if request.client else ""
    try:
        if not ipaddress.ip_address(client_host).is_loopback:
            return JSONResponse({"detail": "Dashboard is local-only."}, status_code=403)
    except ValueError:
        return JSONResponse({"detail": "Dashboard client address is invalid."}, status_code=403)

    if request.url.path == "/scan" and request.method == "POST":
        fetch_site = request.headers.get("sec-fetch-site", "").lower()
        origin = request.headers.get("origin")
        if not origin:
            return JSONResponse({"detail": "Same-origin header is required for scan submissions."}, status_code=403)
        if fetch_site in {"cross-site", "same-site"}:
            return JSONResponse({"detail": "Cross-site scan submissions are not allowed."}, status_code=403)
        if origin:
            origin_host = urlparse(origin).netloc.lower()
            host_header = request.headers.get("host", "").lower()
            if not origin_host or origin_host != host_header:
                return JSONResponse({"detail": "Cross-origin scan submissions are not allowed."}, status_code=403)

        now = time.monotonic()
        with _scan_rate_lock:
            recent = _scan_times[client_host]
            while recent and now - recent[0] > 60:
                recent.popleft()
            if len(recent) >= 10:
                return JSONResponse({"detail": "Scan submission rate limit reached."}, status_code=429)
            recent.append(now)

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    if request.url.path == "/login" and request.method == "POST" and response.status_code < 400:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


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
    dependencies=[Depends(require_auth)],
)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"csrf_token": request.session.get("csrf_token", "")},
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if not request.session.get("csrf_token"):
        request.session["csrf_token"] = secrets.token_urlsafe(32)
    csrf_token = request.session["csrf_token"]
    return HTMLResponse(f"""<!doctype html><title>API Scanner Login</title><form method='post'>
      <input type='hidden' name='csrf_token' value='{csrf_token}'>
      <label>Username <input name='username' autocomplete='username' required></label>
      <label>Password <input type='password' name='password' autocomplete='current-password' required></label>
      <button type='submit'>Sign in</button></form>""")


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...)):
    current_csrf = str(request.session.get("csrf_token", ""))
    if not current_csrf or not hmac.compare_digest(csrf_token, current_csrf):
        return HTMLResponse("Login request rejected.", status_code=403, headers={"Cache-Control": "no-store"})
    host = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _login_rate_lock:
        recent = _login_attempts[host]
        while recent and now - recent[0] > 60:
            recent.popleft()
        if len(recent) >= 5:
            return HTMLResponse("Login rate limit reached.", status_code=429)
        recent.append(now)
    expected_user = os.getenv("API_SCANNER_DASHBOARD_USERNAME", "")
    expected_password = os.getenv("API_SCANNER_DASHBOARD_PASSWORD", "")
    user_matches = hmac.compare_digest(username, expected_user)
    password_matches = hmac.compare_digest(password, expected_password)
    valid = _auth_configured() & user_matches & password_matches
    if not valid:
        return HTMLResponse("Invalid credentials.", status_code=401, headers={"Cache-Control": "no-store"})
    request.session.clear()
    request.session["authenticated_at"] = int(time.time())
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    response = Response(status_code=303, headers={"Location": "/", "Cache-Control": "no-store"})
    return response


@app.post("/logout", dependencies=[Depends(require_csrf)])
def logout(request: Request):
    request.session.clear()
    return Response(status_code=303, headers={"Location": "/login", "Cache-Control": "no-store"})


@app.post(
    "/scan",
    response_class=HTMLResponse,
    dependencies=[Depends(require_csrf)],
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
                "csrf_token": request.session.get("csrf_token", ""),
                "selected_url": redact_url(url) or "",
                "selected_mode": mode,
                "error": str(e),
            },
        )

    if not _dashboard_target_allowed(validated_url):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "csrf_token": request.session.get("csrf_token", ""),
                "selected_url": redact_url(url) or "",
                "selected_mode": mode,
                "error": "Dashboard scans are restricted to loopback targets. Remote dashboard scanning is disabled.",
            },
            status_code=403,
        )

    try:
        scan_mode = ScanMode(mode.lower())
    except ValueError:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "csrf_token": request.session.get("csrf_token", ""),
                "selected_url": redact_url(url) or "",
                "selected_mode": mode,
                "error": (f"Invalid scan mode '{mode}'. Use 'passive' or 'active'."),
            },
        )

    clean_token = token.strip() if token and token.strip() else None

    # Security: track only whether a token was supplied.
    # Never echo the raw token back to the user.
    token_provided = clean_token is not None

    if not _scan_slots.acquire(blocking=False):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "csrf_token": request.session.get("csrf_token", ""),
                "selected_url": redact_url(url) or "",
                "selected_mode": mode,
                "error": "Another scan is already running.",
            },
            status_code=429,
        )

    try:
        result = scan(
            url=validated_url,
            mode=scan_mode,
            token=clean_token,
        )

    except Exception as exc:
        logger.error("Scan failed for target %s (%s)", redact_url(url), type(exc).__name__)

        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "csrf_token": request.session.get("csrf_token", ""),
                "selected_url": redact_url(url) or "",
                "selected_mode": mode,
                "error": ("The scan could not be completed. Please verify the target and try again."),
            },
            status_code=500,
        )
    finally:
        _scan_slots.release()

    # Persist scan result to SQLite history
    saved_scan_id = None

    try:
        saved_scan = save_scan(
            result,
            mode=scan_mode.value,
        )
        saved_scan_id = saved_scan.id

    except Exception:
        logger.error("Database error while saving scan result")

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "csrf_token": request.session.get("csrf_token", ""),
            "result": result,
            "selected_url": redact_url(url) or "",
            "selected_mode": mode,
            # Never pass the raw token back.
            "token_provided": token_provided,
            "saved_scan_id": saved_scan_id,
        },
    )


@app.get(
    "/history",
    response_class=HTMLResponse,
    dependencies=[Depends(require_auth)],
)
def view_history(request: Request):
    scans = get_all_scans()
    for scan_record in scans:
        _sanitize_scan_record_for_display(scan_record)
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
    dependencies=[Depends(require_auth)],
)
def view_scan_details(request: Request, scan_id: int):
    scan_record = get_scan_by_id(scan_id)
    if not scan_record:
        raise HTTPException(
            status_code=404,
            detail=f"Scan with ID {scan_id} not found in database.",
        )

    _sanitize_scan_record_for_display(scan_record)

    return templates.TemplateResponse(
        request=request,
        name="scan_details.html",
        context={
            "scan": scan_record,
            "scan_errors": _json_list(getattr(scan_record, "scan_errors", "[]")),
        },
    )


@app.get("/history/{scan_id}/export/{export_format}", dependencies=[Depends(require_auth)])
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
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.pdf"'},
        )
    elif fmt == "html":
        html_content = generate_html_report(scan_result)
        return Response(
            content=html_content,
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.html"'},
        )
    elif fmt == "json":
        json_content = generate_json_report(scan_result)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.json"'},
        )
    elif fmt == "sarif":
        sarif_content = generate_sarif_report(scan_result)
        return Response(
            content=sarif_content,
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.sarif"'},
        )
    else:
        raise HTTPException(
            status_code=400, detail=f"Invalid format '{export_format}'. Supported formats: pdf, html, json, sarif."
        )


@app.get(
    "/compare",
    response_class=HTMLResponse,
    dependencies=[Depends(require_auth)],
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

    _sanitize_scan_record_for_display(comparison["scan1"])
    _sanitize_scan_record_for_display(comparison["scan2"])

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

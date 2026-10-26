# API Security Scanner

A Python API assessment tool with a Typer CLI, a FastAPI dashboard, OpenAPI and manual endpoint discovery, SQLite scan history, and JSON, HTML, and PDF reports. The scanner performs bounded passive HTTP checks and a read-only active mode against APIs you own or are explicitly authorized to test.

> **Authorized use only.** Use the included local demo API or a controlled target. The scanner does not provide authorization to test a system. Do not scan public systems without written permission.

## Architecture and data flow

`cli/main.py` or `web/app.py` validates the target and passes it to `scanner/engine.py`. `scanner/discovery.py` first checks common OpenAPI locations (or a configured specification URL), then uses an optional user endpoint list, and otherwise scans only the base URL. Discovered operations flow through heuristic checks and bounded HTTP probes. Findings are deduplicated, scored, optionally saved in local SQLite, and rendered by the report generators.

## Install (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Python 3.10 or newer is required. Dependencies are declared in `pyproject.toml`; development dependencies include pytest, Ruff, and pip-audit.

## CLI

```powershell
api-scanner --help
api-scanner scan --help
api-scanner scan --url http://127.0.0.1:8001
api-scanner scan --url http://127.0.0.1:8001 --mode active
api-scanner scan --url http://127.0.0.1:8001 --token $env:API_TOKEN --header "X-Workspace: demo"
api-scanner scan --url http://127.0.0.1:8001 --format json --output .\scan.json
api-scanner scan --url http://127.0.0.1:8001 --format html --output .\scan.html
api-scanner scan --url http://127.0.0.1:8001 --format pdf --output .\scan.pdf
api-scanner scan --url http://127.0.0.1:8001 --format sarif --output .\scan.sarif
api-scanner scan --url http://127.0.0.1:8001 --spec-url http://127.0.0.1:8001/openapi.json
api-scanner scan --url http://127.0.0.1:8001 --endpoints .\endpoints.json
api-scanner history
api-scanner compare 1 2
```

Use `python main.py` instead of `api-scanner` if the package has not been installed. Use `--header "Name: Value"` once per custom header. Credentials are accepted as request headers or a bearer token and are not intentionally printed or stored. Avoid putting credentials in URLs. Output files may contain target URLs and findings, so protect them as assessment data.

### Manual endpoint list

JSON and YAML endpoint files are supported. Each entry has a required `path`, optional `method` (defaults to GET), and optional descriptive metadata. The scanner accepts an array or an object containing an `endpoints` array.

```json
{
  "endpoints": [
    {"method": "GET", "path": "/health", "summary": "Health check"},
    {"method": "GET", "path": "/users/{user_id}", "requires_auth": true}
  ]
}
```

Paths resolve against the supplied base URL. Absolute endpoint URLs must match the target origin. Only supported HTTP methods are accepted, duplicate method/path pairs are removed, and discovery is capped at 500 operations.

### Passive and active behavior

Passive mode sends requests for GET, HEAD, and OPTIONS operations. Active mode adds a small fixed burst (five read-only requests) for the rate-limit indicator. Even if the specification lists POST, PUT, PATCH, or DELETE operations, the scanner does not send them. Redirects are not followed. The scanner uses a peer-checked direct transport, disables environment proxies and compressed responses, validates DNS answers before connecting, and verifies the connected peer IP.

Requests default to public global IP destinations. For an explicitly authorized private test target, set a narrow CIDR before scanning; broad networks are rejected. Example for a local demo:

```powershell
$env:API_SCANNER_ALLOWED_CIDRS = '127.0.0.1/32'
```

Application DNS and peer checks should be backed by OS egress filtering. Example nftables policy for a dedicated Linux scanner network namespace (replace the documentation-only addresses with the one approved target and its resolver before loading; do not apply this sample to a shared host):

```nft
table inet scanner_egress {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    ip daddr 192.0.2.53 udp dport 53 accept
    ip daddr 192.0.2.53 tcp dport 53 accept
    ip daddr 198.51.100.23 tcp dport { 80, 443 } accept
  }
}
```

This permits DNS only to the selected resolver and HTTP(S) only to one fixed IPv4 target; all IPv6 egress remains blocked unless a separately approved destination rule is added. A fixed egress allowlist can stop a rebinding answer from reaching an alternate address even if application policy changes. Keep the scanner's `API_SCANNER_ALLOWED_CIDRS` narrow as well.

The scanner applies this policy to the target and OpenAPI requests. It does not follow redirects or fetch external `$ref` documents. It caps each response at 1 MB by default, request bodies at 64 KB, each scan at 5,000 requests, and total scan duration at 300 seconds. Limits can be adjusted with `API_SCANNER_CONNECT_TIMEOUT`, `API_SCANNER_READ_TIMEOUT`, `API_SCANNER_TOTAL_REQUEST_TIMEOUT`, `API_SCANNER_DNS_TIMEOUT`, `API_SCANNER_MAX_RESPONSE_BYTES`, `API_SCANNER_MAX_REQUEST_BYTES`, `API_SCANNER_MAX_REQUESTS_PER_SCAN`, and `API_SCANNER_MAX_SCAN_SECONDS`; values are validated and hard maxima apply. Compressed responses are refused to avoid unbounded decompression.

## Discovery and coverage

Common specification locations include `/openapi.json`, `/swagger.json`, `/api-docs`, `/v3/api-docs`, `/api/openapi.json`, and `/swagger/v1/swagger.json`. Use `--spec-url` for another same-origin location. A 404 at one location does not stop the remaining probes. Each attempt records an HTTP status, redirect refusal, malformed document, or empty-spec outcome in scan metadata. If no usable spec is found, fallback mode scans only the base URL and marks coverage as incomplete.

OpenAPI parsing retains methods, path and operation parameters, JSON request/response schemas, tags, deprecation, operation identifiers, and security metadata. Local JSON Pointer references are resolved with count and depth limits (`API_SCANNER_MAX_OPENAPI_REFS`, `API_SCANNER_MAX_OPENAPI_REF_DEPTH`; defaults 2,000 and 32). Cyclic, malformed, missing, and external references are retained as discovery limitations. External `$ref` documents are not fetched, including same-origin refs. OpenAPI callbacks/webhooks and server URL overrides are not followed.

## Checks and interpretation

Checks inspect authentication declarations, object identifiers, writable and returned properties, sensitive response patterns, token-like response content, CORS, security headers, information disclosure, rate-limit headers, selected sensitive path names, deprecated/versioned routes, SSRF-like input names, third-party integration indicators, and dangerous methods. They are partial indicators aligned with selected OWASP API Security Top 10 themes, not complete category coverage.

Most checks are heuristic. An object ID does not prove BOLA; a missing rate-limit header does not prove the absence of server-side throttling; an input named `url` does not prove SSRF; a sensitive-looking path does not prove broken function authorization. Findings carry confidence and verification status; review them in application context.

An opt-in read-only BOLA verification is available with `--bola-config`. Supply an explicit list of test identities and known object cases. Every identity has a read-only identity endpoint and expected identity marker. Every object case has a known owner marker and a role access matrix containing both an allowed positive-control role and a denied negative-control role. Only listed identity and object URLs are requested; IDs are never enumerated.

```json
{
  "identities": [
    {
      "id": "owner-test",
      "role": "owner",
      "token": "<owner-test-token>",
      "identity_url": "http://127.0.0.1:8001/me",
      "identity_json_path": "id",
      "expected_identity": "test-user-1"
    },
    {
      "id": "viewer-test",
      "role": "viewer",
      "token": "<viewer-test-token>",
      "identity_url": "http://127.0.0.1:8001/me",
      "identity_json_path": "id",
      "expected_identity": "test-user-2"
    }
  ],
  "objects": [
    {
      "case_id": "invoice-1-owner-policy",
      "object_type": "invoice",
      "object_url": "http://127.0.0.1:8001/invoices/known-test-object",
      "owner_json_path": "owner.id",
      "expected_owner": "test-user-1",
      "access_rules": {"owner": "allow", "viewer": "deny"}
    }
  ]
}
```

Keep this file out of Git and restrict its filesystem permissions. All identity and object URLs must share the target origin. Configs allow up to 20 identities and 50 object cases; each case requires at least one `allow` and one `deny` role, and an allowed identity must match the configured owner marker. Each configured identity is independently authenticated before the object requests. All requests use GET, redirects are not followed, tokens and response bodies are not retained, and 401, unexpected status codes, missing ownership data, and other ambiguous outcomes are inconclusive. The legacy one-object config remains readable as one explicit case. This verifies only listed objects, identities, roles, and rules; it does not establish general BOLA coverage.

The 0–100 score is a deterministic severity-weighted risk indicator: critical/high/medium/low findings use documented penalties in `scanner/scoring.py`, capped per severity group and at the 0–100 range. It is not a security certification. In particular, a high score or empty report does not establish that an API is secure; endpoint discovery may be incomplete and many controls are untested.

## Dashboard and history

Start the local demo API and dashboard in separate PowerShell windows:

```powershell
$env:API_SCANNER_ALLOWED_CIDRS = '127.0.0.1/32'
uvicorn demo_api.main:app --host 127.0.0.1 --port 8001
```

In a second PowerShell window:

```powershell
$env:API_SCANNER_ALLOWED_CIDRS = '127.0.0.1/32'
uvicorn web.app:app --host 127.0.0.1 --port 8000
```

Set the CIDR variable in the window that runs the scanner or dashboard. If the variable is unset, the local demo's loopback address is blocked by the outbound policy.

Open `http://127.0.0.1:8000` and sign in with the configured account. The dashboard supports scan submission, history, scan detail, comparisons, and JSON/HTML/PDF/SARIF exports. SQLite is initialized on application startup and local history is stored under `data/scanner.db`.

The dashboard uses signed, expiring cookie sessions and CSRF tokens. Configure `API_SCANNER_DASHBOARD_USERNAME`, `API_SCANNER_DASHBOARD_PASSWORD` (at least 12 characters), and `API_SCANNER_DASHBOARD_SESSION_SECRET` (at least 32 characters) before starting it. Missing or malformed credentials fail closed. Login and scan submissions are rate limited. Keep it bound to `127.0.0.1`; remote access remains unsupported and disabled. Do not expose it through a reverse proxy or public interface. The scanner's outbound address policy remains in force for dashboard scans.

```powershell
$env:API_SCANNER_DASHBOARD_USERNAME = 'scanner-admin'
$env:API_SCANNER_DASHBOARD_PASSWORD = '<set from a secret manager>'
$env:API_SCANNER_DASHBOARD_SESSION_SECRET = '<long random secret>'
$env:API_SCANNER_DASHBOARD_HTTPS = '0' # set to 1 only when serving HTTPS directly
uvicorn web.app:app --host 127.0.0.1 --port 8000
```

## Reports

Supported formats are terminal output plus JSON, standalone HTML, PDF, and SARIF 2.1.0. HTML and PDF escape untrusted report text. SARIF preserves rule IDs, severity, confidence, verification status, stable fingerprints, and reliable request URI locations. SARIF includes the scan's partial or interrupted status. It does not mean every heuristic finding has been verified. Finding evidence and URL query values with common secret names are redacted, but reports and database history still contain target and finding information and should be handled as sensitive. Tests validate SARIF documents against the OASIS 2.1.0 schema fixture in `tests/data/`.

## Test and quality commands

```powershell
python -m pytest -q
ruff check .
ruff format --check .
pip-audit
```

Pytest's default temporary folder can be overridden in restricted Windows environments:

```powershell
python -m pytest -q --basetemp=.pytest-tmp
```

CI runs tests on Python 3.12 and 3.13, imports the dashboard, checks installed dependencies, runs Ruff lint and format checks, and audits dependencies. Release automation runs those checks before generating sample HTML/PDF reports. Local command results do not imply that a remote GitHub Actions workflow has run.

## Limitations and responsible use

- BOLA verification covers only the configured objects, supplied identities, roles, and access matrix. It does not establish general authorization correctness or detect unlisted object identifiers.
- No general authorization verification, business-logic proof, exploit payloads, or destructive testing.
- No unrestricted crawling or endpoint guessing; fallback discovery covers only the base URL.
- Public global addresses are allowed by default when explicitly supplied as targets; this is not a hostname allowlist. Use the scanner only for authorized systems. Private/internal destinations require a narrowly scoped `API_SCANNER_ALLOWED_CIDRS` exception.
- Hostname resolution and HTTP worker submissions use fixed pools with bounded queues and absolute request deadlines. A resolver stuck in the operating system retains one bounded slot until it returns; additional work fails closed. Application checks do not replace OS or network egress restrictions.
- The dashboard is local-only. Remote deployment is unsupported; authentication does not make public exposure safe. Use OS account isolation where local multi-user access is a concern.
- The scanner does not replace manual testing, code review, threat modeling, or a professional assessment.

## Demo API

The included `demo_api` application is intentionally vulnerable and should remain bound to loopback. Set `API_SCANNER_ALLOWED_CIDRS=127.0.0.1/32` in the scanner's PowerShell window, run `uvicorn demo_api.main:app --host 127.0.0.1 --port 8001` in another window, then scan `http://127.0.0.1:8001`.

## Resume description (verified scope)

Built a Python API security scanner with OpenAPI/manual endpoint discovery, peer-checked bounded HTTP requests, passive and read-only active checks, heuristic OWASP API risk indicators, an opt-in two-identity BOLA comparison, CLI and loopback-only FastAPI interfaces, additive SQLite history migrations, and JSON/HTML/PDF reporting with redacted evidence.

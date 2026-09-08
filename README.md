# 🔐 API Security Scanner

An automated **OWASP API Security Scanner** designed to help developers identify common security weaknesses in REST APIs.

The scanner supports automated API endpoint discovery, passive and active security scanning, authenticated scans, security scoring, multiple report formats, scan history, and a web dashboard.

> ⚠️ **Authorized Use Only:** Only scan APIs that you own or have explicit permission to test.

---

## 🚀 Features

### 🔍 API Endpoint Discovery

- Automatic OpenAPI/Swagger endpoint discovery
- Supports common specification paths:
  - `/openapi.json`
  - `/swagger.json`
  - `/api-docs`
- Falls back to the provided URL when no API specification is found
- Discovers supported HTTP methods
- Detects authentication requirements from API specifications

---

## 🛡️ Security Checks

The scanner performs checks for multiple API security risks, including:

- Missing authentication
- Broken Object Level Authorization (BOLA) risks
- Broken Object Property Level Authorization risks
- Sensitive data exposure
- JWT exposure
- API key exposure
- Token security issues
- Overly permissive CORS policies
- Missing security headers
- Server technology information disclosure
- Exposed administrative endpoints
- Exposed debug endpoints
- Deprecated API endpoints
- Outdated API versions
- Missing rate limiting
- Active rate-limiting testing
- Unsafe API consumption
- SSRF-related risks
- Input validation issues
- Business flow risks

---

# 🔄 Scan Modes

## Passive Mode

Passive mode performs non-destructive security checks using safe HTTP requests.

```bash
api-scanner scan --url http://127.0.0.1:8000
````

---

## Active Mode

Active mode performs additional security testing.

```bash
api-scanner scan --url http://127.0.0.1:8000 --mode active
```

> ⚠️ Active scanning should only be used against APIs you own or are authorized to test.

---

# 🔑 Authenticated Scanning

The scanner supports Bearer token authentication.

```bash
api-scanner scan \
  --url http://127.0.0.1:8000 \
  --token YOUR_BEARER_TOKEN
```

This allows security testing of protected API endpoints.

---

# 📦 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/api-security-scanner.git
cd api-security-scanner
```

Replace `YOUR_USERNAME` with your GitHub username.

---

## 2. Create a Virtual Environment

### Windows PowerShell

```powershell
python -m venv venv
venv\Scripts\Activate
```

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -e .
```

For development dependencies:

```bash
pip install -e ".[dev]"
```

---

# 💻 CLI Usage

## Basic Scan

```bash
api-scanner scan --url http://127.0.0.1:8000
```

Example output:

```text
API Security Scan Results

Target: http://127.0.0.1:8000
Discovery Source: OpenAPI
Endpoints Scanned: 10
Unreachable: 0
Findings: 67

Security Score: 0.0/100
Risk Level: CRITICAL
```

---

## Active Scan

```bash
api-scanner scan \
  --url http://127.0.0.1:8000 \
  --mode active
```

---

## Authenticated Scan

```bash
api-scanner scan \
  --url http://127.0.0.1:8000 \
  --token YOUR_BEARER_TOKEN
```

---

# 📊 Report Formats

## Terminal Report

```bash
api-scanner scan --url http://127.0.0.1:8000
```

---

## JSON Report

```bash
api-scanner scan \
  --url http://127.0.0.1:8000 \
  --format json
```

Save the report to a file:

```bash
api-scanner scan \
  --url http://127.0.0.1:8000 \
  --format json \
  --output report.json
```

---

## HTML Report

The project supports generating HTML security reports.

---

## PDF Report

The project supports generating PDF security reports.

---

# 🌐 Web Dashboard

The project includes a FastAPI-based web dashboard.

Run the application:

```bash
uvicorn web.app:app --reload
```

Then open:

```text
http://127.0.0.1:8000
```

The dashboard allows you to:

* Enter an API URL
* Select passive or active scan mode
* Perform authenticated scans
* Start security scans
* View security findings
* View severity information
* View security scores
* Export reports
* View scan history

---

# 📈 Security Score

The scanner calculates a security score based on the detected findings and their severity.

```text
0 ─────────────────────────────── 100
Critical                           Secure
```

Example:

```text
Security Score: 18.0/100
Risk Level: CRITICAL
```

---

# 🚨 Severity Levels

| Severity    | Description                        |
| ----------- | ---------------------------------- |
| 🔴 CRITICAL | Immediate and severe security risk |
| 🟠 HIGH     | Significant security vulnerability |
| 🟡 MEDIUM   | Important security weakness        |
| 🔵 LOW      | Lower-risk security issue          |
| ℹ️ INFO     | Informational finding              |

---

# 🛡️ OWASP API Security Coverage

The scanner includes automated checks related to major OWASP API security risks.

Current coverage includes areas such as:

* API authorization weaknesses
* Authentication weaknesses
* Object-level access risks
* Object property authorization risks
* Resource consumption and rate limiting
* Sensitive business flow risks
* SSRF-related risks
* Security misconfiguration
* Unsafe API consumption

> **Note:** Not every API vulnerability can be reliably detected automatically. Some security issues require manual testing, application-specific context, and professional security review.

---

# 📁 Project Structure

```text
api-security-scanner/
│
├── scanner/
│   ├── checks/
│   │   ├── active_rate_limiting.py
│   │   ├── api_versioning.py
│   │   ├── authentication.py
│   │   ├── bola.py
│   │   ├── business_flow.py
│   │   ├── cors.py
│   │   ├── exposed_endpoints.py
│   │   ├── information_disclosure.py
│   │   ├── misconfiguration.py
│   │   ├── object_property_authorization.py
│   │   ├── rate_limiting.py
│   │   ├── sensitive_data.py
│   │   ├── ssrf.py
│   │   ├── token_security.py
│   │   ├── unsafe_api_consumption.py
│   │   └── validation.py
│   │
│   ├── reports/
│   │   ├── html_report.py
│   │   ├── json_report.py
│   │   └── pdf_report.py
│   │
│   ├── engine.py
│   ├── discovery.py
│   ├── models.py
│   ├── scoring.py
│   ├── history.py
│   ├── knowledge.py
│   ├── deduplication.py
│   └── summary.py
│
├── web/
│   ├── static/
│   ├── templates/
│   └── app.py
│
├── tests/
├── demo_api/
├── pyproject.toml
├── README.md
└── .gitignore
```

---

# 🧪 Testing

The project includes a comprehensive automated test suite.

Run all tests:

```bash
pytest
```

### Latest Test Result

```text
133 passed in 3.32s
```

The test suite covers:

* Security checks
* Endpoint discovery
* Scan engine behavior
* Passive scanning
* Active scanning
* Authenticated scanning
* CLI functionality
* JSON reports
* HTML reports
* PDF reports
* Security scoring
* Scan history
* Web dashboard integration
* Web exports

---

# 🧪 Demo API

The repository includes a deliberately vulnerable demo API for testing the scanner.

Run the demo API:

```bash
uvicorn demo_api.main:app --reload
```

Then scan it:

```bash
api-scanner scan --url http://127.0.0.1:8000
```

The demo API intentionally contains insecure configurations and vulnerable endpoints for testing purposes.

> ⚠️ Do not use the demo API as a production security example.

---

# ⚠️ Limitations

This project is designed to assist developers with automated API security testing.

It does not replace:

* Manual penetration testing
* Security code review
* Threat modeling
* Professional security assessments

Some vulnerabilities require application-specific business context and cannot be reliably detected through automated HTTP scanning alone.

---

# 🛠️ Technologies Used

* Python
* FastAPI
* HTTPX
* Pydantic
* Typer
* Rich
* Jinja2
* Pytest
* ReportLab

---

# 🔧 Development Workflow

```bash
# Activate the virtual environment
venv\Scripts\Activate

# Run all tests
pytest

# Run a CLI scan
api-scanner scan --url http://127.0.0.1:8000

# Run the web dashboard
uvicorn web.app:app --reload
```

---

# 🤝 Contributing

Contributions are welcome.

To contribute:

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Add or update tests
5. Ensure all tests pass
6. Submit a pull request

Before submitting changes, run:

```bash
pytest
```

---

# ⚠️ Disclaimer

This tool is intended for **educational, development, and authorized security testing purposes only**.

Do not scan systems, APIs, or services without explicit permission from their owners.

The developers of this project are not responsible for unauthorized use.

---

# 👨‍💻 Author

**Prathvik Shetty**

### API Security Scanner

**Automated API Security Testing for Developers**


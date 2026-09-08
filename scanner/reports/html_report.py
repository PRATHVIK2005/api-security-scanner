"""Standalone HTML report generator for API Security Scanner."""

from datetime import datetime, timezone
from pathlib import Path
from scanner.models import ScanResult, Severity
from scanner.summary import count_findings_by_severity


def generate_html_report(
    result: ScanResult,
    output_path: str | Path | None = None,
) -> str:
    """
    Generate a self-contained, professionally styled HTML security report
    from a ScanResult object.
    """
    severity_counts = count_findings_by_severity(result.findings)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Order findings by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
    severity_order = {
        Severity.CRITICAL: 1,
        Severity.HIGH: 2,
        Severity.MEDIUM: 3,
        Severity.LOW: 4,
        Severity.INFO: 5,
    }
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (
            severity_order.get(f.severity, 99)
            if hasattr(f.severity, "value")
            else severity_order.get(Severity(str(f.severity).upper()), 99),
            f.endpoint,
        ),
    )

    # Score color & posture
    score = result.security_score
    if score >= 80:
        score_color = "#00e676"
        score_bg = "rgba(0, 230, 118, 0.15)"
    elif score >= 60:
        score_color = "#ffd600"
        score_bg = "rgba(255, 214, 0, 0.15)"
    elif score >= 40:
        score_color = "#ff6d00"
        score_bg = "rgba(255, 109, 0, 0.15)"
    else:
        score_color = "#ff1744"
        score_bg = "rgba(255, 23, 68, 0.15)"

    total_findings = len(result.findings)

    # Build findings HTML rows
    findings_html = ""
    if sorted_findings:
        for idx, finding in enumerate(sorted_findings, 1):
            sev = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity).upper()
            )
            sev_class = f"sev-{sev.lower()}"

            owasp_badge = (
                f'<span class="badge owasp-badge">{finding.owasp}</span>'
                if finding.owasp
                else ""
            )
            desc_html = (
                f'<div class="finding-block"><strong>VULNERABILITY DESCRIPTION:</strong><p>{finding.description}</p></div>'
                if finding.description
                else ""
            )
            recom_html = (
                f'<div class="finding-block recom-block"><strong>ACTIONABLE RECOMMENDATION:</strong><p>{finding.recommendation}</p></div>'
                if finding.recommendation
                else ""
            )

            findings_html += f"""
            <div class="finding-card {sev_class}-border">
                <div class="finding-header">
                    <div class="badges">
                        <span class="badge {sev_class}">{sev}</span>
                        <span class="badge method-badge">{finding.method or 'UNKNOWN'}</span>
                        {owasp_badge}
                    </div>
                    <span class="finding-id">Finding #{idx}</span>
                </div>
                <h3 class="finding-title">{finding.title}</h3>
                <div class="endpoint-box">
                    <span class="endpoint-label">ENDPOINT:</span>
                    <code>{finding.endpoint}</code>
                </div>
                {desc_html}
                {recom_html}
            </div>
            """
    else:
        findings_html = """
        <div class="no-findings-box">
            <div class="check-icon">🛡️</div>
            <h3>Zero Vulnerabilities Detected</h3>
            <p>Target API successfully satisfied all active and passive OWASP security checks.</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Assessment Report — {result.target}</title>
    <style>
        :root {{
            --bg: #0b1120;
            --card-bg: #131d35;
            --border: #203055;
            --text: #e2e8f0;
            --text-bright: #ffffff;
            --muted: #94a3b8;
            --critical: #ff1744;
            --high: #ff6d00;
            --medium: #ffd600;
            --low: #00e5ff;
            --info: #3b82f6;
            --success: #00e676;
            --cyan: #00f5ff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 40px 20px;
        }}
        .report-container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        /* Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 25px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .brand h1 {{
            font-size: 26px;
            letter-spacing: 1px;
            color: var(--text-bright);
        }}
        .brand h1 span {{ color: var(--cyan); }}
        .brand p {{
            font-size: 12px;
            color: var(--muted);
            letter-spacing: 0.5px;
        }}
        .report-meta {{
            text-align: right;
            font-size: 12px;
            color: var(--muted);
        }}
        .report-meta strong {{ color: var(--text-bright); }}
        /* Overview Panel */
        .overview-panel {{
            display: grid;
            grid-template-columns: 1fr 240px;
            gap: 25px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
        }}
        .target-url {{
            font-family: monospace;
            font-size: 18px;
            color: var(--cyan);
            margin-bottom: 18px;
            word-break: break-all;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
        }}
        .meta-item .label {{
            display: block;
            font-size: 11px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .meta-item .val {{
            font-size: 14px;
            font-weight: 600;
            color: var(--text-bright);
        }}
        /* Score Box */
        .score-box {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: rgba(0,0,0,0.25);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}
        .score-number {{
            font-size: 38px;
            font-weight: 800;
            color: {score_color};
            line-height: 1;
        }}
        .score-max {{ font-size: 13px; color: var(--muted); margin-bottom: 8px; }}
        .risk-pill {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            background: {score_bg};
            color: {score_color};
            border: 1px solid {score_color};
        }}
        /* Severity Summary Cards */
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .sev-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }}
        .sev-card.card-critical {{ border-top: 3px solid var(--critical); }}
        .sev-card.card-high {{ border-top: 3px solid var(--high); }}
        .sev-card.card-medium {{ border-top: 3px solid var(--medium); }}
        .sev-card.card-low {{ border-top: 3px solid var(--low); }}
        .sev-count {{
            font-size: 26px;
            font-weight: 700;
            margin-bottom: 2px;
        }}
        .card-critical .sev-count {{ color: var(--critical); }}
        .card-high .sev-count {{ color: var(--high); }}
        .card-medium .sev-count {{ color: var(--medium); }}
        .card-low .sev-count {{ color: var(--low); }}
        .sev-label {{
            font-size: 11px;
            font-weight: 600;
            color: var(--muted);
            letter-spacing: 0.5px;
        }}
        /* Severity Bar Chart */
        .chart-box {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 35px;
        }}
        .chart-box h3 {{
            font-size: 13px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}
        .bar-row {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
            font-size: 12px;
        }}
        .bar-name {{ width: 75px; font-weight: 600; }}
        .bar-track {{
            flex: 1;
            height: 14px;
            background: rgba(255,255,255,0.06);
            border-radius: 3px;
            overflow: hidden;
        }}
        .bar-fill {{
            height: 100%;
            border-radius: 3px;
            transition: width 0.3s;
        }}
        .fill-critical {{ background: var(--critical); }}
        .fill-high {{ background: var(--high); }}
        .fill-medium {{ background: var(--medium); }}
        .fill-low {{ background: var(--low); }}
        .bar-num {{ width: 30px; text-align: right; font-weight: 700; }}
        /* Section Title */
        .section-heading {{
            font-size: 18px;
            font-weight: 700;
            color: var(--text-bright);
            margin: 30px 0 15px;
            border-left: 3px solid var(--cyan);
            padding-left: 10px;
        }}
        /* Finding Cards */
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 22px;
            margin-bottom: 18px;
        }}
        .sev-critical-border {{ border-left: 4px solid var(--critical); }}
        .sev-high-border {{ border-left: 4px solid var(--high); }}
        .sev-medium-border {{ border-left: 4px solid var(--medium); }}
        .sev-low-border {{ border-left: 4px solid var(--low); }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }}
        .badges {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 700;
        }}
        .badge.sev-critical {{ background: var(--critical); color: #fff; }}
        .badge.sev-high {{ background: var(--high); color: #fff; }}
        .badge.sev-medium {{ background: var(--medium); color: #000; }}
        .badge.sev-low {{ background: var(--low); color: #000; }}
        .badge.method-badge {{ background: rgba(255,255,255,0.1); color: var(--text-bright); }}
        .badge.owasp-badge {{ background: rgba(0, 245, 255, 0.1); color: var(--cyan); border: 1px solid var(--cyan); }}
        .finding-id {{ font-size: 11px; color: var(--muted); }}
        .finding-title {{
            font-size: 16px;
            color: var(--text-bright);
            margin-bottom: 12px;
        }}
        .endpoint-box {{
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 6px 12px;
            margin-bottom: 14px;
            font-size: 12px;
        }}
        .endpoint-label {{ color: var(--muted); font-size: 10px; font-weight: 700; }}
        .endpoint-box code {{ color: var(--cyan); font-family: monospace; }}
        .finding-block {{
            margin-top: 12px;
            font-size: 13px;
        }}
        .finding-block strong {{
            display: block;
            font-size: 10px;
            letter-spacing: 0.5px;
            color: var(--muted);
            margin-bottom: 4px;
        }}
        .recom-block {{
            background: rgba(0, 230, 118, 0.08);
            border: 1px solid rgba(0, 230, 118, 0.2);
            border-radius: 4px;
            padding: 12px 14px;
        }}
        .recom-block strong {{ color: var(--success); }}
        .no-findings-box {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 40px;
            text-align: center;
        }}
        .check-icon {{ font-size: 36px; margin-bottom: 10px; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 11px;
            color: var(--muted);
        }}
        @media (max-width: 768px) {{
            .overview-panel {{ grid-template-columns: 1fr; }}
            .header {{ flex-direction: column; align-items: flex-start; }}
            .report-meta {{ text-align: left; }}
        }}
    </style>
</head>
<body>

<div class="report-container">

    <!-- HEADER -->
    <header class="header">
        <div class="brand">
            <h1>API<span>GUARD</span></h1>
            <p>OWASP API SECURITY ASSESSMENT REPORT</p>
        </div>
        <div class="report-meta">
            <div>Generated: <strong>{now_str}</strong></div>
            <div>Auditor Engine: <strong>API Security Scanner v0.1.0</strong></div>
        </div>
    </header>

    <!-- OVERVIEW PANEL -->
    <div class="overview-panel">
        <div>
            <div class="target-url">{result.target}</div>
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="label">Endpoints Scanned</span>
                    <span class="val">{result.endpoints_scanned}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Unreachable</span>
                    <span class="val">{result.unreachable_endpoints}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Discovery Source</span>
                    <span class="val">{result.discovery_source}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Total Findings</span>
                    <span class="val">{total_findings}</span>
                </div>
                {f'<div class="meta-item"><span class="label">OpenAPI Spec</span><span class="val">{result.specification_url}</span></div>' if result.specification_url else ''}
            </div>
        </div>

        <div class="score-box">
            <div class="score-number">{result.security_score:.1f}</div>
            <div class="score-max">/ 100 Score</div>
            <div class="risk-pill">{result.risk_level} RISK</div>
        </div>
    </div>

    <!-- SEVERITY SUMMARY CARDS -->
    <div class="severity-grid">
        <div class="sev-card card-critical">
            <div class="sev-count">{severity_counts[Severity.CRITICAL]}</div>
            <div class="sev-label">CRITICAL</div>
        </div>
        <div class="sev-card card-high">
            <div class="sev-count">{severity_counts[Severity.HIGH]}</div>
            <div class="sev-label">HIGH</div>
        </div>
        <div class="sev-card card-medium">
            <div class="sev-count">{severity_counts[Severity.MEDIUM]}</div>
            <div class="sev-label">MEDIUM</div>
        </div>
        <div class="sev-card card-low">
            <div class="sev-count">{severity_counts[Severity.LOW]}</div>
            <div class="sev-label">LOW</div>
        </div>
    </div>

    <!-- SEVERITY VISUALIZATION -->
    <div class="chart-box">
        <h3>Severity Distribution</h3>
        <div class="bar-row">
            <span class="bar-name" style="color: var(--critical);">CRITICAL</span>
            <div class="bar-track">
                <div class="bar-fill fill-critical" style="width: {min(100, int((severity_counts[Severity.CRITICAL] / max(1, total_findings)) * 100))}%;"></div>
            </div>
            <span class="bar-num">{severity_counts[Severity.CRITICAL]}</span>
        </div>
        <div class="bar-row">
            <span class="bar-name" style="color: var(--high);">HIGH</span>
            <div class="bar-track">
                <div class="bar-fill fill-high" style="width: {min(100, int((severity_counts[Severity.HIGH] / max(1, total_findings)) * 100))}%;"></div>
            </div>
            <span class="bar-num">{severity_counts[Severity.HIGH]}</span>
        </div>
        <div class="bar-row">
            <span class="bar-name" style="color: var(--medium);">MEDIUM</span>
            <div class="bar-track">
                <div class="bar-fill fill-medium" style="width: {min(100, int((severity_counts[Severity.MEDIUM] / max(1, total_findings)) * 100))}%;"></div>
            </div>
            <span class="bar-num">{severity_counts[Severity.MEDIUM]}</span>
        </div>
        <div class="bar-row">
            <span class="bar-name" style="color: var(--low);">LOW</span>
            <div class="bar-track">
                <div class="bar-fill fill-low" style="width: {min(100, int((severity_counts[Severity.LOW] / max(1, total_findings)) * 100))}%;"></div>
            </div>
            <span class="bar-num">{severity_counts[Severity.LOW]}</span>
        </div>
    </div>

    <!-- DETAILED FINDINGS -->
    <h2 class="section-heading">Detailed Findings ({total_findings})</h2>
    {findings_html}

    <!-- FOOTER -->
    <footer class="footer">
        <p>CONFIDENTIAL — Generated by API Guard (OWASP API Security Intelligence). For authorized security personnel only.</p>
    </footer>

</div>

</body>
</html>"""

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html, encoding="utf-8")

    return html

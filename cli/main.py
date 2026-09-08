from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from scanner.engine import scan
from scanner.models import ScanMode, Severity
from scanner.reports.json_report import generate_json_report
from scanner.reports.html_report import generate_html_report
from scanner.reports.pdf_report import generate_pdf_report
from scanner.summary import count_findings_by_severity
from scanner.validation import InvalidURLError


app = typer.Typer(
    name="api-scanner",
    help="OWASP API Security Scanner for Developers",
    no_args_is_help=True,
)

console = Console()


@app.command(
    name="scan",
    help="Scan an API for security issues.",
)
def scan_api(
    url: str = typer.Option(
        ...,
        "--url",
        "-u",
        help="Target API URL to scan",
    ),
    mode: ScanMode = typer.Option(
        ScanMode.PASSIVE,
        "--mode",
        help="Scan mode: passive or active",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Bearer token for authenticated API scanning",
    ),
    header: list[str] | None = typer.Option(
        None,
        "--header",
        "-H",
        help="Custom header in 'Name: Value' format (can be specified multiple times)",
    ),
    output_format: str = typer.Option(
        "terminal",
        "--format",
        help="Output format: terminal, json, pdf, or html",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Save report to a file (default: report.pdf / report.html if format is pdf/html)",
    ),
):
    """Scan an API for security issues."""

    # Parse optional custom headers
    parsed_headers = {}
    if header:
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                parsed_headers[k.strip()] = v.strip()
            else:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] Invalid header format '{h}'. Expected 'Name: Value'."
                )

    format_normalized = output_format.lower().strip()
    if format_normalized not in {"terminal", "json", "pdf", "html"}:
        console.print(
            "[bold red]Invalid format.[/bold red] "
            "Use 'terminal', 'json', 'pdf', or 'html'."
        )
        raise typer.Exit(code=1)

    try:
        result = scan(
            url,
            mode=mode,
            token=token,
            headers=parsed_headers if parsed_headers else None,
        )
    except (InvalidURLError, ValueError) as exc:
        console.print(f"[bold red]Validation Error:[/bold red] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Scan Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # Persist scan to SQLite history if DB is configured
    try:
        from scanner.history import save_scan
        save_scan(result, mode=mode.value if hasattr(mode, "value") else str(mode))
    except Exception:
        pass

    # 1. JSON Report
    if format_normalized == "json":
        report = generate_json_report(result)
        if output is not None:
            output.write_text(report, encoding="utf-8")
            console.print(f"[green]JSON report saved to {output}[/green]")
        else:
            console.print(report)
        return

    # 2. HTML Report
    if format_normalized == "html":
        target_path = output if output is not None else Path("report.html")
        generate_html_report(result, target_path)
        console.print(f"[green]HTML security report saved to {target_path}[/green]")
        return

    # 3. PDF Report
    if format_normalized == "pdf":
        target_path = output if output is not None else Path("report.pdf")
        generate_pdf_report(result, target_path)
        console.print(f"[green]PDF security report saved to {target_path}[/green]")
        return

    # 4. Terminal Report (default)
    console.print("\n[bold cyan]API Security Scan Results[/bold cyan]")
    console.print(f"Target: {result.target}")
    console.print(f"Discovery Source: {result.discovery_source}")

    if result.specification_url:
        console.print(f"Specification: {result.specification_url}")

    console.print(f"Endpoints Scanned: {result.endpoints_scanned}")
    console.print(f"Unreachable: {result.unreachable_endpoints}")
    console.print(f"Findings: {len(result.findings)}")
    console.print(f"\nSecurity Score: [bold]{result.security_score:.1f}/100[/bold]")
    console.print(f"Risk Level: [bold]{result.risk_level}[/bold]")

    severity_counts = count_findings_by_severity(result.findings)

    console.print("\n[bold cyan]Severity Summary[/bold cyan]")
    console.print(f"CRITICAL: {severity_counts[Severity.CRITICAL]}")
    console.print(f"HIGH:     {severity_counts[Severity.HIGH]}")
    console.print(f"MEDIUM:   {severity_counts[Severity.MEDIUM]}")
    console.print(f"LOW:      {severity_counts[Severity.LOW]}")

    console.print(f"\nScan Mode: {mode.value.upper() if hasattr(mode, 'value') else str(mode).upper()}")

    # Safe authentication reporting - never print token secret
    if token:
        console.print("Authentication: [green]Bearer Token Provided[/green]")
    elif parsed_headers:
        header_names = ", ".join(parsed_headers.keys())
        console.print(f"Authentication: [green]Custom Headers ({header_names})[/green]")
    else:
        console.print("Authentication: [yellow]None[/yellow]")

    table = Table(title="Security Findings")
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Method")
    table.add_column("Endpoint")

    for finding in result.findings:
        table.add_row(
            finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            finding.title,
            getattr(finding, "method", "UNKNOWN") or "UNKNOWN",
            finding.endpoint,
        )

    console.print(table)


@app.command(
    name="history",
    help="View past scan history.",
)
def view_history():
    """Retrieve and list past scans from SQLite database."""
    from scanner.history import get_all_scans

    scans = get_all_scans()
    if not scans:
        console.print("[yellow]No past scans found in history database.[/yellow]")
        return

    table = Table(title="API Security Scan History")
    table.add_column("ID", justify="right")
    table.add_column("Date (UTC)")
    table.add_column("Target URL")
    table.add_column("Score", justify="right")
    table.add_column("Risk")
    table.add_column("Findings", justify="right")
    table.add_column("Mode")

    for s in scans:
        date_str = s.scan_date.strftime("%Y-%m-%d %H:%M") if s.scan_date else "N/A"
        table.add_row(
            str(s.id),
            date_str,
            s.target_url,
            f"{s.security_score:.1f}",
            str(s.risk_level),
            str(s.findings_count),
            str(s.scan_mode).upper(),
        )

    console.print(table)


@app.command(
    name="compare",
    help="Compare two past scans by ID.",
)
def compare_history(
    scan1: int = typer.Argument(..., help="First scan ID to compare"),
    scan2: int = typer.Argument(..., help="Second scan ID to compare"),
):
    """Compare two past scans and show security posture diff."""
    from scanner.history import compare_scans

    diff = compare_scans(scan1, scan2)
    if not diff:
        console.print(
            f"[bold red]Error:[/bold red] Could not compare scans #{scan1} and #{scan2}. One or both scans do not exist."
        )
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]Scan Comparison: #{scan1} vs #{scan2}[/bold cyan]")
    console.print(f"Target: {diff['scan1'].target_url}")
    console.print(f"Status: [bold]{diff['status']}[/bold] — {diff['status_text']}")
    
    score_sign = "+" if diff["score_diff"] > 0 else ""
    console.print(
        f"Score Change: [bold]{score_sign}{diff['score_diff']}[/bold] "
        f"({diff['scan1'].security_score:.1f} -> {diff['scan2'].security_score:.1f})"
    )
    
    find_sign = "+" if diff["findings_diff"] > 0 else ""
    console.print(
        f"Findings Change: [bold]{find_sign}{diff['findings_diff']}[/bold] "
        f"({diff['scan1'].findings_count} -> {diff['scan2'].findings_count})"
    )


if __name__ == "__main__":
    app()
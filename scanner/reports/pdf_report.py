"""Professional PDF security report generator for API Security Scanner using ReportLab."""

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line

from scanner.models import ScanResult, Severity
from scanner.summary import count_findings_by_severity


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw 'Page X of Y' and header/footer."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_header_footer(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(
                54,
                letter[1] - 36,
                "API Security Scanner — Professional Assessment Report",
            )
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Running Footer (all pages)
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(letter[0] - 54, 30, page_str)
        self.drawString(
            54,
            30,
            "CONFIDENTIAL — OWASP API Security Intelligence Report",
        )
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 42, letter[0] - 54, 42)

        self.restoreState()


def create_severity_chart(counts: dict[Severity, int], total_findings: int) -> Drawing:
    """Create a graphical horizontal bar chart visualizing findings by severity."""
    d = Drawing(480, 110)
    
    # Background card
    d.add(Rect(0, 0, 480, 110, fillColor=colors.HexColor("#f8fafc"), strokeColor=colors.HexColor("#e2e8f0"), strokeWidth=1, rx=4, ry=4))
    d.add(String(16, 90, "SEVERITY DISTRIBUTION CHART", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.HexColor("#475569")))

    categories = [
        (Severity.CRITICAL, "CRITICAL", colors.HexColor("#dc2626")),
        (Severity.HIGH, "HIGH", colors.HexColor("#ea580c")),
        (Severity.MEDIUM, "MEDIUM", colors.HexColor("#d97706")),
        (Severity.LOW, "LOW", colors.HexColor("#0284c7")),
    ]

    max_count = max(total_findings, 1)
    bar_max_width = 300
    y_pos = 68

    for sev_key, label, color in categories:
        count = counts.get(sev_key, 0)
        pct = count / max_count if total_findings > 0 else 0
        bar_width = max(4, int(pct * bar_max_width)) if count > 0 else 0

        # Label
        d.add(String(16, y_pos, label, fontName="Helvetica-Bold", fontSize=8, fillColor=color))
        
        # Track
        d.add(Rect(90, y_pos - 2, bar_max_width, 10, fillColor=colors.HexColor("#e2e8f0"), strokeColor=None, rx=2, ry=2))
        
        # Fill
        if bar_width > 0:
            d.add(Rect(90, y_pos - 2, bar_width, 10, fillColor=color, strokeColor=None, rx=2, ry=2))
        
        # Count & Percentage
        text_info = f"{count} ({pct*100:.0f}%)" if total_findings > 0 else "0"
        d.add(String(90 + bar_max_width + 12, y_pos, text_info, fontName="Helvetica", fontSize=8, fillColor=colors.HexColor("#334155")))
        
        y_pos -= 18

    return d


def generate_pdf_report(
    result: ScanResult,
    output_path: str | Path | None = None,
    scan_mode: str | None = None,
) -> bytes:
    """
    Generate a professional, publication-ready PDF security assessment report
    from a ScanResult object.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=15,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=8,
    )
    meta_label = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#64748b"),
    )
    meta_val = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0f172a"),
    )
    finding_title = ParagraphStyle(
        "FindingTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
    )
    finding_endpoint = ParagraphStyle(
        "FindingEndpoint",
        parent=styles["Normal"],
        fontName="Courier-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0284c7"),
    )
    body_text = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    recom_text = ParagraphStyle(
        "RecomText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#15803d"),
    )

    story = []

    # 1. REPORT HEADER
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph("API SECURITY ASSESSMENT REPORT", title_style))
    story.append(Paragraph("Automated Vulnerability & Compliance Audit", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # 2. TARGET INFORMATION & SECURITY OVERVIEW (2-column layout)
    score = result.security_score
    risk_level = str(result.risk_level).upper()

    if score >= 80:
        score_color = colors.HexColor("#16a34a")
    elif score >= 60:
        score_color = colors.HexColor("#ca8a04")
    elif score >= 40:
        score_color = colors.HexColor("#ea580c")
    else:
        score_color = colors.HexColor("#dc2626")

    effective_mode = scan_mode or getattr(result, "scan_mode", "passive") or "passive"
    scan_mode_display = f"{str(effective_mode).capitalize()} Scan"

    # Left: Target Info table
    target_data = [
        [Paragraph("TARGET URL", meta_label), Paragraph(result.target, meta_val)],
        [Paragraph("AUDIT DATE", meta_label), Paragraph(now_str, meta_val)],
        [Paragraph("SCAN MODE", meta_label), Paragraph(scan_mode_display, meta_val)],
        [Paragraph("ENDPOINTS SCANNED", meta_label), Paragraph(str(result.endpoints_scanned), meta_val)],
        [Paragraph("UNREACHABLE", meta_label), Paragraph(str(result.unreachable_endpoints), meta_val)],
        [Paragraph("DISCOVERY SOURCE", meta_label), Paragraph(result.discovery_source, meta_val)],
    ]
    if result.specification_url:
        target_data.append([Paragraph("OPENAPI SPEC", meta_label), Paragraph(result.specification_url, meta_val)])

    target_table = Table(target_data, colWidths=[110, 200])
    target_table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ])
    )

    # Right: Score card
    score_data = [
        [Paragraph("SECURITY POSTURE SCORE", meta_label)],
        [Paragraph(f"<b>{score:.1f}</b> <font size=10>/ 100</font>", ParagraphStyle("ScoreVal", fontName="Helvetica-Bold", fontSize=26, leading=30, textColor=score_color, alignment=1))],
        [Paragraph(f"<b>{risk_level} RISK</b>", ParagraphStyle("RiskBadge", fontName="Helvetica-Bold", fontSize=9, textColor=score_color, alignment=1))],
        [Spacer(1, 4)],
        [Paragraph(f"Total Findings: <b>{len(result.findings)}</b>", ParagraphStyle("TotalCount", fontName="Helvetica", fontSize=9, alignment=1, textColor=colors.HexColor("#475569")))],
    ]
    score_table = Table(score_data, colWidths=[170])
    score_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    )

    overview_table = Table([[target_table, score_table]], colWidths=[310, 194])
    overview_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(overview_table)
    story.append(Spacer(1, 14))

    # 3. SEVERITY SUMMARY TABLE
    severity_counts = count_findings_by_severity(result.findings)
    crit_count = severity_counts.get(Severity.CRITICAL, 0)
    high_count = severity_counts.get(Severity.HIGH, 0)
    med_count = severity_counts.get(Severity.MEDIUM, 0)
    low_count = severity_counts.get(Severity.LOW, 0)
    info_count = severity_counts.get(Severity.INFO, 0)

    summary_headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL FINDINGS"]
    summary_values = [str(crit_count), str(high_count), str(med_count), str(low_count), str(len(result.findings))]

    sev_summary_table = Table(
        [
            [Paragraph(f"<b>{h}</b>", ParagraphStyle("Hdr", fontName="Helvetica-Bold", fontSize=8, alignment=1, textColor=colors.white)) for h in summary_headers],
            [Paragraph(f"<b>{v}</b>", ParagraphStyle("Val", fontName="Helvetica-Bold", fontSize=12, alignment=1, textColor=colors.HexColor("#0f172a"))) for v in summary_values],
        ],
        colWidths=[100, 100, 100, 100, 104],
    )
    sev_summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#dc2626")),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#ea580c")),
            ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#d97706")),
            ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#0284c7")),
            ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#475569")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(sev_summary_table)
    story.append(Spacer(1, 12))

    # 4. SEVERITY VISUALIZATION CHART
    chart_drawing = create_severity_chart(severity_counts, len(result.findings))
    story.append(chart_drawing)
    story.append(Spacer(1, 16))

    # 5. DETAILED FINDINGS SECTION
    story.append(Paragraph(f"Detailed Security Findings ({len(result.findings)})", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

    if not result.findings:
        no_findings_box = Table(
            [[Paragraph("<b>Clean Bill of Health:</b> No security findings or vulnerabilities were detected during this audit.", body_text)]],
            colWidths=[504],
        )
        no_findings_box.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#bbf7d0")),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 16),
            ])
        )
        story.append(no_findings_box)
    else:
        # Sort findings: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
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

        for idx, finding in enumerate(sorted_findings, 1):
            sev_str = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity).upper()
            )

            if sev_str == "CRITICAL":
                border_color = colors.HexColor("#dc2626")
                badge_bg = colors.HexColor("#dc2626")
            elif sev_str == "HIGH":
                border_color = colors.HexColor("#ea580c")
                badge_bg = colors.HexColor("#ea580c")
            elif sev_str == "MEDIUM":
                border_color = colors.HexColor("#d97706")
                badge_bg = colors.HexColor("#d97706")
            else:
                border_color = colors.HexColor("#0284c7")
                badge_bg = colors.HexColor("#0284c7")

            finding_flowables = []

            # Finding Header Row: Badge | Method | Title
            header_text = f"<b><font color='{border_color.hexval()}'>[{sev_str}]</font> {finding.title}</b>"
            finding_flowables.append(Paragraph(header_text, finding_title))
            
            method_str = getattr(finding, "method", "UNKNOWN") or "UNKNOWN"
            endpoint_line = f"<b>METHOD:</b> {method_str} &nbsp;&nbsp;|&nbsp;&nbsp; <b>ENDPOINT:</b> {finding.endpoint}"
            if finding.owasp:
                endpoint_line += f"<br/><b>OWASP:</b> {finding.owasp}"
            finding_flowables.append(Paragraph(endpoint_line, finding_endpoint))
            finding_flowables.append(Spacer(1, 4))

            # Description
            if finding.description:
                finding_flowables.append(Paragraph("<b>Description:</b>", meta_label))
                finding_flowables.append(Paragraph(finding.description, body_text))
                finding_flowables.append(Spacer(1, 4))

            # Recommendation
            if finding.recommendation:
                recom_box = Table(
                    [[
                        Paragraph("<b>Remediation:</b>", ParagraphStyle("RecomHdr", fontName="Helvetica-Bold", fontSize=8, textColor=colors.HexColor("#15803d"))),
                        Paragraph(finding.recommendation, recom_text),
                    ]],
                    colWidths=[70, 410],
                )
                recom_box.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#bbf7d0")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ])
                )
                finding_flowables.append(recom_box)

            finding_flowables.append(Spacer(1, 6))

            # Encapsulate each finding inside a styled card Table
            card_content = Table([[finding_flowables]], colWidths=[504])
            card_content.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("LINELEFT", (0, 0), (-1, -1), 3.5, border_color),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ])
            )

            story.append(KeepTogether([card_content, Spacer(1, 10)]))

    # Build PDF using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(pdf_bytes)

    return pdf_bytes

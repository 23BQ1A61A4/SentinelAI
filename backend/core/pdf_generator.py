"""
Professional PDF Audit Report Generator using ReportLab
Produces executive-grade compliance & security audit dossiers
"""

import os
from pathlib import Path
from typing import Optional
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

try:
    from database.models import AuditReport
except (ImportError, ValueError):
    from ..database.models import AuditReport

class PDFReportGenerator:
    """Generates styled audit and compliance PDF reports."""

    def __init__(self, output_dir: Optional[str] = None):
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            try:
                from ..config import REPORTS_DIR
                self.output_dir = REPORTS_DIR
            except (ImportError, ValueError):
                self.output_dir = Path("generated_reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, report: AuditReport) -> str:
        """
        Builds the PDF document and returns the absolute file path.
        """
        filename = f"Compliance_Audit_{report.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom Styles
        primary_color = colors.HexColor("#1A365D")
        secondary_color = colors.HexColor("#2B6CB0")
        accent_color = colors.HexColor("#C53030")
        dark_text = colors.HexColor("#2D3748")
        light_bg = colors.HexColor("#EDF2F7")

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=primary_color,
            alignment=TA_CENTER
        )

        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=secondary_color,
            alignment=TA_CENTER
        )

        h1_style = ParagraphStyle(
            'H1Heading',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=primary_color,
            spaceBefore=12,
            spaceAfter=6
        )

        h2_style = ParagraphStyle(
            'H2Heading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=secondary_color,
            spaceBefore=8,
            spaceAfter=4
        )

        body_style = ParagraphStyle(
            'BodyDark',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=dark_text,
            alignment=TA_JUSTIFY
        )

        badge_style = ParagraphStyle(
            'BadgeStyle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=12,
            textColor=colors.white,
            alignment=TA_CENTER
        )

        story = []

        # Header Title Banner
        story.append(Paragraph("AGENTIC AI-BASED SMART COMPLIANCE AUDITOR", title_style))
        story.append(Paragraph("Enterprise LLM Security Validation & Regulatory Audit Dossier", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=2, color=primary_color, spaceBefore=2, spaceAfter=10))

        # Metadata Table
        meta_data = [
            [
                Paragraph("<b>Audit ID:</b>", body_style), Paragraph(report.id, body_style),
                Paragraph("<b>Audit Date:</b>", body_style), Paragraph(report.created_at, body_style)
            ],
            [
                Paragraph("<b>Target System:</b>", body_style), Paragraph(report.target.name, body_style),
                Paragraph("<b>Model Evaluated:</b>", body_style), Paragraph(report.target.model_name, body_style)
            ],
            [
                Paragraph("<b>Data Sensitivity:</b>", body_style), Paragraph(report.target.data_sensitivity, body_style),
                Paragraph("<b>Decision Verdict:</b>", body_style), Paragraph(f"<b>{report.decision.status}</b>", body_style)
            ]
        ]
        meta_table = Table(meta_data, colWidths=[90, 180, 90, 180])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), light_bg),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 12))

        # Executive Summary Box
        story.append(Paragraph("1. Executive Summary & Composite Scores", h1_style))
        story.append(Paragraph(report.executive_summary, body_style))
        story.append(Spacer(1, 8))

        # Metric Score Cards Table
        comp_color = colors.HexColor("#38A169") if report.overall_compliance_score >= 75 else colors.HexColor("#E53E3E")
        sec_color = colors.HexColor("#38A169") if report.overall_security_score >= 70 else colors.HexColor("#E53E3E")
        risk_color = colors.HexColor("#E53E3E") if report.composite_risk_score >= 60 else colors.HexColor("#38A169")

        score_data = [
            [
                Paragraph(f"<b>Compliance Score</b><br/><font size=14>{report.overall_compliance_score:.1f}%</font>", badge_style),
                Paragraph(f"<b>Security Score</b><br/><font size=14>{report.overall_security_score:.1f}%</font>", badge_style),
                Paragraph(f"<b>Composite Risk</b><br/><font size=14>{report.composite_risk_score:.1f}/100</font>", badge_style),
                Paragraph(f"<b>Total Vulnerabilities</b><br/><font size=14>{report.vulnerabilities_found}</font>", badge_style)
            ]
        ]
        score_table = Table(score_data, colWidths=[135, 135, 135, 135])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), comp_color),
            ('BACKGROUND', (1, 0), (1, 0), sec_color),
            ('BACKGROUND', (2, 0), (2, 0), risk_color),
            ('BACKGROUND', (3, 0), (3, 0), primary_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 14))

        # OWASP Top 10 Security Findings Table
        story.append(Paragraph("2. OWASP Top 10 for LLM - Security Validation Findings", h1_style))
        vuln_headers = [
            Paragraph("<b>ID</b>", body_style),
            Paragraph("<b>OWASP Category</b>", body_style),
            Paragraph("<b>Severity</b>", body_style),
            Paragraph("<b>CVSS</b>", body_style),
            Paragraph("<b>Status</b>", body_style),
            Paragraph("<b>Exploit Evidence / Summary</b>", body_style)
        ]
        vuln_rows = [vuln_headers]

        for v in report.vulnerabilities:
            sev_color = "#E53E3E" if v.severity in ["CRITICAL", "HIGH"] else "#DD6B20" if v.severity == "MEDIUM" else "#3182CE"
            status_text = "<font color='red'><b>EXPLOITABLE</b></font>" if v.is_exploitable else "<font color='green'><b>DEFENDED</b></font>"
            
            vuln_rows.append([
                Paragraph(v.id, body_style),
                Paragraph(f"<b>{v.owasp_id}</b>: {v.owasp_title}", body_style),
                Paragraph(f"<font color='{sev_color}'><b>{v.severity}</b></font>", body_style),
                Paragraph(str(v.cvss_score), body_style),
                Paragraph(status_text, body_style),
                Paragraph(v.exploit_evidence[:140] + "..." if len(v.exploit_evidence) > 140 else v.exploit_evidence, body_style)
            ])

        vuln_table = Table(vuln_rows, colWidths=[65, 120, 60, 40, 75, 180])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), light_bg),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 14))

        # Compliance Controls Checklist
        story.append(Paragraph("3. Regulatory & Framework Compliance Audit (ISO 27001 & NIST)", h1_style))
        comp_headers = [
            Paragraph("<b>Standard</b>", body_style),
            Paragraph("<b>Control ID</b>", body_style),
            Paragraph("<b>Control Title</b>", body_style),
            Paragraph("<b>Status</b>", body_style),
            Paragraph("<b>Findings & Audit Evidence</b>", body_style)
        ]
        comp_rows = [comp_headers]

        for c in report.compliance_controls:
            stat_color = "green" if c.status == "COMPLIANT" else "#D69E2E" if c.status == "PARTIALLY_COMPLIANT" else "red"
            comp_rows.append([
                Paragraph(c.standard.split()[0], body_style),
                Paragraph(c.control_id, body_style),
                Paragraph(c.control_title, body_style),
                Paragraph(f"<font color='{stat_color}'><b>{c.status}</b></font>", body_style),
                Paragraph(c.findings, body_style)
            ])

        comp_table = Table(comp_rows, colWidths=[80, 80, 130, 90, 160])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), light_bg),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(comp_table)
        story.append(Spacer(1, 14))

        # Remediation Roadmap & Timeline
        story.append(Paragraph("4. Phased Remediation Roadmap & Estimated Compliance Gain", h1_style))
        road_headers = [
            Paragraph("<b>Phase / Timeline</b>", body_style),
            Paragraph("<b>Priority</b>", body_style),
            Paragraph("<b>Action Item & Recommendation</b>", body_style),
            Paragraph("<b>Est. Hours</b>", body_style),
            Paragraph("<b>Score Gain</b>", body_style)
        ]
        road_rows = [road_headers]

        for r in report.roadmap:
            road_rows.append([
                Paragraph(r.phase.split(":")[0], body_style),
                Paragraph(f"<b>{r.priority}</b>", body_style),
                Paragraph(f"<b>{r.title}</b><br/>{r.description}", body_style),
                Paragraph(f"{r.estimated_hours} hrs", body_style),
                Paragraph(f"+{r.expected_compliance_gain:.1f}%", body_style)
            ])

        road_table = Table(road_rows, colWidths=[90, 50, 260, 65, 75])
        road_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), light_bg),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(road_table)
        story.append(Spacer(1, 16))

        # CISO Sign-off Box
        sign_box_data = [
            [
                Paragraph("<b>CISO / Lead Auditor Sign-Off:</b>", body_style),
                Paragraph("<b>Audit Decision:</b> " + report.decision.status, body_style)
            ],
            [
                Paragraph("Signature: ___________________________", body_style),
                Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", body_style)
            ]
        ]
        sign_table = Table(sign_box_data, colWidths=[270, 270])
        sign_table.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 1, primary_color),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether(sign_table))

        # Build PDF
        doc.build(story)
        return str(filepath)

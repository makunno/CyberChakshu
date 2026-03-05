#!/usr/bin/env python3
"""
Detailed Forensic PDF Report Generator
Generates comprehensive PDF reports with all findings, every anomaly,
and specific locations for investigator action.

Includes:
- Layered correlation analysis results
- Complete extraction details
- All suspicious files with exact locations
- Timestamp anomalies by layer
- Anti-forensic indicators with evidence
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import (
    HexColor,
    black,
    white,
    red,
    orange,
    yellow,
    green,
    grey,
)
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    ListFlowable,
    ListItem,
    Flowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus.tableofcontents import TableOfContents


SEVERITY_COLORS = {
    "CRITICAL": HexColor("#dc2626"),
    "HIGH": HexColor("#ea580c"),
    "MEDIUM": HexColor("#ca8a04"),
    "LOW": HexColor("#16a34a"),
    "INFO": HexColor("#3b82f6"),
    "UNKNOWN": HexColor("#6b7280"),
}

SEVERITY_BG_COLORS = {
    "CRITICAL": HexColor("#fecaca"),
    "HIGH": HexColor("#fed7aa"),
    "MEDIUM": HexColor("#fef08a"),
    "LOW": HexColor("#bbf7d0"),
    "INFO": HexColor("#dbeafe"),
    "UNKNOWN": HexColor("#e5e7eb"),
}


class ForensicPDFReport:
    def __init__(
        self,
        output_path: str,
        image_path: str,
        ai_results: Dict[str, Any],
        antiforensic_results: Dict[str, Any],
        layered_results: Dict[str, Any] = None,
        extraction_results: Dict[str, Any] = None,
    ):
        self.output_path = output_path
        self.image_path = image_path
        self.ai_results = ai_results
        self.antiforensic_results = antiforensic_results
        self.layered_results = layered_results or {}
        self.extraction_results = extraction_results or {}

        self.doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.elements = []
        self.page_num = 1

    def _setup_custom_styles(self):
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Heading1"],
                fontSize=28,
                spaceAfter=10,
                alignment=TA_CENTER,
                textColor=HexColor("#1f2937"),
                fontName="Helvetica-Bold",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportSubtitle",
                parent=self.styles["Normal"],
                fontSize=11,
                spaceAfter=25,
                alignment=TA_CENTER,
                textColor=HexColor("#6b7280"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=16,
                spaceBefore=25,
                spaceAfter=12,
                textColor=HexColor("#1f2937"),
                borderPadding=8,
                borderColor=HexColor("#3b82f6"),
                borderWidth=2,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SubSectionHeader",
                parent=self.styles["Heading3"],
                fontSize=13,
                spaceBefore=15,
                spaceAfter=8,
                textColor=HexColor("#374151"),
                borderPadding=5,
                borderColor=HexColor("#d1d5db"),
                borderWidth=1,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportBody",
                parent=self.styles["Normal"],
                fontSize=10,
                spaceAfter=10,
                alignment=TA_JUSTIFY,
                leading=14,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="FindingText",
                parent=self.styles["Normal"],
                fontSize=9,
                spaceAfter=4,
                leading=12,
                leftIndent=10,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="CodeText",
                parent=self.styles["Normal"],
                fontSize=8,
                fontName="Courier",
                spaceAfter=3,
                leading=11,
                textColor=HexColor("#7c3aed"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="AlertBox",
                parent=self.styles["Normal"],
                fontSize=11,
                spaceAfter=10,
                alignment=TA_LEFT,
                leading=16,
                borderPadding=10,
            )
        )

    def generate(self) -> str:
        self._add_header()
        self._add_executive_summary()
        self._add_live_tampering_section()
        self._add_layered_correlation_analysis()
        self._add_timestomp_findings_limited()
        self._add_ai_findings_summary()
        self._save_all_files_to_txt()
        self._add_detailed_recommendations()

        self.doc.build(
            self.elements,
            onFirstPage=self._add_page_num,
            onLaterPages=self._add_page_num,
        )
        return self.output_path

    def _add_live_tampering_section(self):
        self.elements.append(
            Paragraph("2. LIVE TAMPERING DETECTION ($LogFile Correlation)", self.styles["SectionHeader"])
        )
        
        desc = """
        <b>The Core Problem:</b> Traditional timestomping is detected by comparing $SI and $FN. 
        However, advanced 'Live Tampering' occurs while the system is running, leaving traces in 
        the $USN Journal and $LogFile. This report focuses on these inconsistencies.
        """
        self.elements.append(Paragraph(desc, self.styles["ReportBody"]))
        
        # Add 4 Levels of Truth table
        truth_data = [
            ["Level", "Source", "Forensic Value"],
            ["Level 1", "$SI (Standard Info)", "Easily spoofed by tools. What the user sees."],
            ["Level 2", "$FN (File Name)", "Often missed by tools. Updated by NTFS kernel."],
            ["Level 3", "USN Journal", "Ground truth of file system transactions."],
            ["Level 4", "$LogFile", "NTFS transaction logs. Proves metadata was modified."],
        ]
        
        truth_table = Table(truth_data, colWidths=[1 * inch, 2 * inch, 4 * inch])
        truth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        self.elements.append(truth_table)
        self.elements.append(Spacer(1, 15))

    def _add_timestomp_findings_limited(self):
        self.elements.append(
            Paragraph("4. CRITICAL INCONSISTENCIES (Top 10)", self.styles["SectionHeader"])
        )

        findings = self.layered_results.get("suspicious_files", [])
        if not findings:
            self.elements.append(Paragraph("No critical inconsistencies found.", self.styles["ReportBody"]))
            return

        # Show only top 10
        for i, finding in enumerate(findings[:10], 1):
            severity = finding.get("severity", "UNKNOWN")
            sev_color = SEVERITY_COLORS.get(severity, grey)
            
            header = f"[{severity}] #{i}: {finding.get('filename')}"
            self.elements.append(Paragraph(f"<b>{header}</b>", self.styles["SubSectionHeader"]))
            
            explanation = finding.get("explanation", "No details")
            self.elements.append(Paragraph(f"Analysis: {explanation}", self.styles["FindingText"]))
            
            # Show a small correlation if available
            layers = finding.get("affected_layers", [])
            if layers:
                self.elements.append(Paragraph(f"Layers Triggered: {', '.join(layers)}", self.styles["CodeText"]))

        if len(findings) > 10:
            msg = f"<i>Note: {len(findings) - 10} additional suspicious files were detected and saved to all_suspicious_files.txt for manual review.</i>"
            self.elements.append(Spacer(1, 10))
            self.elements.append(Paragraph(msg, self.styles["ReportBody"]))

    def _add_ai_findings_summary(self):
        self.elements.append(Paragraph("5. AI FORENSIC VERDICT", self.styles["SectionHeader"]))
        summary = self.ai_results.get("summary", "N/A")
        risk = self.ai_results.get("risk_level", "UNKNOWN")
        
        risk_style = ParagraphStyle(name="Risk", textColor=SEVERITY_COLORS.get(risk, black), fontName="Helvetica-Bold", fontSize=12)
        self.elements.append(Paragraph(f"Risk Level: {risk}", risk_style))
        self.elements.append(Paragraph(f"Verdict: {summary}", self.styles["ReportBody"]))
        
        impact = self.ai_results.get("new_capabilities_impact", "N/A")
        if impact != "N/A":
            self.elements.append(Paragraph(f"<b>Layer 3/4 Impact:</b> {impact}", self.styles["ReportBody"]))

    def _save_all_files_to_txt(self):
        """Save all suspicious files to a separate text file to keep PDF short."""
        try:
            findings = self.layered_results.get("suspicious_files", [])
            txt_path = Path(self.output_path).parent / "all_suspicious_files.txt"
            
            with open(txt_path, "w") as f:
                f.write(f"COMPLETE LIST OF SUSPICIOUS FILES - {datetime.now().isoformat()}\n")
                f.write("="*80 + "\n\n")
                for i, find in enumerate(findings, 1):
                    f.write(f"#{i} [{find.get('severity')}] {find.get('filename')}\n")
                    f.write(f"   Score: {find.get('score')}\n")
                    f.write(f"   Analysis: {find.get('explanation')}\n")
                    f.write(f"   Layers: {', '.join(find.get('affected_layers', []))}\n")
                    f.write("-" * 40 + "\n")
            
            self.elements.append(Spacer(1, 15))
            self.elements.append(Paragraph(f"<b>Full list saved to:</b> {txt_path.name}", self.styles["ReportBody"]))
        except Exception as e:
            print(f"Error saving txt findings: {e}")

    def _add_page_num(self, canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(grey)
        page_num_text = f"Page {self.page_num}"
        canvas.drawRightString(doc.pagesize[0] - 0.5 * inch, 0.25 * inch, page_num_text)
        canvas.drawString(0.5 * inch, 0.25 * inch, "FreeKhana Forensic Analysis Report")
        self.page_num += 1
        canvas.restoreState()

    def _add_header(self):
        self.elements.append(
            Paragraph("DIGITAL FORENSIC ANALYSIS REPORT", self.styles["ReportTitle"])
        )

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        img_name = os.path.basename(self.image_path)

        subtitle = f"""
        <b>Image File:</b> {img_name}<br/>
        <b>Analysis Date:</b> {timestamp}<br/>
        <b>Tool:</b> FreeKhana SIEM - NTFS Timestomp Detection System
        """
        self.elements.append(Paragraph(subtitle, self.styles["ReportSubtitle"]))

        self._add_risk_banner()

    def _add_risk_banner(self):
        layered = self.layered_results.get("analysis_summary", {})
        af_summary = self.antiforensic_results.get("summary", {})

        critical = layered.get("critical", 0)
        high = layered.get("high", 0)
        medium = layered.get("medium", 0)
        suspicious = layered.get("suspicious_files", 0)

        if critical > 0:
            risk_level = "CRITICAL"
        elif high > 0:
            risk_level = "HIGH"
        elif medium > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        risk_color = SEVERITY_COLORS.get(risk_level, SEVERITY_COLORS["UNKNOWN"])
        bg_color = SEVERITY_BG_COLORS.get(risk_level, SEVERITY_BG_COLORS["UNKNOWN"])

        banner_text = f"""
        <b>OVERALL RISK ASSESSMENT: {risk_level}</b><br/>
        <small>Critical: {critical} | High: {high} | Medium: {medium} | Total Suspicious: {suspicious}</small>
        """

        banner_table = Table(
            [[banner_text]],
            colWidths=[7.5 * inch],
        )
        banner_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                    ("TEXTCOLOR", (0, 0), (-1, -1), risk_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 14),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("BOX", (0, 0), (-1, -1), 3, risk_color),
                ]
            )
        )
        self.elements.append(banner_table)
        self.elements.append(Spacer(1, 20))

    def _add_executive_summary(self):
        self.elements.append(
            Paragraph("1. EXECUTIVE SUMMARY", self.styles["SectionHeader"])
        )

        layered = self.layered_results.get("analysis_summary", {})
        total_files = layered.get("total_files_analyzed", 0)
        suspicious = layered.get("suspicious_files", 0)
        critical = layered.get("critical", 0)
        high = layered.get("high", 0)

        af_indicators = self.antiforensic_results.get("summary", {}).get(
            "total_indicators", 0
        )

        summary = f"""
        This forensic analysis examined <b>{total_files}</b> files from the disk image for evidence of 
        timestamp manipulation (timestomping) and anti-forensic techniques.
        
        <b>Key Findings:</b>
        <ul>
        <li>Files analyzed: {total_files}</li>
        <li>Suspicious files detected: <b>{suspicious}</b></li>
        <li>Critical severity: {critical}</li>
        <li>High severity: {high}</li>
        <li>Anti-forensic indicators: {af_indicators}</li>
        </ul>
        
        <b>Methodology:</b> The analysis uses a 4-layer correlation model:
        <ol>
        <li><b>Layer 1 (30%):</b> MFT $SI vs $FN timestamp comparison</li>
        <li><b>Layer 2 (30%):</b> USN Journal creation event verification</li>
        <li><b>Layer 3 (20%):</b> $LogFile transaction history analysis</li>
        <li><b>Layer 4 (20%):</b> External artifacts (future dates, volume correlation)</li>
        </ol>
        """
        self.elements.append(Paragraph(summary, self.styles["ReportBody"]))
        self.elements.append(Spacer(1, 10))

    def _add_extraction_details(self):
        self.elements.append(
            Paragraph("2. ARTIFACT EXTRACTION DETAILS", self.styles["SectionHeader"])
        )

        extraction = self.extraction_results
        partitions = extraction.get("partitions", [])

        self.elements.append(
            Paragraph(
                f"<b>Partitions Found:</b> {len(partitions)}", self.styles["ReportBody"]
            )
        )

        for i, part in enumerate(partitions):
            part_data = [
                ["Partition", str(i)],
                ["Slot", part.get("slot", "N/A")],
                ["Start Sector", part.get("start", "N/A")],
                ["Description", part.get("desc", "N/A")],
            ]
            part_table = Table(part_data, colWidths=[1.5 * inch, 4 * inch])
            part_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), HexColor("#f3f4f6")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#d1d5db")),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            self.elements.append(part_table)
            self.elements.append(Spacer(1, 8))

        extracted_files = extraction.get("extracted_files", {})
        self.elements.append(
            Paragraph("<b>Extracted Artifacts:</b>", self.styles["ReportBody"])
        )

        for category, files in extracted_files.items():
            if files:
                self.elements.append(
                    Paragraph(
                        f"• {category}: {len(files)} file(s)",
                        self.styles["FindingText"],
                    )
                )

        self.elements.append(Spacer(1, 10))

    def _add_layered_correlation_analysis(self):
        self.elements.append(
            Paragraph(
                "3. LAYERED TIMESTOMP CORRELATION ANALYSIS",
                self.styles["SectionHeader"],
            )
        )

        layered = self.layered_results
        summary = layered.get("analysis_summary", {})

        self.elements.append(
            Paragraph("<b>Analysis Summary:</b>", self.styles["ReportBody"])
        )

        summary_data = [
            ["Metric", "Value"],
            ["Total Files Analyzed", str(summary.get("total_files_analyzed", 0))],
            ["Suspicious Files", str(summary.get("suspicious_files", 0))],
            ["Critical Severity", str(summary.get("critical", 0))],
            ["High Severity", str(summary.get("high", 0))],
            ["Medium Severity", str(summary.get("medium", 0))],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#374151")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#d1d5db")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        self.elements.append(summary_table)
        self.elements.append(Spacer(1, 15))

        self.elements.append(
            Paragraph("<b>Detection Layers Explained:</b>", self.styles["ReportBody"])
        )

        layers_info = """
        <b>Layer 1 - SI/FN Mismatch (30% weight):</b><br/>
        Compares $Standard_Information timestamps with $File_Name timestamps.
        Timestomping tools often modify SI but forget FN, or vice versa.<br/><br/>
        
        <b>Layer 2 - USN Journal (30% weight):</b><br/>
        Compares file creation time with USN Journal FILE_CREATE events.
        USN journal is harder to fake and provides ground truth.<br/><br/>
        
        <b>Layer 3 - $LogFile (20% weight):</b><br/>
        Analyzes NTFS transaction log for SetFileInformation operations.
        May reveal modifications even if USN was cleared.<br/><br/>
        
        <b>Layer 4 - External Artifacts (20% weight):</b><br/>
        Checks for future timestamps, zero dates, and volume creation correlation.<br/><br/>
        
        <b>Layer 5 - Windows Event Logs (15% weight):</b><br/>
        Correlates file timestamps with Security/System event log entries.
        Files created AFTER latest event + 1 day, or 30+ days BEFORE earliest event are flagged.
        """
        self.elements.append(Paragraph(layers_info, self.styles["ReportBody"]))
        self.elements.append(Spacer(1, 10))

    def _add_timestomp_findings(self):
        self.elements.append(
            Paragraph("4. DETAILED TIMESTOMP FINDINGS", self.styles["SectionHeader"])
        )

        layered_findings = self.layered_results.get("suspicious_files", [])
        af_timestomp = self.antiforensic_results.get("timestomping", [])

        all_findings = layered_findings
        source = "layered"

        if not all_findings and af_timestomp:
            all_findings = af_timestomp
            source = "antiforensic"

        if not all_findings:
            self.elements.append(
                Paragraph("No timestomp anomalies detected.", self.styles["ReportBody"])
            )
            self.elements.append(Spacer(1, 10))
            return

        self.elements.append(
            Paragraph(
                f"<b>Total Suspicious Files: {len(all_findings)}</b> (Source: {source})",
                self.styles["ReportBody"],
            )
        )
        self.elements.append(Spacer(1, 5))

        for i, finding in enumerate(all_findings[:50], 1):
            self._add_timestomp_finding_detail(finding, i)

        if len(all_findings) > 50:
            self.elements.append(
                Paragraph(
                    f"... and {len(all_findings) - 50} more suspicious files",
                    self.styles["FindingText"],
                )
            )

        self.elements.append(Spacer(1, 10))

    def _add_timestomp_finding_detail(self, finding: Any, index: int):
        if isinstance(finding, str):
            finding_text = finding.replace("<", "&lt;").replace(">", "&gt;")
            header = f"[MEDIUM] Finding #{index}"
            header_data = [
                [
                    Paragraph(
                        header, self.styles.get("Normal", self.styles["ReportBody"])
                    )
                ]
            ]
            header_table = Table(header_data, colWidths=[7.5 * inch])
            header_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#fef08a")),
                        ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#ca8a04")),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 11),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("BOX", (0, 0), (-1, -1), 2, HexColor("#ca8a04")),
                    ]
                )
            )
            self.elements.append(header_table)
            self.elements.append(
                Paragraph(f"• {finding_text}", self.styles["FindingText"])
            )
            return

        severity = finding.get("severity", "UNKNOWN")
        sev_color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])
        bg_color = SEVERITY_BG_COLORS.get(severity, SEVERITY_BG_COLORS["UNKNOWN"])

        filename = finding.get("filename", "Unknown")
        file_ref = finding.get("file_reference", "N/A")
        score = finding.get("score", 0)
        explanation = finding.get("explanation", "No details")

        header = f"[{severity}] #{index}: {filename}"
        header_data = [
            [Paragraph(header, self.styles.get("Normal", self.styles["ReportBody"]))]
        ]
        header_table = Table(header_data, colWidths=[7.5 * inch])
        header_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                    ("TEXTCOLOR", (0, 0), (-1, -1), sev_color),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 2, sev_color),
                ]
            )
        )
        self.elements.append(header_table)

        details = f"""
        <b>File Reference:</b> {file_ref}<br/>
        <b>Anomaly Score:</b> {score:.1f}/100<br/>
        <b>Details:</b> {explanation}
        """
        self.elements.append(Paragraph(details, self.styles["FindingText"]))

        affected = finding.get("affected_layers", [])
        if affected:
            layers_text = "<b>Detection Layers Triggered:</b> " + ", ".join(affected)
            self.elements.append(Paragraph(layers_text, self.styles["FindingText"]))

        recommendation = finding.get("recommendation", "")
        if recommendation:
            self.elements.append(
                Paragraph(
                    f"<b>Recommendation:</b> {recommendation}",
                    self.styles["FindingText"],
                )
            )

        self.elements.append(Spacer(1, 8))

    def _add_antiforensic_analysis_detailed(self):
        self.elements.append(
            Paragraph(
                "5. ANTI-FORENSIC TECHNIQUE DETECTION", self.styles["SectionHeader"]
            )
        )

        af = self.antiforensic_results

        categories = [
            (
                "timestomping",
                "Timestomping Detection",
                "Manipulation of file timestamps",
            ),
            (
                "shadow_copy_deletion",
                "Shadow Copy Deletion",
                "Evidence of VSS deletion",
            ),
            ("hidden_streams", "Hidden Data Streams (ADS)", "Alternate Data Streams"),
            ("log_clearing", "Log Clearing Evidence", "Windows event log manipulation"),
            (
                "registry_tampering",
                "Registry Tampering",
                "Registry modification indicators",
            ),
            ("file_deletion", "File Deletion Tracking", "Deleted file evidence"),
            ("mft_anomalies", "MFT Anomalies", "Master File Table irregularities"),
        ]

        for key, title, description in categories:
            findings = af.get(key, [])
            self._add_antiforensic_category_detail(title, description, findings)

        self.elements.append(Spacer(1, 10))

    def _add_antiforensic_category_detail(
        self, title: str, description: str, findings: List
    ):
        count = len(findings)

        if count > 0:
            indicator_color = HexColor("#dc2626")
            status = f"[{count} FINDING{'S' if count != 1 else ''}]"
        else:
            indicator_color = HexColor("#16a34a")
            status = "[CLEAR - No indicators]"

        header_data = [[Paragraph(f"{title} {status}", self.styles["ReportBody"])]]
        header_table = Table(header_data, colWidths=[7.5 * inch])
        header_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        HexColor("#fef2f2") if count > 0 else HexColor("#f0fdf4"),
                    ),
                    ("TEXTCOLOR", (0, 0), (-1, -1), indicator_color),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("BOX", (0, 0), (-1, -1), 2, indicator_color),
                ]
            )
        )
        self.elements.append(header_table)

        self.elements.append(
            Paragraph(f"<i>{description}</i>", self.styles["FindingText"])
        )
        self.elements.append(Spacer(1, 5))

        if findings:
            for finding in findings[:20]:
                if isinstance(finding, dict):
                    message = finding.get("message", str(finding))
                    source_file = finding.get("source_file", "")
                    line_num = finding.get("line_number", "")
                    evidence = finding.get("evidence", "")
                    stream_name = finding.get("stream_name", "")
                    specific_paths = finding.get("specific_paths", [])
                    orphan_files = finding.get("orphan_file_names", [])

                    detail_parts = [f"• {message}"]
                    if source_file:
                        detail_parts.append(f"  <b>Source:</b> {source_file}")
                    if stream_name:
                        detail_parts.append(f"  <b>Stream:</b> {stream_name}")
                    if line_num:
                        detail_parts.append(f"  <b>Line:</b> {line_num}")
                    if evidence:
                        detail_parts.append(f"  <b>Evidence:</b> {str(evidence)[:80]}")
                    if orphan_files:
                        detail_parts.append(
                            f"  <b>Files:</b> {', '.join(orphan_files[:3])}"
                        )
                    if specific_paths:
                        detail_parts.append(
                            f"  <b>Paths:</b> {', '.join(specific_paths[:2])}"
                        )

                    finding_text = "<br/>".join(detail_parts)
                    self.elements.append(
                        Paragraph(finding_text, self.styles["FindingText"])
                    )
                else:
                    clean = str(finding).replace("<", "&lt;").replace(">", "&gt;")
                    self.elements.append(
                        Paragraph(f"• {clean}", self.styles["FindingText"])
                    )

            if len(findings) > 20:
                self.elements.append(
                    Paragraph(
                        f"  <i>... and {len(findings) - 20} more findings</i>",
                        self.styles["FindingText"],
                    )
                )
        else:
            self.elements.append(
                Paragraph(
                    "  ✓ No indicators found in this category",
                    self.styles["FindingText"],
                )
            )

        self.elements.append(Spacer(1, 10))

    def _add_ai_findings_detailed(self):
        self.elements.append(
            Paragraph("6. AI-POWERED ANALYSIS FINDINGS", self.styles["SectionHeader"])
        )

        findings = self.ai_results.get("findings", [])

        if not findings:
            self.elements.append(
                Paragraph(
                    "No AI findings generated (may require API key configuration).",
                    self.styles["ReportBody"],
                )
            )
            return

        self.elements.append(
            Paragraph(
                f"<b>Total AI Findings: {len(findings)}</b>", self.styles["ReportBody"]
            )
        )
        self.elements.append(Spacer(1, 5))

        for i, finding in enumerate(findings[:30], 1):
            severity = finding.get("severity", "UNKNOWN")
            sev_color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])
            bg_color = SEVERITY_BG_COLORS.get(severity, SEVERITY_BG_COLORS["UNKNOWN"])

            technique = finding.get("technique", "Unknown")
            evidence = finding.get("evidence", "N/A")
            explanation = finding.get("explanation", "N/A")
            confidence = finding.get("confidence", 0) * 100

            header = f"[{severity}] {technique} (Confidence: {confidence:.0f}%)"
            header_data = [[Paragraph(header, self.styles["ReportBody"])]]
            header_table = Table(header_data, colWidths=[7.5 * inch])
            header_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                        ("TEXTCOLOR", (0, 0), (-1, -1), sev_color),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            self.elements.append(header_table)

            content = f"<b>Evidence:</b> {evidence[:300]}..."
            self.elements.append(Paragraph(content, self.styles["FindingText"]))

            self.elements.append(Spacer(1, 3))

        self.elements.append(Spacer(1, 10))

    def _add_suspicious_files_table(self):
        self.elements.append(
            Paragraph("7. COMPLETE SUSPICIOUS FILES LIST", self.styles["SectionHeader"])
        )

        findings = self.layered_results.get("suspicious_files", [])

        if not findings:
            self.elements.append(
                Paragraph("No suspicious files identified.", self.styles["ReportBody"])
            )
            return

        self.elements.append(
            Paragraph(
                f"Listing all {len(findings)} suspicious files requiring investigation:",
                self.styles["ReportBody"],
            )
        )
        self.elements.append(Spacer(1, 10))

        header_data = [
            [
                Paragraph(h, self.styles["ReportBody"])
                for h in ["#", "Severity", "Filename", "Score", "Anomaly Type"]
            ]
        ]
        table_data = [header_data[0]]

        for i, f in enumerate(findings[:100], 1):
            severity = f.get("severity", "UNK")[:4]
            filename = f.get("filename", "Unknown")[:30]
            score = f.get("score", 0)
            explanation = f.get("explanation", "")[:30]

            table_data.append(
                [
                    Paragraph(str(i), self.styles["ReportBody"]),
                    Paragraph(severity, self.styles["ReportBody"]),
                    Paragraph(filename, self.styles["ReportBody"]),
                    Paragraph(f"{score:.1f}", self.styles["ReportBody"]),
                    Paragraph(explanation, self.styles["ReportBody"]),
                ]
            )

        if len(table_data) > 1:
            files_table = Table(
                table_data,
                colWidths=[0.4 * inch, 0.8 * inch, 3 * inch, 0.8 * inch, 2.5 * inch],
            )
            files_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1f2937")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("ALIGN", (0, 0), (0, -1), "CENTER"),
                        ("ALIGN", (3, 0), (3, -1), "CENTER"),
                        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#d1d5db")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )
            self.elements.append(files_table)

        self.elements.append(Spacer(1, 15))

    def _add_detailed_recommendations(self):
        self.elements.append(
            Paragraph("8. INVESTIGATION RECOMMENDATIONS", self.styles["SectionHeader"])
        )

        layered = self.layered_results.get("analysis_summary", {})
        suspicious = layered.get("suspicious_files", 0)

        recommendations = []

        if suspicious > 0:
            recommendations.extend(
                [
                    f"<b>URGENT:</b> Investigate {suspicious} files with timestamp anomalies immediately.",
                    "Review each suspicious file's full path and metadata.",
                    "Cross-reference with user's activity logs and network connections.",
                    "Check for known timestomping tools (Timestomp, FAR, etc.) on the system.",
                    "Examine Windows Event Logs for evidence of anti-forensic tool execution.",
                ]
            )

        recommendations.extend(
            [
                "Preserve the forensic image with proper chain of custody.",
                "Document all findings with screenshots and timestamps.",
                "Compare findings with known IOC databases.",
                "Check file contents for embedded payloads or malware.",
                "Interview system users about file origins if appropriate.",
                "Consider timeline reconstruction using Plaso or CrowdStrike.",
            ]
        )

        for i, rec in enumerate(recommendations, 1):
            self.elements.append(Paragraph(f"{i}. {rec}", self.styles["ReportBody"]))

        self.elements.append(Spacer(1, 15))

    def _add_investigator_checklist(self):
        self.elements.append(
            Paragraph("9. INVESTIGATOR ACTION CHECKLIST", self.styles["SectionHeader"])
        )

        checklist = [
            "☐ Document chain of custody for original evidence",
            "☐ Verify analysis environment integrity",
            "☐ Review critical severity findings immediately",
            "☐ Document all file paths with anomalies",
            "☐ Check for related files in same directories",
            "☐ Examine user account activity",
            "☐ Review network connections at anomaly timestamps",
            "☐ Check for malware/ransomware indicators",
            "☐ Interview relevant personnel",
            "☐ Preserve all logs and artifacts",
            "☐ Create backup of suspicious files",
            "☐ Document investigation steps taken",
            "☐ Generate incident report if warranted",
            "☐ Consider law enforcement referral if criminal activity detected",
        ]

        for item in checklist:
            self.elements.append(Paragraph(item, self.styles["ReportBody"]))

        self.elements.append(Spacer(1, 20))

        self.elements.append(
            Paragraph(
                "<i>Report generated by FreeKhana SIEM - NTFS Timestomp Detection System</i>",
                self.styles["FindingText"],
            )
        )
        self.elements.append(
            Paragraph(
                f"<i>Report ID: {datetime.now().strftime('%Y%m%d%H%M%S')}</i>",
                self.styles["FindingText"],
            )
        )


def generate_forensic_report(
    output_path: str,
    image_path: str,
    ai_results: Dict,
    antiforensic_results: Dict,
    layered_results: Dict = None,
    extraction_results: Dict = None,
) -> str:
    """Generate the forensic PDF report"""
    report = ForensicPDFReport(
        output_path=output_path,
        image_path=image_path,
        ai_results=ai_results,
        antiforensic_results=antiforensic_results,
        layered_results=layered_results,
        extraction_results=extraction_results,
    )
    return report.generate()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print(
            "Usage: python pdf_report_generator.py <output_path> <image_path> [json_results...]"
        )
        sys.exit(1)

    output_path = sys.argv[1]
    image_path = sys.argv[2]

    ai_results = {}
    antiforensic_results = {}
    layered_results = {}
    extraction_results = {}

    for json_file in sys.argv[3:]:
        if os.path.exists(json_file):
            with open(json_file) as f:
                data = json.load(f)
                if "findings" in data:
                    ai_results = data
                elif "summary" in data:
                    antiforensic_results = data
                elif "analysis_summary" in data:
                    layered_results = data
                elif "partitions" in data:
                    extraction_results = data

    generate_forensic_report(
        output_path=output_path,
        image_path=image_path,
        ai_results=ai_results,
        antiforensic_results=antiforensic_results,
        layered_results=layered_results,
        extraction_results=extraction_results,
    )
    print(f"Report generated: {output_path}")

import io
import json
import csv
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from apps.alerts.models import Alert
from apps.processes.models import ProcessLog
from apps.services.models import ServiceLog
from apps.eventlogs.models import WindowsEventLog

def generate_pdf_report(title="SOC Endpoint Security Report"):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )
    styles = getSampleStyleSheet()

    # Cyber dark & blue theme styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        textColor=colors.HexColor('#00E5FF'),
        spaceAfter=10
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#2979FF'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#333333'),
        spaceAfter=6
    )

    story = []
    story.append(Paragraph(title, title_style))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | <b>System:</b> Stitch Sentinel EDR Agent", body_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00E5FF'), spaceBefore=5, spaceAfter=15))

    # Executive Summary Section
    story.append(Paragraph("1. Executive Summary", heading_style))
    total_alerts = Alert.objects.count()
    critical_alerts = Alert.objects.filter(severity='CRITICAL').count()
    high_alerts = Alert.objects.filter(severity='HIGH').count()
    suspicious_services = ServiceLog.objects.filter(is_suspicious=True).count()
    total_procs = ProcessLog.objects.values('pid').distinct().count()

    exec_text = f"""
    This executive security summary presents endpoint monitoring findings for host <b>WIN-EDR-AGENT-01</b>.<br/>
    During the observation window, <b>{total_alerts} security alerts</b> were raised (<b>{critical_alerts} Critical</b>, <b>{high_alerts} High</b> severity).
    A total of <b>{total_procs} active processes</b> and <b>{suspicious_services} suspicious Windows services</b> were audited.
    """
    story.append(Paragraph(exec_text, body_style))
    story.append(Spacer(1, 10))

    # Alert Table Section
    story.append(Paragraph("2. Top Security Alerts & MITRE ATT&CK Mapping", heading_style))
    alerts = Alert.objects.all().order_by('-timestamp')[:10]
    
    table_data = [["Severity", "Alert Title", "MITRE Technique", "Status", "Timestamp"]]
    for a in alerts:
        table_data.append([
            a.severity,
            a.title[:35],
            a.mitre_technique[:25],
            a.status,
            a.timestamp.strftime('%H:%M:%S')
        ])

    alert_table = Table(table_data, colWidths=[65, 200, 140, 60, 65])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#051424')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00E5FF')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
    ]))
    story.append(alert_table)
    story.append(Spacer(1, 15))

    # Recommendations
    story.append(Paragraph("3. SOC Recommendations", heading_style))
    rec_text = """
    • <b>Isolate & Remediate:</b> Immediately review and terminate processes associated with Critical severity alerts.<br/>
    • <b>Service Audit:</b> Inspect unquoted service paths and replace binary executables running out of Temp directories.<br/>
    • <b>Event Log Policy:</b> Enable Sysmon Process Access logging (Event ID 10) to detect LSASS credential dumping.<br/>
    • <b>IOC Sync:</b> Maintain daily synchronization of external C2 IP addresses and file hash blocklists.
    """
    story.append(Paragraph(rec_text, body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

def generate_csv_report():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Alert ID", "Severity", "Title", "Hostname", "Username", "Description", "MITRE Technique", "Status", "Timestamp"])
    
    for a in Alert.objects.all().order_by('-timestamp'):
        writer.writerow([
            a.id, a.severity, a.title, a.hostname, a.username, a.description, a.mitre_technique, a.status, a.timestamp.isoformat()
        ])
    return output.getvalue()

def generate_json_report():
    data = {
        "report_title": "Stitch Sentinel EDR Security Audit Report",
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_alerts": Alert.objects.count(),
            "critical_alerts": Alert.objects.filter(severity='CRITICAL').count(),
            "high_alerts": Alert.objects.filter(severity='HIGH').count(),
            "total_processes": ProcessLog.objects.count(),
            "suspicious_services": ServiceLog.objects.filter(is_suspicious=True).count()
        },
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "hostname": a.hostname,
                "description": a.description,
                "mitre_technique": a.mitre_technique,
                "status": a.status,
                "timestamp": a.timestamp.isoformat()
            } for a in Alert.objects.all()[:50]
        ]
    }
    return json.dumps(data, indent=2)

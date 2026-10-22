# PowerPoint Presentation Slides Outline

Use this outline to structure the PowerPoint (PPT) presentation deck for your internship project defense.

---

### Slide 1: Title Slide
- **Title**: Stitch Sentinel: Windows Endpoint EDR Agent & SOC Dashboard
- **Subtitle**: Windows Service & Process Monitoring Agent (Internship Submission)
- **Author**: [Your Name]
- **Date**: [Date]

### Slide 2: Project Context & Goal
- **Problem**: Modern malware abuses Windows startup services and uses Living-off-the-Land Binaries (LOLBins) to establish persistence.
- **Solution**: A lightweight EDR agent coupled with a dynamic Django SOC console for real-time monitoring, triage, and reporting.

### Slide 3: Technical Architecture
- **Agent Component**: Multi-threaded Python daemon monitoring processes (`psutil`), services, event logs (`pywin32`), and system metrics.
- **Backend Component**: Django REST Framework, JWT Session Authentication, SQLite/PostgreSQL Database, PDF ReportLab Engine.
- **Frontend Design**: "Midnight Protocol" cybersecurity dark theme, Chart.js live analytics, and DataTables.

### Slide 4: Key Detection Capabilities
- **T1566.001 - spear-phishing**: Flags Office applications spawning scripts/shells.
- **T1543.003 - persistence**: Detects unquoted service paths and startup service updates.
- **T1003.001 - dumping**: Detects Sysmon Event ID 10 LSASS memory reads.
- **T1070.001 - evasion**: Triggers critical alerts if Event ID 1102 ("Audit Log Cleared") is registered.

### Slide 5: SOC Dashboard Walkthrough
- Real-time Alert queue with severity tags (Critical, High, Medium, Low).
- Interactive process tree visualizer showing parent-child chains.
- Live resource utilization graphs (CPU/RAM telemetry trendlines).

### Slide 6: Key Implementation Highlights
- **Offline Telemetry Buffer**: Automatically caches up to 500 events locally if connection is lost.
- **CSV IOC Import**: Bulk ingestion of Threat Intelligence hashes and IPs.
- **Report Generation**: Dynamically compiles PDF executive summaries with ReportLab.

### Slide 7: Project Impact & Summary
- Fully functional prototype suitable for SMB endpoint protection.
- High efficiency (low memory footprint, minimal polling overhead).
- Future additions: Automatic host containment via Windows Defender Firewall.

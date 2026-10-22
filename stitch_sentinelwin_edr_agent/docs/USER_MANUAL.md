# Stitch Sentinel - Operational User Manual

Welcome to the Stitch Sentinel EDR & SOC Management Console operational manual. This document guides SOC analysts and system administrators through using the dashboard features.

## Section 1: Authentication & Access Control

1. Navigate to the portal URL (`http://127.0.0.1:8000/`).
2. Input credentials:
   - **Operator Username**: `admin`
   - **Password**: `admin123`
3. Click **Authenticate Session** to load the SOC Workbench.

## Section 2: SOC Dashboard View

The dashboard serves as the central pane of glass for security operations:
- **Alert Indicators**: Displays color-coded counts for Critical, High, Medium, and Low severity alerts.
- **Resource Sparklines**: View system CPU/RAM usage levels.
- **Threat Event Stream**: Lists real-time threat notifications, including MITRE mapping and hostname origin.

## Section 3: Process Explorer

Click on the **Processes** tab:
- **Interactive Matrix**: Lists all active endpoint processes with parent PIDs, user context, and binary execution paths.
- **Process Actions**: Clicking **Details** triggers a modal showing complete invocation arguments and digital signature status.
- **Triage**: Highlights in red any executables running from Temp or AppData folders.

## Section 4: Incident Investigation Workbench

Under **SOC Investigation**:
- **Process Parentage Graph**: Inspect the multi-level child process execution tree (e.g. `winword.exe` -> `powershell.exe` -> `mimikatz.exe`).
- **Timeline Logs**: Correlates alerts and event logs by their exact timestamp, helping analysts trace attack flow chronologically.

## Section 5: Threat Intelligence & IOCs

Under **IOC Management**:
- **Rule Set**: Lists active SHA256/MD5 hashes, IP addresses, domains, and process names.
- **Add Indicator**: Manually add custom hash blocklists.
- **Import CSV**: Bulk load IOCs from security threat feeds using the CSV uploader.

# Internship Project Report: Windows Service & Process Monitoring Agent (Stitch Sentinel)

---

## 1. Abstract
This project report details the design, implementation, and evaluation of **Stitch Sentinel**, a lightweight Endpoint Detection and Response (EDR) agent system. The solution comprises a multi-threaded Python system daemon deployed on Windows endpoints and a centralized Django REST web console for SOC analytics, threat triage, and incident containment. Over the course of the internship, a rules engine mapping to the MITRE ATT&CK framework was engineered alongside a digital forensic process tree analyzer, enabling real-time detection of cyber threats such as spear-phishing payloads, privilege escalations, persistence mechanism abuse, and credential dumps.

---

## 2. Problem Statement & Motivation
Modern threat actors continuously target corporate endpoints, abusing legitimate Windows management frameworks (Living off the Land) to execute fileless malware, bypass security controls, and establish persistent footholds. Endpoint protection platforms must capture telemetry from process actions, services, and Windows event log streams continuously. 

This project aims to deliver a functional, lightweight EDR prototype capable of:
1. Auditing live process creations, execution paths, and parent-child execution patterns.
2. Detecting startup service additions, changes, and vulnerability pathways (e.g. unquoted paths, temp folders).
3. Centralizing forensic event indicators and logs for SOC analysis.
4. Integrating a rule-based engine mapping detections to MITRE ATT&CK techniques.

---

## 3. System Architecture & Methodology
Stitch Sentinel employs an agent-server split architecture:
- **Python EDR Agent**: Runs as a local daemon. Utilizes `psutil` and native Win32 API handles via `pywin32` to capture running processes, service registry configurations, and Security event channels. Enforces real-time hash checks against local IOC threat feeds.
- **Django REST Server**: Ingests JSON telemetry payloads securely using JSON Web Token (JWT) signatures. Evaluates incoming alerts and provides a responsive dark-theme SOC dashboard using Bootstrap 5, Chart.js, and DataTables.

```
+------------------+                   +--------------------+
|  Windows EDR     | --(JWT Telemetry)--> |  Django REST Server|
|  Agent (Python)  |                      |  SOC Dashboard UI  |
|  [Telemetry]     | <-- (Sync Rules) --- |  [Database Engine] |
+------------------+                   +--------------------+
```

---

## 4. Detection Methodologies & Rules Engine
The detection engine covers several target attack techniques:
1. **LOLBin Abuse**: Detects PowerShell executing with credential bypass parameters (`-ExecutionPolicy Bypass`).
2. **Suspicious Parent-Child Trees**: Flags Microsoft Office binaries (`winword.exe`, `excel.exe`) spawning command shell interpreters.
3. **Defense Evasion**: Monitors Security event channel logs for Event ID 1102 ("Audit Log Cleared").
4. **Credential Dumping**: Evaluates Sysmon logs for Event ID 10 indicating unauthorized LSASS process memory reads.

---

## 5. Implementation & Code Specifications
The complete modular Python implementation of the agent uses an API client with an offline buffer to store telemetry logs during network outages. The Django backend uses custom REST ViewSets and API ingestion views that parse incoming telemetry, run the rule evaluation engine, and write alerts dynamically to the database.

---

## 6. Test Evaluation & Validation
Validation was performed using simulated test vectors:
- Spawning dummy processes from Temp paths.
- Running mock processes mimicking LOLBins.
- Executing the test suite:
  ```bash
  python manage.py test
  ```
The test suite validated all endpoints, token auth mechanisms, data models, and rule detection thresholds.

---

## 7. Conclusion & Future Enhancements
Stitch Sentinel successfully demonstrates the viability of modular, low-overhead endpoint monitoring systems. Future iterations will include automated endpoint quarantine actions (host isolation via Windows Firewall API), real-time process memory scanning (YARA integration), and heuristic anomaly detection using machine learning.

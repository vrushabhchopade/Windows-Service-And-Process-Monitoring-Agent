# Viva Voce (Project Defense) Questions & Answers

Prepare for your project defense using the following sample questions and answers.

---

### Q1: What is a Living-off-the-Land Binary (LOLBin) and how does your agent detect them?
**A**: LOLBins are legitimate binaries signed by Microsoft that are native to the Windows OS (like `powershell.exe`, `certutil.exe`, `mshta.exe`) but are abused by threat actors for evasion. The agent monitors parent-child execution chains using `psutil`. If a web browser or Office application spawns a shell or script tool with bypass arguments, the agent detects and flags the abnormal relationship.

### Q2: Why did you choose Django and Django REST Framework (DRF) for the backend?
**A**: Django offers built-in security features (such as CSRF protection and SQL injection mitigation), a built-in Object-Relational Mapper (ORM) for quick database queries, and modular application structures. DRF allows us to build RESTful endpoints with standard JWT validation for secure telemetry ingestion.

### Q3: Explain the offline buffering mechanism in your agent.
**A**: In `agent/api_client.py`, the agent uses a Python `deque` double-ended queue with a maximum limit of 500 entries. If a telemetry POST fails due to network outage, the payload is appended to the queue. When a connection is re-established, the agent iterates through the queue and flushes the cached payloads.

### Q4: How does the agent discover unquoted service paths?
**A**: The agent queries the Windows Service Control Manager. It looks at the binary path string of each service. If the path contains spaces but is not surrounded by quotes, the agent flags this as a potential vulnerability. Windows evaluates unquoted paths in order, meaning a malicious binary placed in a parent folder (like `C:\Program.exe` instead of `C:\Program Files\...`) could hijack execution.

### Q5: How do you map security detections to the MITRE ATT&CK framework?
**A**: Every rule evaluated in `agent/process_monitor.py` and `agent/service_monitor.py` maps to specific MITRE IDs (e.g. T1059 for PowerShell execution, T1543.003 for Windows Services). These IDs are sent along with the telemetry payload and displayed on the SOC dashboard.

### Q6: What Windows Event IDs are monitored, and why?
**A**:
- **1102**: Security Log Cleared (indicates defense evasion).
- **4625**: Failed Logons (indicates brute force).
- **7045**: New Windows Service Installed (indicates persistence).
- **Sysmon ID 10**: LSASS memory read (indicates credential dumping tools like Mimikatz).

### Q7: How does the IOC threat engine function?
**A**: The agent retrieves the active Indicators of Compromise (hashes, process names, domain lists) from the Django REST backend. It then matches live processes, command-line arguments, and files against these values. Any match generates a critical alert instantly on the backend dashboard.

### Q8: What database is used, and how does it scale?
**A**: For development, the system runs on SQLite. For production workloads, the system is fully compatible with PostgreSQL. The database connection can be configured via the `DATABASE_URL` environment variable.

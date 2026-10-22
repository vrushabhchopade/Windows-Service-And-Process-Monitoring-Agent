# Project Demonstration Video Script

This guide outlines a walkthrough script for presenting a live product demonstration of the Stitch Sentinel EDR Agent & SOC Dashboard.

---

## Part 1: Project Introduction & Abstract (0:00 - 1:00)
- **Visual**: Show the flagship Github repository.
- **Narrator**: *"Hello everyone. Today I am demonstrating my internship project, Stitch Sentinel, a lightweight Windows Endpoint Detection & Response (EDR) agent system. This solution contains a modular Python background agent and a Django-based SOC Analyst Dashboard using the Midnight Protocol cybersecurity design theme."*

---

## Part 2: Starting the Backend Dashboard (1:00 - 2:30)
- **Visual**: Open the terminal and launch the Django service.
- **Narrator**: *"I will first run the database migrations and seed the system with live mock data. Then we will start the Django development web server."*
- **Action**: Run:
  ```bash
  python backend/manage.py migrate
  ```
  ```bash
  python backend/manage.py seed_data
  ```
  ```bash
  python backend/manage.py runserver
  ```
- **Visual**: Open browser at `http://127.0.0.1:8000/login/`. Log in with username `admin` and password `admin123`. Show the responsive dashboard loaded with metrics.

---

## Part 3: Running the EDR Agent (2:30 - 4:00)
- **Visual**: Open a new command prompt windows next to the browser.
- **Narrator**: *"Next, let's run the Python EDR agent. It authenticates using JWT tokens, fetches active IOC threat blocklists, and begins scanning running processes, services, and event log entries."*
- **Action**: Run:
  ```bash
  python agent/main.py
  ```
- **Visual**: Show agent terminal logs outputting telemetry details. Highlight the browser dashboard updating CPU usage charts and adding new alerts.

---

## Part 4: Threat Detection & IOC Verification (4:00 - 6:00)
- **Visual**: Click on the **Processes** and **Alerts Queue** tabs.
- **Narrator**: *"In the Alerts view, we can see real-time alert triggers. Notice this Critical alert: 'Unauthorized Blacklisted Process: mimikatz.exe'. It contains an exact description, MITRE ATT&CK technique reference, and containment recommendations. We can also view the complete process execution hierarchy in our SOC Investigation workbench."*
- **Visual**: Go to **SOC Investigation** tab. Show the process parent-child tree showing `winword.exe` spawning `powershell.exe`.

---

## Part 5: Conclusion & Report Exports (6:00 - end)
- **Visual**: Click on the **Reports** tab. Click "Download PDF Report". Open the generated PDF file.
- **Narrator**: *"Finally, the system supports generating executive PDF, CSV, and JSON security audits. Here is the PDF compiled dynamically by our report generator engine. This concludes the demonstration. Thank you."*

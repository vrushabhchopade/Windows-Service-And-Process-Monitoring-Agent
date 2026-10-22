# Stitch Sentinel - Windows Service & Process Monitoring Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](https://python.org)
[![Django Version](https://img.shields.io/badge/Django-5.0+-navy.svg)](https://djangoproject.com)
[![Platform Compatibility](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%28Dev%29-cyan.svg)](#)

Stitch Sentinel is a production-grade, lightweight Endpoint Detection & Response (EDR) agent system. It pairs a multi-threaded Python system daemon for Windows endpoints with a high-performance Django REST and Bootstrap 5 "Midnight Protocol" SOC Dashboard.

## Features

- **Process Auditing**: Captures PID, PPID, executable path, user context, cmdline arguments, hash calculations (MD5/SHA256), and CPU/RAM usage.
- **Parent-Child Process Trees**: Builds a complete execution hierarchy to detect LOLBin abuse (e.g., `winword.exe` -> `powershell.exe`).
- **Windows Service Auditing**: Flags unquoted paths, services running out of Temp/AppData folders, weak permissions, and stopped critical security services.
- **Event Log Ingestor**: Monitored Event IDs (4624, 4625, 4688, 1102, 7045, etc.) from Security, Sysmon, Defender, and System channels.
- **IOC Threat Intel Engine**: Runs real-time system matching against active indicators (MD5, SHA256, domain, IP, filename, cmdline).
- **"Midnight Protocol" Dashboard**: Dark-mode SOC analyst UI featuring live Chart.js statistics, interactive tables, and incident timeline logs.

## Directory Structure

```
stitch_sentinelwin_edr_agent/
├── agent/                # Multi-threaded Python monitoring agent
├── backend/              # Django backend & REST APIs
│   ├── apps/             # Modular applications
│   ├── static/           # CSS & JS assets
│   └── templates/        # Dashboard layout views
├── docs/                 # Operational guides & specifications
├── reports/              # Internship deliverables (Report, PPT, Viva prep)
├── tests/                # Verification test suites
└── installer/            # Packaging and service installation scripts
```

## Quick Start

### 1. Set Up Backend Server
```bash
# Clone the repository and install dependencies
pip install -r requirements.txt

# Run migrations and seed live mock data
python backend/manage.py migrate
python backend/manage.py seed_data

# Run developer server
python backend/manage.py runserver
```
Navigate to `http://127.0.0.1:8000/` and authenticate using:
- **Username**: `admin`
- **Password**: `admin123`

### 2. Launch EDR Agent
```bash
# Run one-pass telemetry collection
python agent/main.py --once

# Run continuous background monitoring loop
python agent/main.py
```

## Documentation

Full project manuals and deliverables are available in:
- [Installation Guide](docs/INSTALLATION_GUIDE.md)
- [User Manual](docs/USER_MANUAL.md)
- [Detection Rules Specifications](docs/DETECTION_RULES.md)
- [API Reference](docs/API_DOCUMENTATION.md)
- [Internship Project Report](reports/PROJECT_REPORT.md)

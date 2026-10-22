# Windows Service & Process Monitoring Agent - Technical Documentation

## 1. Project Overview
A production-ready Windows Endpoint Detection & Response (EDR) style agent built with Python, paired with a Django-based SOC Dashboard for monitoring, investigation, and alerting.

## 2. Agent Architecture (Python)
The agent runs as a background service using `pywin32` and `psutil`.

### Core Modules:
- **`process_monitor.py`**: Hooks into process creation/termination. Maps parent-child trees and detects LOLBins (powershell.exe, mshta.exe).
- **`service_monitor.py`**: Audits `win32service`. Detects new/stopped services and suspicious binary paths.
- **`ioc_engine.py`**: Scans running processes and files against SHA256 hashes, IPs, and domains retrieved from the backend.
- **`api_client.py`**: Securely transmits JSON telemetry via JWT-authenticated REST APIs.

## 3. Backend Architecture (Django)
- **Django REST Framework**: Handles endpoint ingestion and IOC management.
- **Channels (Optional)**: Provides real-time websocket updates to the dashboard charts.
- **Database**: PostgreSQL (Production) / SQLite (Dev). Optimized for time-series event data.

## 4. Detection Logic
- **Suspicious Parentage**: Flagging `winword.exe -> cmd.exe`.
- **Malicious Paths**: Monitoring `\Temp\` or `\AppData\Local\` for unauthorized execution.
- **Service Persistence**: Identifying new services created with SYSTEM privileges.

## 5. Security Features
- **JWT Auth**: Agent-Backend communication is encrypted and signed.
- **Rate Limiting**: Throttles telemetry to prevent DoS.
- **Input Sanitization**: Strict validation on all incoming telemetry.
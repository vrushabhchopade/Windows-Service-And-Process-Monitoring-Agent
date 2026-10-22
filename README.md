# SentinelShield: Advanced Intrusion Detection & Web Protection System

[![Python Version](https://img.shields.io/badge/Python-3.12+-brightgreen.svg)](https://python.org)
[![FastAPI Version](https://img.shields.io/badge/FastAPI-0.115+-blue.svg)](https://fastapi.tiangolo.com)
[![Frontend](https://img.shields.io/badge/Frontend-Google%20Stitch%20HUD-cyan.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-25%20Passing-success.svg)](#)

SentinelShield is an enterprise-grade full-stack Web Application Firewall (WAF) and Intrusion Detection System (IDS). It pairs a high-performance Python FastAPI backend with an authentic **Google Stitch** "Cyber Defense Operations" HUD Glassmorphism dashboard.

---

## Key Features

- **Inline Web Application Firewall (WAF)**: Intercepts and blocks malicious HTTP requests before execution.
- **Intrusion Detection Engine**: Rule-based regex pattern matcher with safe recursive URL input normalization.
- **OWASP Top 10 Attack Detection**:
  - **SQL Injection (SQLi)**: UNION-based, boolean tautologies (`OR 1=1`), stacked DDL queries (`; DROP TABLE`), and blind time delay extraction.
  - **Cross-Site Scripting (XSS)**: Explicit `<script>` tags, inline DOM event handlers (`onload=`, `onerror=`), and SVG/IMG payload vectors.
  - **Directory Traversal & Local File Inclusion (LFI)**: Relative path navigation (`../../etc/passwd`, `win.ini`) and PHP stream wrappers.
  - **Command Injection (RCE)**: Shell metacharacter chaining (`; whoami`, `| cat`, `powershell -enc`).
  - **Automated Security Scanners**: Detection of tools like `sqlmap`, `nikto`, `masscan`, `nmap`, and `dirbuster`.
- **Sliding Window Rate Limiter**: Per-IP request frequency tracking with configurable limits, burst budgets, and HTTP 429 penalties.
- **Incident Queue & Security Alerts**: Full alert lifecycle management (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) with analyst forensic notes.
- **IP Reputation & Dynamic Blocklist**: Threat intelligence scoring (0–100), Tor exit node classification, and instant edge firewall drop enforcement.
- **Live Interactive Threat Testing Console**: Test custom payloads or attack presets and receive instant verdict, confidence scores, and SOC Playbook guidance.
- **Reports & Exporting**: Executive threat posture reports with direct CSV and JSON audit log downloads.

---

## Architecture Overview

```
+---------------------------------------------------------------------------------------+
|                                  FRONTEND LAYER                                       |
|  - Google Stitch Cyber Defense HUD Glassmorphism Design System                        |
|  - Tailwind CSS + Inter & JetBrains Mono Typography + Material Symbols Outlined       |
|  - 11 Dynamic SOC Views (Dashboard, Traffic, Detection, Alerts, Logs, IPs, etc.)     |
|  - Centralized API Service Client (frontend/src/api.js)                               |
+-------------------------------------------+-------------------------------------------+
                                            │ REST API (JSON)
                                            ▼
+---------------------------------------------------------------------------------------+
|                                  BACKEND API LAYER                                    |
|  FastAPI (ASGI) + Uvicorn + Pydantic v2 Validation                                     |
|  - CORS Middleware configured for http://localhost:5173 & http://127.0.0.1:8000        |
|  - Real-Time WAF Inspection Middleware (backend/app/middleware/waf_middleware.py)      |
|  - Sliding-Window Rate Limiting Engine (backend/app/services/ratelimit_service.py)     |
+-------------------------------------------+-------------------------------------------+
                                            │
         ┌──────────────────────────────────┴───────────────────────────────────┐
         ▼                                                                      ▼
+───────────────────────────────────+                 +─────────────────────────────────+
|      WAF & IDS DETECTION ENGINE   |                 |    SQLITE PERSISTENT DATABASE   |
| - Safe Recursive URL Normalization|                 | SQLAlchemy 2.0 ORM              |
| - Precompiled Regex Rulesets      |                 | - HTTPRequestLog                |
| - Benign Pattern Whitelist        |                 | - SecurityEvent                 |
| - Playbook Guidance Generation    |                 | - SecurityAlert                 |
+───────────────────────────────────+                 | - WAFRule & IPReputation        |
                                                      +─────────────────────────────────+
```

---

## Directory Structure

```text
stitch_sentinelwin_edr_agent/
│
├── backend/                              # Python FastAPI Backend
│   ├── app/
│   │   ├── main.py                       # FastAPI entry point, CORS & middleware
│   │   ├── config.py                     # Environment configuration
│   │   ├── database.py                   # SQLAlchemy engine and session setup
│   │   ├── models/models.py              # Database ORM models
│   │   ├── schemas/schemas.py            # Pydantic validation schemas
│   │   ├── detection/
│   │   │   ├── engine.py                 # Normalization and inspection logic
│   │   │   └── rules.py                  # OWASP detection signature definitions
│   │   ├── middleware/
│   │   │   └── waf_middleware.py         # Starlette HTTP request inspector middleware
│   │   ├── services/
│   │   │   └── ratelimit_service.py      # Sliding window IP rate limiter
│   │   ├── utils/helpers.py              # Trusted proxy extraction & data redaction
│   │   └── routers/                      # REST API endpoints (10 routers)
│   ├── tests/                            # Pytest automated test suite (25 tests)
│   ├── requirements.txt                  # Python dependencies
│   ├── seed.py                           # Safe demonstration data generator
│   └── sentinelshield.db                 # SQLite development database
│
└── frontend/                             # Google Stitch Frontend Application
    ├── index.html                        # SOC Dashboard Single Page Application
    ├── package.json                      # Frontend scripts
    ├── vite.config.js                    # Vite dev server with /api proxy
    └── src/
        ├── api.js                        # Centralized API service client
        └── app.js                        # Client-side router and UI controller
```

---

## Quick Start Guide (Windows PowerShell)

### 1. Open Terminal in Project Root
```powershell
cd c:\Users\Lenovo\OneDrive\Desktop\stitch_sentinelwin_edr_agent
```

### 2. Initialize Database & Seed Demonstration Records
```powershell
.\.venv\Scripts\python.exe backend\seed.py
```

### 3. Run Automated Tests
```powershell
.\.venv\Scripts\pytest.exe backend\tests -v
```
*(All 25 unit and integration tests will pass)*

### 4. Start the FastAPI Backend Server
```powershell
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Start the Frontend (In a second PowerShell window)
```powershell
cd c:\Users\Lenovo\OneDrive\Desktop\stitch_sentinelwin_edr_agent\frontend
npm run dev
```

### 6. Open in Browser
- **SentinelShield SOC Frontend:** [http://localhost:5173](http://localhost:5173) (or directly via [http://127.0.0.1:8000](http://127.0.0.1:8000))
- **Interactive Swagger API Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check Endpoint:** [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

## Demonstration Examples

### 1. Interactive Detection Console
Navigate to **Attack Detection** (`#attack-detection-center`) in the dashboard:
1. Click **"SQLi: UNION SELECT"**.
2. Click **"Analyze Request"**.
3. View the immediate response: verdict `BLOCKED`, rule `WAF-SQLI-001`, execution latency `< 0.1ms`, and SOC Playbook recommendation.

### 2. Live Inline WAF Interception
Try sending an attack query parameter in your browser:
```text
http://127.0.0.1:8000/api/users?id=1%20UNION%20SELECT%201,2
```
The WAF middleware intercepts the request before reaching your application and returns **HTTP 403 Forbidden** with an alert detailing the matched rule and attack classification.

---

## License

This project is open-source under the MIT License.

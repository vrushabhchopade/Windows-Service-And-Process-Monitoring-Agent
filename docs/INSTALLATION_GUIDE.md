# Installation and Deployment Guide

This document describes the step-by-step setup, configuration, and launch procedures for the Stitch Sentinel Windows EDR Agent and Django SOC Backend.

## Prerequisites

- **Python**: Version 3.11 or newer.
- **Operating System**: Windows 10/11 (for the agent), Cross-platform (for the backend).
- **Libraries**: Visual Studio C++ Build Tools (required for compiling certain python packages like `pywin32` on local systems).

---

## Local Installation

### Step 1: Clone Repository & Create Virtual Environment
```bash
git clone https://github.com/internship-submissions/stitch-sentinel-edr.git
cd stitch-sentinel-edr
python -m venv venv
venv\Scripts\activate
```

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Initialize Database & Seeding
```bash
# Run database migrations
python backend/manage.py migrate

# Seed default admin, IOC lists, and telemetry alerts
python backend/manage.py seed_data
```

### Step 4: Run Django SOC Dashboard
```bash
python backend/manage.py runserver
```
Open `http://127.0.0.1:8000/` and sign in using `admin / admin123`.

---

## EDR Agent Deployment

### Option A: Run directly as Python script
```bash
# Run one telemetry pass
python agent/main.py --once

# Run continuous loop
python agent/main.py
```

### Option B: Build Standalone Executable
Run the batch compiler script to build the standalone binary:
```bash
cd installer
build.bat
```
The compiled executable will be generated at `installer/dist/stitch_agent.exe`.

### Option C: Run EDR Agent as Windows Background Service
Run the service installation script with administrator rights:
```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\installer\install_service.ps1
```

---

## Docker Containment Deployments

To run the backend server in Docker:
```bash
docker-compose up --build
```
This launches a PostgreSQL database container alongside the Django web application.

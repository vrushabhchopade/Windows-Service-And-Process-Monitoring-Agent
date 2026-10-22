# Troubleshooting & Diagnostic Guide

If you encounter issues while deploying or operating the Stitch Sentinel EDR Agent and Dashboard, follow the diagnostic steps outlined below.

---

## 1. Agent Connection Failures

### Symptom: Agent log shows `[-] Failed to connect` or HTTP errors
- **Diagnostic Check**: Ensure the Django backend service is running and accessible:
  ```bash
  curl -I http://127.0.0.1:8000/api/v1/ioc/
  ```
- **Resolution**:
  - Update `backend_url` inside `config/config.json` to point to the correct IP address/port of the backend.
  - Verify that the agent username and password in `config/config.json` match the credentials in Django. Run the seeding script to restore default credentials:
    ```bash
    python backend/manage.py seed_data
    ```

---

## 2. Event Log Monitoring Failures on Non-Windows Platforms

### Symptom: `win32evtlog query failed` or empty Event log arrays
- **Context**: The `pywin32` library depends on native Windows APIs. Running the agent on Linux/macOS developer environments triggers a mock event log generator.
- **Diagnostic Check**: Run the agent with debugging enabled:
  ```bash
  python agent/main.py --once
  ```
- **Resolution**: This behavior is by design to ensure cross-platform development compatibility. In production, compile the agent using the `build.bat` script and deploy exclusively on Windows targets.

---

## 3. Windows Service Registration Failures

### Symptom: PowerShell service installer throws execution policy exceptions
- **Diagnostic Check**: Run the PowerShell command-line as an Administrator and check policy status:
  ```powershell
  Get-ExecutionPolicy -List
  ```
- **Resolution**: Temporarily bypass execution controls for the deployment session:
  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process
  .\installer\install_service.ps1
  ```

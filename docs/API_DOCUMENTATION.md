# Stitch Sentinel - Django REST API Reference

Stitch Sentinel uses a JWT-authenticated REST API for telemetry ingestion and rule synchronization.

---

## 1. Authentication Endpoints

### Operator Login
- **Endpoint**: `POST /api/v1/auth/login/`
- **Request Payload**:
  ```json
  {
    "username": "admin",
    "password": "admin123"
  }
  ```
- **Response**:
  ```json
  {
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "username": "admin",
    "is_staff": true
  }
  ```

---

## 2. Telemetry Ingestion Endpoints

### Process Log Ingestion
- **Endpoint**: `POST /api/v1/telemetry/process/`
- **Request Payload**:
  ```json
  {
    "hostname": "WIN-EDR-AGENT-01",
    "processes": [
      {
        "pid": 5890,
        "ppid": 5512,
        "name": "powershell.exe",
        "parent_name": "winword.exe",
        "username": "CORP\\jsmith",
        "exe_path": "C:\\Windows\\System32\\powershell.exe",
        "cmdline": "powershell.exe -ExecutionPolicy Bypass",
        "cpu_percent": 12.5,
        "memory_percent": 5.4,
        "is_in_temp": false,
        "is_signed": true,
        "suspicious_flags": [
          {
            "type": "SUSPICIOUS_PARENT_CHILD",
            "severity": "HIGH",
            "description": "Suspicious parent-child execution chain: winword.exe -> powershell.exe"
          }
        ]
      }
    ],
    "ioc_matches": []
  }
  ```
- **Response**: `201 Created`

---

## 3. Threat Intelligence IOC Endpoints

### Get Active IOC Rules
- **Endpoint**: `GET /api/v1/ioc/`
- **Response**:
  ```json
  [
    {
      "id": 1,
      "ioc_type": "ProcessName",
      "value": "mimikatz.exe",
      "severity": "CRITICAL",
      "description": "LSASS Credential Dumper",
      "is_enabled": true
    }
  ]
  ```

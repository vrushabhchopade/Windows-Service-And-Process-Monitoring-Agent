# Detection Rule Specifications & MITRE ATT&CK Mapping

This document details the rule-based threat detection mechanisms implemented inside the Stitch Sentinel monitoring agent.

---

## 1. Suspicious Parent-Child Process Executions

### Winword / Excel Spawning Scripts
- **Rule**: Detect Microsoft Office binaries (`winword.exe`, `excel.exe`, `powerpnt.exe`) spawning command shell interpreters (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`).
- **MITRE Technique**: **T1566.001 - Phishing: Spearphishing Attachment**
- **Severity**: **HIGH**
- **Recommendation**: Terminate the spawned interpreter process and isolate the host.

### Explorer Spawning Shells
- **Rule**: Detect Windows shell execution chains (`explorer.exe` -> `powershell.exe`) containing script execution bypass parameters.
- **MITRE Technique**: **T1059.001 - Command and Scripting Interpreter: PowerShell**
- **Severity**: **HIGH**

---

## 2. Startup & Persistence Services

### Suspicious Service Binaries
- **Rule**: Detect service registry keys pointing to executables residing in Temp, AppData, or Public directories (e.g., `C:\Users\Public\Temp\backdoor.exe`).
- **MITRE Technique**: **T1543.003 - Create or Modify System Process: Windows Service**
- **Severity**: **HIGH**

### Stopped Critical Security Services
- **Rule**: Alert when core security services (e.g., Windows Defender `WinDefend`, Firewall `MpsSvc`, Sysmon `Sysmon64`) transition to a `Stopped` status.
- **MITRE Technique**: **T1562.001 - Impair Defenses: Disable or Modify Tools**
- **Severity**: **CRITICAL**

---

## 3. Windows Event Log Indicators

### Security Log Cleared (Event ID 1102)
- **Rule**: Trigger a critical alert when the Windows Security log is cleared by an administrator.
- **MITRE Technique**: **T1070.001 - Indicator Removal: Clear Windows Event Logs**
- **Severity**: **CRITICAL**

### Sysmon LSASS Memory Dumping (Event ID 10)
- **Rule**: Detect process memory reads of the Local Security Authority Subsystem Service (`lsass.exe`) with source process execution signatures.
- **MITRE Technique**: **T1003.001 - OS Credential Dumping: LSASS Memory**
- **Severity**: **CRITICAL**

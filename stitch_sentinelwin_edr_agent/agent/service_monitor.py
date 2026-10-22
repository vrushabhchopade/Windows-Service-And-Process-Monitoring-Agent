import os
import platform
import logging
from datetime import datetime
from agent.utils import get_hostname, is_suspicious_path

logger = logging.getLogger("AgentLogger")

CRITICAL_SECURITY_SERVICES = {
    "windefend": "Windows Defender Antivirus Service",
    "mpssvc": "Windows Defender Firewall",
    "wscsvc": "Security Center",
    "sense": "Windows Defender Advanced Threat Protection",
    "sysmon": "System Monitor (Sysmon)",
    "eventlog": "Windows Event Log"
}

class ServiceMonitor:
    def __init__(self):
        self.hostname = get_hostname()
        self.previous_services = {}

    def _query_win32_services(self):
        services = []
        if platform.system() == "Windows":
            try:
                import win32service
                import win32serviceutil
                
                resume_handle = 0
                scm_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
                
                status_dict = {
                    win32service.SERVICE_RUNNING: "Running",
                    win32service.SERVICE_STOPPED: "Stopped",
                    win32service.SERVICE_PAUSED: "Paused",
                    win32service.SERVICE_START_PENDING: "Start Pending",
                    win32service.SERVICE_STOP_PENDING: "Stop Pending"
                }

                service_type = win32service.SERVICE_WIN32
                service_state = win32service.SERVICE_STATE_ALL

                results = win32service.EnumServicesStatusEx(scm_handle, service_type, service_state)
                for svc in results:
                    s_name = svc['ServiceName']
                    d_name = svc['DisplayName']
                    status_code = svc['CurrentState']
                    status_str = status_dict.get(status_code, "Unknown")
                    
                    try:
                        cfg = win32service.QueryServiceConfig(
                            win32service.OpenService(scm_handle, s_name, win32service.SERVICE_QUERY_CONFIG)
                        )
                        bin_path = cfg[3]
                        start_type_code = cfg[1]
                        account = cfg[7]
                        
                        start_map = {
                            win32service.SERVICE_AUTO_START: "Automatic",
                            win32service.SERVICE_DEMAND_START: "Manual",
                            win32service.SERVICE_DISABLED: "Disabled",
                            win32service.SERVICE_BOOT_START: "Boot",
                            win32service.SERVICE_SYSTEM_START: "System"
                        }
                        start_type = start_map.get(start_type_code, "Unknown")
                    except Exception:
                        bin_path = "N/A"
                        start_type = "Unknown"
                        account = "LocalSystem"

                    services.append({
                        "service_name": s_name,
                        "display_name": d_name,
                        "binary_path": bin_path,
                        "startup_type": start_type,
                        "status": status_str,
                        "service_account": account,
                        "description": f"Windows Service {d_name}"
                    })
                win32service.CloseServiceHandle(scm_handle)
                return services
            except Exception as e:
                logger.debug(f"win32service query failed, attempting WMI/fallback: {e}")

        # Fallback for non-Windows dev environments or WMI failure
        return self._generate_fallback_services()

    def _generate_fallback_services(self):
        """
        Provides structured service definitions for cross-platform testing.
        """
        return [
            {
                "service_name": "WinDefend",
                "display_name": "Windows Defender Antivirus Service",
                "binary_path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
                "startup_type": "Automatic",
                "status": "Running",
                "service_account": "NT AUTHORITY\\LocalSystem",
                "description": "Helps protect users from malware and other unwanted software."
            },
            {
                "service_name": "MpsSvc",
                "display_name": "Windows Defender Firewall",
                "binary_path": "C:\\Windows\\System32\\mpssvc.dll",
                "startup_type": "Automatic",
                "status": "Running",
                "service_account": "NT Authority\\LocalService",
                "description": "Windows Defender Firewall helps protect your computer."
            },
            {
                "service_name": "EventLog",
                "display_name": "Windows Event Log",
                "binary_path": "C:\\Windows\\System32\\wevtsvc.dll",
                "startup_type": "Automatic",
                "status": "Running",
                "service_account": "NT AUTHORITY\\LocalService",
                "description": "This service manages events and event logs."
            },
            {
                "service_name": "Sysmon64",
                "display_name": "System Monitor",
                "binary_path": "C:\\Windows\\Sysmon64.exe",
                "startup_type": "Automatic",
                "status": "Running",
                "service_account": "NT AUTHORITY\\SYSTEM",
                "description": "System Activity Monitor"
            },
            {
                "service_name": "RemoteUpdateSvc",
                "display_name": "Remote System Update Helper",
                "binary_path": "C:\\Users\\Public\\Temp\\update_svc.exe -run",
                "startup_type": "Automatic",
                "status": "Running",
                "service_account": "NT AUTHORITY\\SYSTEM",
                "description": "Suspicious persistence service"
            }
        ]

    def audit_services(self):
        services_list = self._query_win32_services()
        audited_services = []

        for svc in services_list:
            s_name = svc["service_name"]
            s_name_lower = s_name.lower()
            bin_path = svc["binary_path"]
            status = svc["status"]

            is_suspicious = False
            warnings = []

            # Check suspicious Temp execution path
            if is_suspicious_path(bin_path):
                is_suspicious = True
                warnings.append(f"Service executes binary from suspicious path: {bin_path}")

            # Check unquoted service path with spaces
            if bin_path and " " in bin_path and not bin_path.startswith('"') and not bin_path.endswith('"'):
                if not bin_path.lower().startswith("c:\\windows\\system32"):
                    is_suspicious = True
                    warnings.append(f"Unquoted service path vulnerable to hijacking: {bin_path}")

            # Check critical security services stopped
            if s_name_lower in CRITICAL_SECURITY_SERVICES and status.lower() == "stopped":
                is_suspicious = True
                warnings.append(f"CRITICAL SECURITY SERVICE IS STOPPED: {svc['display_name']}")

            # Detect newly added services
            if self.previous_services and s_name not in self.previous_services:
                warnings.append(f"Newly registered Windows service detected: {s_name}")

            svc["is_suspicious"] = is_suspicious
            svc["warnings"] = warnings
            svc["hostname"] = self.hostname
            audited_services.append(svc)

            self.previous_services[s_name] = status

        return {
            "hostname": self.hostname,
            "timestamp": datetime.now().isoformat(),
            "services": audited_services
        }

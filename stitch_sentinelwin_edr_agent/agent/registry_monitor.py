import os
import platform
import logging
from datetime import datetime
from agent.utils import get_hostname

logger = logging.getLogger("AgentLogger")

# Critical autostart registry paths
REGISTRY_PERSISTENCE_PATHS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM")
]

class RegistryMonitor:
    def __init__(self):
        self.hostname = get_hostname()
        self.previous_values = {}

    def scan_registry(self):
        entries = []
        is_windows = (platform.system() == "Windows")

        if is_windows:
            import winreg
            for path, hive in REGISTRY_PERSISTENCE_PATHS:
                try:
                    h_root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
                    key = winreg.OpenKey(h_root, path, 0, winreg.KEY_READ)
                    num_values = winreg.QueryInfoKey(key)[1]
                    
                    for i in range(num_values):
                        name, val, val_type = winreg.EnumValue(key, i)
                        entries.append({
                            "hive": hive,
                            "path": path,
                            "name": name,
                            "value": str(val),
                            "timestamp": datetime.now().isoformat()
                        })
                    winreg.CloseKey(key)
                except Exception as e:
                    logger.debug(f"Failed to scan registry {hive}\\{path}: {e}")
        else:
            # Fallback mock registry settings for dev testing
            entries = self._generate_fallback_entries()

        # Detection logic
        anomalies = []
        for entry in entries:
            key_id = f"{entry['hive']}\\{entry['path']}\\{entry['name']}"
            val = entry["value"].lower()

            is_suspicious = False
            description = ""
            
            # Look for indicators
            if "temp" in val or "appdata" in val or "public" in val:
                is_suspicious = True
                description = f"Persistence program executing from suspicious temp path: {entry['value']}"
            elif "powershell" in val or "cmd.exe" in val or "mshta" in val or "rundll32" in val:
                is_suspicious = True
                description = f"Persistence registry pointing to interpreter shell: {entry['value']}"

            # Detect modification/new additions
            if self.previous_values and key_id not in self.previous_values:
                is_suspicious = True
                description = f"Newly created autostart registry key detected: {key_id} -> {entry['value']}"
            elif self.previous_values and self.previous_values.get(key_id) != val:
                is_suspicious = True
                description = f"Registry persistence key value changed: {key_id} updated to {entry['value']}"

            self.previous_values[key_id] = val

            if is_suspicious:
                anomalies.append({
                    "type": "REGISTRY_PERSISTENCE",
                    "severity": "HIGH",
                    "description": description,
                    "mitre": "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                    "hive": entry["hive"],
                    "path": entry["path"],
                    "name": entry["name"],
                    "value": entry["value"]
                })

        return {
            "hostname": self.hostname,
            "timestamp": datetime.now().isoformat(),
            "anomalies": anomalies,
            "entries": entries
        }

    def _generate_fallback_entries(self):
        return [
            {
                "hive": "HKCU",
                "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
                "name": "OneDrive",
                "value": r"C:\Users\jsmith\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background",
                "timestamp": datetime.now().isoformat()
            },
            {
                "hive": "HKLM",
                "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
                "name": "MaliciousUpdater",
                "value": r"C:\Users\Public\Temp\updater.exe --silent",
                "timestamp": datetime.now().isoformat()
            },
            {
                "hive": "HKLM",
                "path": r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "name": "Shell",
                "value": "explorer.exe,cmd.exe /c C:\\Temp\\payload.exe",
                "timestamp": datetime.now().isoformat()
            }
        ]

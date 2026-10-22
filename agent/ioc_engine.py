import logging
from agent.utils import get_hostname

logger = logging.getLogger("AgentLogger")

DEFAULT_IOC_RULES = [
    {"ioc_type": "ProcessName", "value": "mimikatz.exe", "description": "Known LSASS Credential Dumper", "severity": "CRITICAL"},
    {"ioc_type": "ProcessName", "value": "psexec.exe", "description": "Sysinternals Remote Execution Tool", "severity": "HIGH"},
    {"ioc_type": "FileName", "value": "nc.exe", "description": "Netcat utility for reverse shells", "severity": "HIGH"},
    {"ioc_type": "SHA256", "value": "ef483293883a93647318536f901170d195e7d23d8c1c5304b77f8842410a51c4", "description": "Cobalt Strike Beacon Hash", "severity": "CRITICAL"},
    {"ioc_type": "IP", "value": "185.220.101.5", "description": "Known Malicious Tor Exit IP", "severity": "CRITICAL"}
]

# JSON representation of Sigma Rules
SIGMA_RULES = [
    {
        "id": "sigma-powershell-download",
        "title": "Suspicious PowerShell Script Download",
        "technique": "T1059.001",
        "severity": "HIGH",
        "selection": {
            "cmdline": ["downloadstring", "downloadfile", "invoke-webrequest", "iwr", "wget"]
        }
    },
    {
        "id": "sigma-vssadmin-deletion",
        "title": "Volume Shadow Copies Deletion",
        "technique": "T1490",
        "severity": "CRITICAL",
        "selection": {
            "name": ["vssadmin.exe", "wmic.exe"],
            "cmdline": ["delete", "shadows", "shadowcopy"]
        }
    },
    {
        "id": "sigma-sam-dumping",
        "title": "SAM Registry Hive Dumping",
        "technique": "T1003.002",
        "severity": "HIGH",
        "selection": {
            "cmdline": ["save", "hklm\\sam", "hklm\\system"]
        }
    }
]

class IOCEngine:
    def __init__(self, api_client=None):
        self.api_client = api_client
        self.iocs = DEFAULT_IOC_RULES
        self.hostname = get_hostname()

    def sync_iocs(self):
        if self.api_client:
            fetched = self.api_client.fetch_iocs()
            if fetched:
                self.iocs = fetched
                logger.info(f"[+] Loaded {len(self.iocs)} active IOC rules from backend")

    def scan_processes(self, processes):
        matches = []
        for proc in processes:
            p_name = proc.get("name", "").lower()
            exe_path = proc.get("exe_path", "").lower()
            cmdline = proc.get("cmdline", "").lower()
            md5 = proc.get("md5", "").lower()
            sha256 = proc.get("sha256", "").lower()
            username = proc.get("username", "").lower()
            parent = proc.get("parent_name", "").lower()

            # 1. Standard IOC Rules Matching
            for ioc in self.iocs:
                if not ioc.get("is_enabled", True) and "is_enabled" in ioc:
                    continue

                i_type = ioc.get("ioc_type")
                i_val = str(ioc.get("value", "")).lower()

                is_match = False
                if i_type == "ProcessName" and i_val == p_name:
                    is_match = True
                elif i_type == "FileName" and (i_val in p_name or i_val in exe_path):
                    is_match = True
                elif i_type == "SHA256" and sha256 and i_val == sha256:
                    is_match = True
                elif i_type == "MD5" and md5 and i_val == md5:
                    is_match = True
                elif i_type == "CommandLine" and i_val in cmdline:
                    is_match = True

                if is_match:
                    matches.append({
                        "type": "IOC_MATCH",
                        "ioc_type": i_type,
                        "ioc_value": ioc.get("value"),
                        "severity": ioc.get("severity", "HIGH"),
                        "description": f"IOC {i_type} match '{ioc.get('value')}': {ioc.get('description', 'Threat intel match')}",
                        "matched_process": proc.get("name"),
                        "pid": proc.get("pid"),
                        "hostname": self.hostname,
                        "mitre_technique": "T1071 - Application Layer Protocol"
                    })

            # 2. Sigma Rule Matches
            for rule in SIGMA_RULES:
                select = rule["selection"]
                match_name = True
                match_cmd = True

                if "name" in select:
                    match_name = any(n in p_name for n in select["name"])
                if "cmdline" in select:
                    match_cmd = any(c in cmdline for c in select["cmdline"])

                if match_name and match_cmd:
                    matches.append({
                        "type": "SIGMA_RULE_TRIGGER",
                        "severity": rule["severity"],
                        "description": f"Sigma Rule '{rule['title']}' matched process execution: {cmdline}",
                        "matched_process": proc.get("name"),
                        "pid": proc.get("pid"),
                        "hostname": self.hostname,
                        "mitre_technique": rule["technique"]
                    })

            # 3. Privilege Escalation Heuristic
            # If parent process runs in non-admin context, but child process runs as elevated/system
            if username in ["nt authority\\system", "system"] and parent not in ["services.exe", "wininit.exe", "smss.exe", "n/a", ""]:
                # Exclude standard system children
                if p_name not in ["svchost.exe", "conhost.exe", "taskhostw.exe", "runtimebroker.exe"]:
                    matches.append({
                        "type": "PRIVILEGE_ESCALATION",
                        "severity": "HIGH",
                        "description": f"Possible privilege escalation: System process '{proc.get('name')}' spawned by user parent '{proc.get('parent_name')}'",
                        "matched_process": proc.get("name"),
                        "pid": proc.get("pid"),
                        "hostname": self.hostname,
                        "mitre_technique": "T1068 - Exploitation for Privilege Escalation"
                    })

            # 4. Ransomware File Extension Heuristic
            ransom_exts = [".locky", ".crypt", ".wannacry", ".locked", ".ryuk"]
            if any(exe_path.endswith(ext) for ext in ransom_exts):
                matches.append({
                    "type": "RANSOMWARE_INDICATOR",
                    "severity": "CRITICAL",
                    "description": f"Executable file carries known ransomware extension structure: {exe_path}",
                    "matched_process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "hostname": self.hostname,
                    "mitre_technique": "T1486 - Data Encrypted for Impact"
                })

        return matches

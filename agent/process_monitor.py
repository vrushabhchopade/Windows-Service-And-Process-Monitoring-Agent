import psutil
import logging
from datetime import datetime
from agent.utils import (
    get_hostname,
    compute_file_hashes,
    is_suspicious_path,
    is_executable_signed
)

logger = logging.getLogger("AgentLogger")

# Detection Rules Mapping MITRE ATT&CK
LOLBIN_NAMES = {
    "cmd.exe": "T1059.003 - Command and Scripting Interpreter: Windows Command Shell",
    "powershell.exe": "T1059.001 - Command and Scripting Interpreter: PowerShell",
    "wmic.exe": "T1047 - Windows Management Instrumentation",
    "rundll32.exe": "T1218.011 - System Binary Proxy Execution: Rundll32",
    "regsvr32.exe": "T1218.010 - System Binary Proxy Execution: Regsvr32",
    "mshta.exe": "T1218.005 - System Binary Proxy Execution: Mshta",
    "wscript.exe": "T1059.005 - Visual Basic",
    "cscript.exe": "T1059.005 - Visual Basic",
    "certutil.exe": "T1105 - Ingress Tool Transfer",
    "bitsadmin.exe": "T1197 - BITS Jobs"
}

BLACK_LISTED_PROCS = {
    "mimikatz.exe": "T1003.001 - OS Credential Dumping: LSASS Memory",
    "psexec.exe": "T1569.002 - System Services: Service Execution",
    "procdump.exe": "T1003.001 - OS Credential Dumping: Process Memory Dump",
    "powersploit.exe": "T1059.001 - PowerShell Exploitation Framework",
    "nc.exe": "T1095 - Non-Application Layer Protocol",
    "ncat.exe": "T1095 - Non-Application Layer Protocol",
    "netcat.exe": "T1095 - Non-Application Layer Protocol"
}

SUSPICIOUS_PARENTS = {
    "winword.exe": [
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    ],
    "excel.exe": [
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    ],
    "powerpnt.exe": [
        "cmd.exe",
        "powershell.exe"
    ],
    "outlook.exe": [
        "cmd.exe",
        "powershell.exe"
    ],
    "explorer.exe": [
        "powershell.exe",
        "cmd.exe",
        "mshta.exe"
    ],
    "services.exe": [
        "cmd.exe",
        "powershell.exe",
        "rundll32.exe"
    ]
}


class ProcessMonitor:

    def __init__(self):
        self.hostname = get_hostname()
        self.known_pids = set()
        self.signature_cache = {}

    # ==========================================================
    # FAST LIVE PROCESS SNAPSHOT
    # ==========================================================

    def get_live_processes(self):
        """
        Lightweight real-time process snapshot.

        This method is intentionally fast:
        - No file hashing
        - No Authenticode/signature verification
        - No expensive security analysis

        Used by the live dashboard process monitoring.
        """

        processes = []
        current_pids = set()

        for proc in psutil.process_iter(
            [
                "pid",
                "ppid",
                "name",
                "username",
                "exe",
                "cmdline",
                "create_time",
                "status"
            ]
        ):
            try:
                info = proc.info

                pid = info.get("pid")

                if not pid:
                    continue

                current_pids.add(pid)

                name = info.get("name") or ""
                exe_path = info.get("exe") or ""

                cmdline_list = info.get("cmdline") or []

                if isinstance(cmdline_list, list):
                    cmdline = " ".join(cmdline_list)
                else:
                    cmdline = str(cmdline_list)

                # Parent process
                parent_name = ""

                try:
                    ppid = info.get("ppid")

                    if ppid:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name()

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):
                    parent_name = ""

                # CPU
                try:
                    cpu_percent = proc.cpu_percent(interval=None)
                except Exception:
                    cpu_percent = 0.0

                # Memory
                try:
                    memory_percent = proc.memory_percent()
                except Exception:
                    memory_percent = 0.0

                # Process creation time
                create_time = info.get("create_time")

                if create_time:
                    try:
                        create_time = datetime.fromtimestamp(
                            create_time
                        ).isoformat()
                    except Exception:
                        create_time = None

                processes.append({
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "name": name,
                    "parent_name": parent_name,
                    "username": info.get("username") or "",
                    "exe_path": exe_path,
                    "cmdline": cmdline,
                    "create_time": create_time,
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(memory_percent, 2),
                    "status": info.get("status") or "unknown",
                    "hostname": self.hostname,

                    # Live snapshot intentionally does not perform
                    # expensive signature verification.
                    "is_signed": None,

                    # Security scan will populate these later.
                    "is_in_temp": None,
                    "suspicious_flags": []
                })

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

            except Exception as e:
                logger.debug(
                    f"Live process snapshot error: {e}"
                )
                continue

        self.known_pids = current_pids

        return {
            "hostname": self.hostname,
            "timestamp": datetime.now().isoformat(),
            "processes": processes
        }

    # ==========================================================
    # DETAILED SECURITY PROCESS SCAN
    # ==========================================================

    def get_process_details(self, proc):

        try:

            with proc.oneshot():

                pid = proc.pid
                ppid = proc.ppid()
                name = proc.name()

                try:
                    parent = proc.parent()
                    parent_name = parent.name() if parent else "N/A"
                except Exception:
                    parent_name = "N/A"

                try:
                    username = proc.username()
                except Exception:
                    username = "SYSTEM/Unknown"

                try:
                    exe_path = proc.exe()
                except Exception:
                    exe_path = ""

                try:
                    cmdline_list = proc.cmdline()
                    cmdline = (
                        " ".join(cmdline_list)
                        if cmdline_list
                        else name
                    )
                except Exception:
                    cmdline = name

                try:
                    create_time = datetime.fromtimestamp(
                        proc.create_time()
                    ).isoformat()
                except Exception:
                    create_time = datetime.now().isoformat()

                try:
                    cpu_percent = proc.cpu_percent(
                        interval=None
                    )
                except Exception:
                    cpu_percent = 0.0

                try:
                    mem_percent = proc.memory_percent()
                except Exception:
                    mem_percent = 0.0

                # Expensive file hashing
                hashes = compute_file_hashes(exe_path)

                # Suspicious path detection
                in_temp = is_suspicious_path(exe_path)

                name_lower = name.lower()
                parent_lower = parent_name.lower()
                cmd_lower = cmdline.lower()

                # Only perform expensive signature verification
                # when needed.
                needs_signature_check = (
                    name_lower in BLACK_LISTED_PROCS
                    or name_lower in LOLBIN_NAMES
                    or parent_lower in SUSPICIOUS_PARENTS
                    or in_temp
                    or any(
                        keyword in cmd_lower
                        for keyword in [
                            "powershell",
                            "encodedcommand",
                            "downloadstring",
                            "bypass"
                        ]
                    )
                )

                if exe_path and needs_signature_check:

                    if exe_path not in self.signature_cache:
                        self.signature_cache[
                            exe_path
                        ] = is_executable_signed(exe_path)

                    signed = self.signature_cache[exe_path]

                else:
                    signed = True

                suspicious_flags = (
                    self._evaluate_suspicious_behavior(
                        name=name,
                        parent_name=parent_name,
                        exe_path=exe_path,
                        cmdline=cmdline,
                        in_temp=in_temp,
                        signed=signed,
                        cpu_percent=cpu_percent,
                        mem_percent=mem_percent
                    )
                )

                return {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "parent_name": parent_name,
                    "username": username,
                    "exe_path": exe_path,
                    "cmdline": cmdline,
                    "create_time": create_time,
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(mem_percent, 2),
                    "md5": hashes["md5"],
                    "sha256": hashes["sha256"],
                    "is_in_temp": in_temp,
                    "is_signed": signed,
                    "status": "Running",
                    "hostname": self.hostname,
                    "suspicious_flags": suspicious_flags
                }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):
            return None

        except Exception as e:
            try:
                proc_pid = proc.pid
            except Exception:
                proc_pid = "unknown"

            logger.debug(
                f"Error scanning proc {proc_pid}: {e}"
            )

            return None

    # ==========================================================
    # SECURITY / SUSPICIOUS BEHAVIOR
    # ==========================================================

    def _evaluate_suspicious_behavior(
        self,
        name,
        parent_name,
        exe_path,
        cmdline,
        in_temp,
        signed,
        cpu_percent,
        mem_percent
    ):

        flags = []

        name_lower = name.lower()
        parent_lower = parent_name.lower()
        cmd_lower = cmdline.lower()

        # Blacklisted process
        if name_lower in BLACK_LISTED_PROCS:

            flags.append({
                "type": "BLACK_LISTED_PROCESS",
                "severity": "CRITICAL",
                "description": (
                    f"Unauthorized blacklisted process detected: "
                    f"{name}"
                ),
                "mitre": BLACK_LISTED_PROCS[name_lower]
            })

        # Suspicious parent-child relationship
        if parent_lower in SUSPICIOUS_PARENTS:

            forbidden_children = (
                SUSPICIOUS_PARENTS[parent_lower]
            )

            if name_lower in forbidden_children:

                flags.append({
                    "type": "SUSPICIOUS_PARENT_CHILD",
                    "severity": "HIGH",
                    "description": (
                        f"Suspicious parent-child execution chain: "
                        f"{parent_name} -> {name}"
                    ),
                    "mitre": (
                        "T1059 - Command and Scripting Interpreter"
                    )
                })

        # LOLBin abuse detection
        if name_lower in LOLBIN_NAMES:

            if (
                "encodedcommand" in cmd_lower
                or "-e " in cmd_lower
                or "downloadstring" in cmd_lower
                or "bypass" in cmd_lower
            ):

                flags.append({
                    "type": "LOLBIN_ABUSE_OBFUSCATION",
                    "severity": "HIGH",
                    "description": (
                        f"Obfuscated or bypass command executed "
                        f"via LOLBin {name}: {cmdline[:100]}"
                    ),
                    "mitre": LOLBIN_NAMES[name_lower]
                })

        # Temp directory execution
        if in_temp:

            flags.append({
                "type": "TEMP_DIRECTORY_EXECUTION",
                "severity": "MEDIUM",
                "description": (
                    f"Executable running from suspicious/temp "
                    f"directory: {exe_path}"
                ),
                "mitre": (
                    "T1036.005 - Masquerading: "
                    "Match Legitimate Name or Location"
                )
            })

        # Unsigned executable
        if (
            exe_path
            and not signed
            and not ("c:\\windows" in exe_path.lower())
        ):

            flags.append({
                "type": "UNSIGNED_EXECUTABLE",
                "severity": "LOW",
                "description": (
                    f"Unsigned binary executing outside Windows "
                    f"directory: {exe_path}"
                ),
                "mitre": "T1036 - Masquerading"
            })

        # High CPU usage
        if cpu_percent > 90.0:

            flags.append({
                "type": "HIGH_CPU_USAGE",
                "severity": "MEDIUM",
                "description": (
                    f"Process consuming abnormally high CPU "
                    f"({cpu_percent}%)"
                ),
                "mitre": "T1496 - Resource Hijacking"
            })

        return flags

    # ==========================================================
    # FULL SECURITY SCAN
    # ==========================================================

    def scan(self):

        processes = []
        current_pids = set()

        for proc in psutil.process_iter():

            details = self.get_process_details(proc)

            if details:

                processes.append(details)
                current_pids.add(details["pid"])

        self.known_pids = current_pids

        return {
            "hostname": self.hostname,
            "timestamp": datetime.now().isoformat(),
            "processes": processes
        }
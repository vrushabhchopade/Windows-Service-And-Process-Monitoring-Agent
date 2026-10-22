import os
import platform
import logging
import threading
from datetime import datetime
from agent.utils import get_hostname

logger = logging.getLogger("AgentLogger")

class WMIMonitor:
    def __init__(self):
        self.hostname = get_hostname()
        self.wmi_listener_thread = None
        self.running = False
        self.captured_events = []

    def start_monitoring(self):
        """
        Starts real-time WMI event consumer query in a background thread if on Windows.
        """
        self.running = True
        is_windows = (platform.system() == "Windows")
        if is_windows:
            self.wmi_listener_thread = threading.Thread(target=self._run_wmi_listener, daemon=True)
            self.wmi_listener_thread.start()
            logger.info("[+] Real-time WMI process monitor thread active")
        else:
            logger.info("[*] Cross-platform execution: WMI monitor initialized in simulation mode")

    def _run_wmi_listener(self):
        try:
            import wmi
            c = wmi.WMI()
            # Hook instance creation events for Win32_Process
            watcher = c.watch_for(
                notification_type="Creation",
                wmi_class="Win32_Process",
                delay_in_seconds=1
            )
            while self.running:
                try:
                    proc_event = watcher()
                    p_name = proc_event.Name
                    pid = proc_event.ProcessId
                    ppid = proc_event.ParentProcessId
                    cmd = proc_event.CommandLine or p_name
                    
                    event = {
                        "event_type": "PROCESS_CREATION",
                        "pid": pid,
                        "ppid": ppid,
                        "name": p_name,
                        "cmdline": cmd,
                        "timestamp": datetime.now().isoformat()
                    }
                    self.captured_events.append(event)
                    logger.debug(f"[WMI Event] New Process: {p_name} (PID: {pid})")
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"WMI listener failed to initialize: {e}")

    def collect_events(self):
        # Read and clear current queue
        events = list(self.captured_events)
        self.captured_events.clear()

        # If empty and not on Windows, inject some mock WMI process creation event
        if not events and platform.system() != "Windows":
            events.append({
                "event_type": "PROCESS_CREATION",
                "pid": 9898,
                "ppid": 3420,
                "name": "wmic.exe",
                "cmdline": "wmic.exe shadowcopy delete",
                "timestamp": datetime.now().isoformat()
            })

        # Heuristic rules evaluation
        anomalies = []
        for e in events:
            cmd = e["cmdline"].lower()
            if "shadowcopy" in cmd and "delete" in cmd:
                anomalies.append({
                    "type": "VSS_SHADOW_DELETION",
                    "severity": "CRITICAL",
                    "description": f"Volume Shadow Copy deletion detected via WMI: {e['cmdline']}",
                    "mitre": "T1490 - Inhibit System Recovery",
                    "pid": e["pid"],
                    "process_name": e["name"]
                })

        return {
            "hostname": self.hostname,
            "timestamp": datetime.now().isoformat(),
            "anomalies": anomalies,
            "events": events
        }

    def stop(self):
        self.running = False

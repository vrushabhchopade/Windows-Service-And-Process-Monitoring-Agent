import os
import sys
import time
import argparse
import signal
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.config import AgentConfig
from agent.logger import setup_logger
from agent.api_client import APIClient
from agent.process_monitor import ProcessMonitor
from agent.service_monitor import ServiceMonitor
from agent.eventlog_monitor import EventLogMonitor
from agent.cpu_monitor import CPUMonitor
from agent.memory_monitor import MemoryMonitor
from agent.disk_monitor import DiskMonitor
from agent.network_monitor import NetworkMonitor
from agent.ioc_engine import IOCEngine
from agent.scheduler import AgentScheduler

# New Enterprise monitors
from agent.registry_monitor import RegistryMonitor
from agent.fim_monitor import FIMMonitor
from agent.task_monitor import TaskMonitor
from agent.wmi_monitor import WMIMonitor

logger = setup_logger()

class SentinelAgent:
    def __init__(self, config_path=None):
        self.config = AgentConfig(config_path)
        
        backend_url = self.config.get("backend_url")
        username = self.config.get("auth.username")
        password = self.config.get("auth.password")
        
        self.api_client = APIClient(backend_url, username, password)
        self.process_monitor = ProcessMonitor()
        self.service_monitor = ServiceMonitor()
        self.eventlog_monitor = EventLogMonitor()
        self.cpu_monitor = CPUMonitor()
        self.memory_monitor = MemoryMonitor()
        self.disk_monitor = DiskMonitor()
        self.network_monitor = NetworkMonitor()
        self.ioc_engine = IOCEngine(self.api_client)
        self.scheduler = AgentScheduler()
        
        # Instantiate new enterprise monitors
        self.registry_monitor = RegistryMonitor()
        self.fim_monitor = FIMMonitor()
        self.task_monitor = TaskMonitor()
        self.wmi_monitor = WMIMonitor()
        
        self.is_running = True

    def run_process_scan(self):
        logger.info("[*] Running Process & Security Telemetry Audit...")
        data = self.process_monitor.scan()
        
        # 1. Base process matching (Standard, Sigma rules, Ransomware signatures, Privilege Escalation)
        ioc_matches = self.ioc_engine.scan_processes(data.get("processes", []))
        
        # 2. Registry anomalies check
        reg_data = self.registry_monitor.scan_registry()
        for anomaly in reg_data.get("anomalies", []):
            ioc_matches.append({
                "ioc_type": "Registry",
                "ioc_value": f"{anomaly['hive']}\\{anomaly['path']}\\{anomaly['name']}",
                "severity": anomaly["severity"],
                "description": anomaly["description"],
                "matched_process": anomaly["value"][:50],
                "pid": None,
                "mitre_technique": anomaly["mitre"]
            })

        # 3. File Integrity Monitoring (FIM) & Ransomware check
        fim_data = self.fim_monitor.scan()
        for alert in fim_data.get("alerts", []):
            ioc_matches.append({
                "ioc_type": "FIM",
                "ioc_value": "RansomwareHeuristic",
                "severity": alert["severity"],
                "description": alert["description"],
                "matched_process": "FIMEngine",
                "pid": None,
                "mitre_technique": alert["mitre"]
            })

        # 4. Scheduled Tasks check
        task_data = self.task_monitor.query_scheduled_tasks()
        for anomaly in task_data.get("anomalies", []):
            ioc_matches.append({
                "ioc_type": "ScheduledTask",
                "ioc_value": anomaly["task_name"],
                "severity": anomaly["severity"],
                "description": anomaly["description"],
                "matched_process": anomaly["action"][:50],
                "pid": None,
                "mitre_technique": anomaly["mitre"]
            })

        # 5. WMI process creation check
        wmi_data = self.wmi_monitor.collect_events()
        for anomaly in wmi_data.get("anomalies", []):
            ioc_matches.append({
                "ioc_type": "WMIEvent",
                "ioc_value": anomaly["process_name"],
                "severity": anomaly["severity"],
                "description": anomaly["description"],
                "matched_process": anomaly["process_name"],
                "pid": anomaly["pid"],
                "mitre_technique": anomaly["mitre"]
            })

        # 6. Network connections / Lateral movement check
        net_metrics = self.network_monitor.get_metrics()
        for anomaly in net_metrics.get("anomalies", []):
            ioc_matches.append({
                "ioc_type": "NetworkConnection",
                "ioc_value": f"{anomaly['remote_ip']}:{anomaly['remote_port']}",
                "severity": anomaly["severity"],
                "description": anomaly["description"],
                "matched_process": "NetworkMonitor",
                "pid": anomaly["pid"],
                "mitre_technique": anomaly["mitre"]
            })

        if ioc_matches:
            data["ioc_matches"] = ioc_matches
            logger.warning(f"[!] Alert: {len(ioc_matches)} threat indicators matched during EDR scan!")

        self.api_client.post_telemetry("process", data)

    def run_service_scan(self):
        logger.info("[*] Running Service Audit...")
        data = self.service_monitor.audit_services()
        self.api_client.post_telemetry("service", data)

    def run_eventlog_scan(self):
        logger.info("[*] Reading Event Logs...")
        logs = self.eventlog_monitor.read_event_logs()
        data = {
            "hostname": self.process_monitor.hostname,
            "logs": logs
        }
        self.api_client.post_telemetry("eventlog", data)

    def run_systemhealth_scan(self):
        logger.info("[*] Collecting System Health Telemetry...")
        cpu_data = self.cpu_monitor.get_metrics()
        mem_data = self.memory_monitor.get_metrics()
        disk_data = self.disk_monitor.get_metrics()
        net_metrics = self.network_monitor.get_metrics()

        payload = {
            "hostname": self.process_monitor.hostname,
            "cpu_percent": cpu_data.get("cpu_percent"),
            "ram_percent": mem_data.get("ram_percent"),
            "disk_percent": disk_data.get("disk_percent"),
            "disk_free_gb": disk_data.get("free_gb"),
            "network_sent_mb": net_metrics.get("network_sent_mb"),
            "network_recv_mb": net_metrics.get("network_recv_mb"),
            "top_cpu_processes": cpu_data.get("top_cpu_processes", []),
            "top_ram_processes": mem_data.get("top_memory_processes", [])
        }
        self.api_client.post_telemetry("systemhealth", payload)

    def sync_iocs(self):
        logger.info("[*] Syncing IOC Rules from Backend...")
        self.ioc_engine.sync_iocs()

    def run_once(self):
        logger.info("[+] Executing single-pass telemetry audit...")
        self.api_client.authenticate()
        self.sync_iocs()
        self.run_process_scan()
        self.run_service_scan()
        self.run_eventlog_scan()
        self.run_systemhealth_scan()
        logger.info("[+] Single-pass audit completed.")

    def start(self):
        logger.info("==========================================================")
        logger.info("  Stitch Sentinel - Windows EDR Monitoring Agent v2.0.0   ")
        logger.info("==========================================================")
        
        self.api_client.authenticate()
        self.sync_iocs()

        # Start real-time monitors
        self.wmi_monitor.start_monitoring()

        proc_int = self.config.get("monitoring.process_interval_seconds", 10)
        svc_int = self.config.get("monitoring.service_interval_seconds", 30)
        evt_int = self.config.get("monitoring.eventlog_interval_seconds", 15)
        sys_int = self.config.get("monitoring.systemhealth_interval_seconds", 5)
        ioc_int = self.config.get("monitoring.ioc_sync_interval_seconds", 60)

        self.scheduler.add_job(proc_int, self.run_process_scan)
        self.scheduler.add_job(svc_int, self.run_service_scan)
        self.scheduler.add_job(evt_int, self.run_eventlog_scan)
        self.scheduler.add_job(sys_int, self.run_systemhealth_scan)
        self.scheduler.add_job(ioc_int, self.sync_iocs)

        # Initial baseline execution
        self.run_process_scan()
        self.run_service_scan()
        self.run_eventlog_scan()
        self.run_systemhealth_scan()

        self.scheduler.start()

        def signal_handler(sig, frame):
            logger.info("[!] Signal received. Stopping Agent...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        logger.info("[+] Agent continuous monitoring loop active. Press Ctrl+C to exit.")
        while self.is_running:
            time.sleep(1)

    def stop(self):
        self.is_running = False
        self.wmi_monitor.stop()
        self.scheduler.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stitch Sentinel Windows EDR Agent")
    parser.add_argument("--once", action="store_true", help="Run single telemetry audit pass and exit")
    parser.add_argument("--config", type=str, help="Path to config.json file")
    args = parser.parse_args()

    agent = SentinelAgent(config_path=args.config)
    if args.once:
        agent.run_once()
    else:
        agent.start()

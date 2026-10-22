
import sys
import time
import argparse
import signal
import socket
import getpass
from pathlib import Path

# ==============================================================
# ADD PROJECT ROOT TO SYS.PATH
# ==============================================================

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent)
)

# ==============================================================
# IMPORTS
# ==============================================================

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

from agent.registry_monitor import RegistryMonitor
from agent.fim_monitor import FIMMonitor
from agent.task_monitor import TaskMonitor
from agent.wmi_monitor import WMIMonitor


logger = setup_logger()


# ==============================================================
# SENTINEL AGENT
# ==============================================================

class SentinelAgent:

    def __init__(self, config_path=None):

        self.config = AgentConfig(config_path)

        backend_url = self.config.get("backend_url")
        username = self.config.get("auth.username")
        password = self.config.get("auth.password")

        self.api_client = APIClient(
            backend_url,
            username,
            password
        )

        # ------------------------------------------------------
        # MONITORS
        # ------------------------------------------------------

        self.process_monitor = ProcessMonitor()
        self.service_monitor = ServiceMonitor()
        self.eventlog_monitor = EventLogMonitor()

        self.cpu_monitor = CPUMonitor()
        self.memory_monitor = MemoryMonitor()
        self.disk_monitor = DiskMonitor()
        self.network_monitor = NetworkMonitor()

        self.ioc_engine = IOCEngine(self.api_client)

        self.scheduler = AgentScheduler()

        # ------------------------------------------------------
        # ENTERPRISE MONITORS
        # ------------------------------------------------------

        self.registry_monitor = RegistryMonitor()
        self.fim_monitor = FIMMonitor()
        self.task_monitor = TaskMonitor()
        self.wmi_monitor = WMIMonitor()

        self.is_running = True

    # ==========================================================
    # AGENT ID
    # ==========================================================

    def get_agent_id(self):

        """
        Generate a unique Agent ID for this Windows machine.

        The hostname is used so copied agents on different
        Windows machines do not use the same default Agent ID.
        """

        hostname = socket.gethostname()

        configured_agent_id = self.config.get(
            "agent_id",
            ""
        )

        configured_agent_id = (
            str(configured_agent_id).strip()
            if configured_agent_id is not None
            else ""
        )

        # Custom Agent ID
        if (
            configured_agent_id
            and configured_agent_id != "WIN-EDR-AGENT-01"
        ):
            return configured_agent_id

        # Default endpoint-specific Agent ID
        return f"WIN-EDR-{hostname}"

    # ==========================================================
    # ENDPOINT REGISTRATION
    # ==========================================================

    def register_endpoint(self):

        """
        Register this Windows machine
        with the central backend.
        """

        hostname = socket.gethostname()

        # ------------------------------------------------------
        # CURRENT WINDOWS USER
        # ------------------------------------------------------

        try:
            username = getpass.getuser()

        except Exception:
            username = ""

        # ------------------------------------------------------
        # LOCAL IP ADDRESS
        # ------------------------------------------------------

        try:
            ip_address = socket.gethostbyname(
                hostname
            )

        except Exception:
            ip_address = None

        # ------------------------------------------------------
        # UNIQUE ENDPOINT ID
        # ------------------------------------------------------

        agent_id = self.get_agent_id()

        # ------------------------------------------------------
        # ENROLLMENT TOKEN
        # ------------------------------------------------------

        enrollment_token = self.config.get(
            "enrollment.token",
            ""
        )

        # ------------------------------------------------------
        # ENDPOINT DATA
        # ------------------------------------------------------

        endpoint_data = {
            "agent_id": agent_id,
            "hostname": hostname,
            "username": username,
            "os_name": "Windows",
            "agent_version": "2.0.0",
            "ip_address": ip_address,
            "enrollment_token": enrollment_token,
        }

        logger.info(
            "[ENDPOINT] Registering endpoint..."
        )

        logger.info(
            "[ENDPOINT] Hostname: %s",
            hostname
        )

        logger.info(
            "[ENDPOINT] Agent ID: %s",
            agent_id
        )

        logger.info(
            "[ENDPOINT] Username: %s",
            username
        )

        logger.info(
            "[ENDPOINT] IP Address: %s",
            ip_address
        )

        # ------------------------------------------------------
        # SEND REGISTRATION
        # ------------------------------------------------------

        success = self.api_client.register_endpoint(
            endpoint_data
        )

        if success:

            logger.info(
                "[ENDPOINT] Registration successful: %s",
                hostname
            )

        else:

            logger.warning(
                "[ENDPOINT] Registration failed: %s",
                hostname
            )

        return success

    # ==========================================================
    # HEARTBEAT
    # ==========================================================

    def send_heartbeat(self):

        agent_id = self.get_agent_id()

        success = self.api_client.send_heartbeat(
            agent_id
        )

        if success:

            logger.debug(
                "[+] Heartbeat sent successfully: %s",
                agent_id
            )

        else:

            logger.warning(
                "[-] Heartbeat failed: %s",
                agent_id
            )

    # ==========================================================
    # FAST LIVE PROCESS SNAPSHOT
    # ==========================================================

    def run_live_process_scan(self):

        try:

            logger.info(
                "[LIVE] Collecting live process snapshot..."
            )

            data = (
                self.process_monitor.get_live_processes()
            )

            self.api_client.post_telemetry(
                "process",
                data
            )

            logger.info(
                "[LIVE] Process snapshot sent: %s processes",
                len(
                    data.get(
                        "processes",
                        []
                    )
                )
            )

        except Exception as e:

            logger.exception(
                "[LIVE] Live process telemetry failed: %s",
                e
            )

    # ==========================================================
    # HEAVY PROCESS / SECURITY AUDIT
    # ==========================================================

    def run_process_scan(self):

        logger.info(
            "[SECURITY] Running Process & Security Telemetry Audit..."
        )

        try:

            # --------------------------------------------------
            # PROCESS SECURITY SCAN
            # --------------------------------------------------

            data = self.process_monitor.scan()

            # --------------------------------------------------
            # IOC PROCESS MATCHING
            # --------------------------------------------------

            ioc_matches = self.ioc_engine.scan_processes(
                data.get(
                    "processes",
                    []
                )
            )

            # --------------------------------------------------
            # REGISTRY ANOMALIES
            # --------------------------------------------------

            reg_data = (
                self.registry_monitor.scan_registry()
            )

            for anomaly in reg_data.get(
                "anomalies",
                []
            ):

                ioc_matches.append({

                    "ioc_type": "Registry",

                    "ioc_value": (
                        f"{anomaly['hive']}\\"
                        f"{anomaly['path']}\\"
                        f"{anomaly['name']}"
                    ),

                    "severity": anomaly["severity"],

                    "description": anomaly["description"],

                    "matched_process": (
                        anomaly["value"][:50]
                    ),

                    "pid": None,

                    "mitre_technique": anomaly["mitre"]
                })

            # --------------------------------------------------
            # FILE INTEGRITY MONITORING
            # --------------------------------------------------

            fim_data = (
                self.fim_monitor.scan()
            )

            for alert in fim_data.get(
                "alerts",
                []
            ):

                ioc_matches.append({

                    "ioc_type": "FIM",

                    "ioc_value": "RansomwareHeuristic",

                    "severity": alert["severity"],

                    "description": alert["description"],

                    "matched_process": "FIMEngine",

                    "pid": None,

                    "mitre_technique": alert["mitre"]
                })

            # --------------------------------------------------
            # SCHEDULED TASKS
            # --------------------------------------------------

            task_data = (
                self.task_monitor.query_scheduled_tasks()
            )

            for anomaly in task_data.get(
                "anomalies",
                []
            ):

                ioc_matches.append({

                    "ioc_type": "ScheduledTask",

                    "ioc_value": anomaly["task_name"],

                    "severity": anomaly["severity"],

                    "description": anomaly["description"],

                    "matched_process": (
                        anomaly["action"][:50]
                    ),

                    "pid": None,

                    "mitre_technique": anomaly["mitre"]
                })

            # --------------------------------------------------
            # WMI EVENTS
            # --------------------------------------------------

            wmi_data = (
                self.wmi_monitor.collect_events()
            )

            for anomaly in wmi_data.get(
                "anomalies",
                []
            ):

                ioc_matches.append({

                    "ioc_type": "WMIEvent",

                    "ioc_value": anomaly["process_name"],

                    "severity": anomaly["severity"],

                    "description": anomaly["description"],

                    "matched_process": (
                        anomaly["process_name"]
                    ),

                    "pid": anomaly["pid"],

                    "mitre_technique": anomaly["mitre"]
                })

            # --------------------------------------------------
            # NETWORK / LATERAL MOVEMENT
            # --------------------------------------------------

            net_metrics = (
                self.network_monitor.get_metrics()
            )

            for anomaly in net_metrics.get(
                "anomalies",
                []
            ):

                ioc_matches.append({

                    "ioc_type": "NetworkConnection",

                    "ioc_value": (
                        f"{anomaly['remote_ip']}:"
                        f"{anomaly['remote_port']}"
                    ),

                    "severity": anomaly["severity"],

                    "description": anomaly["description"],

                    "matched_process": "NetworkMonitor",

                    "pid": anomaly["pid"],

                    "mitre_technique": anomaly["mitre"]
                })

            # --------------------------------------------------
            # ALERT LOGGING
            # --------------------------------------------------

            if ioc_matches:

                logger.warning(
                    "[SECURITY] Alert: %s threat indicators matched!",
                    len(ioc_matches)
                )

            # --------------------------------------------------
            # FRESH LIVE PROCESS SNAPSHOT
            # --------------------------------------------------

            fresh_data = (
                self.process_monitor.get_live_processes()
            )

            fresh_data["ioc_matches"] = ioc_matches

            self.api_client.post_telemetry(
                "process",
                fresh_data
            )

            logger.info(
                "[SECURITY] Security audit completed."
            )

        except Exception as e:

            logger.exception(
                "[SECURITY] Process security scan failed: %s",
                e
            )

    # ==========================================================
    # SERVICE SCAN
    # ==========================================================

    def run_service_scan(self):

        logger.info(
            "[SERVICE] Running Service Audit..."
        )

        try:

            data = (
                self.service_monitor.audit_services()
            )

            self.api_client.post_telemetry(
                "service",
                data
            )

        except Exception as e:

            logger.exception(
                "[SERVICE] Service audit failed: %s",
                e
            )

    # ==========================================================
    # EVENT LOG SCAN
    # ==========================================================

    def run_eventlog_scan(self):

        logger.info(
            "[EVENTLOG] Reading Event Logs..."
        )

        try:

            logs = (
                self.eventlog_monitor.read_event_logs()
            )

            data = {

                "hostname":
                    self.process_monitor.hostname,

                "logs": logs
            }

            self.api_client.post_telemetry(
                "eventlog",
                data
            )

        except Exception as e:

            logger.exception(
                "[EVENTLOG] Event log scan failed: %s",
                e
            )

    # ==========================================================
    # SYSTEM HEALTH SCAN
    # ==========================================================

    def run_systemhealth_scan(self):

        logger.info(
            "[HEALTH] Collecting System Health Telemetry..."
        )

        try:

            total_start = time.perf_counter()

            # --------------------------------------------------
            # CPU
            # --------------------------------------------------

            start = time.perf_counter()

            cpu_data = (
                self.cpu_monitor.get_metrics()
            )

            logger.info(
                "[CPU VALUE] Agent CPU: %s%%",
                cpu_data.get("cpu_percent")
            )

            logger.info(
                "[TIMING] CPU monitor: %.3fs",
                time.perf_counter() - start
            )

            # --------------------------------------------------
            # MEMORY
            # --------------------------------------------------

            start = time.perf_counter()

            mem_data = (
                self.memory_monitor.get_metrics()
            )

            logger.info(
                "[TIMING] Memory monitor: %.3fs",
                time.perf_counter() - start
            )

            # --------------------------------------------------
            # DISK
            # --------------------------------------------------

            start = time.perf_counter()

            disk_data = (
                self.disk_monitor.get_metrics()
            )

            logger.info(
                "[TIMING] Disk monitor: %.3fs",
                time.perf_counter() - start
            )

            # --------------------------------------------------
            # NETWORK
            # --------------------------------------------------

            start = time.perf_counter()

            net_metrics = (
                self.network_monitor.get_metrics()
            )

            logger.info(
                "[TIMING] Network monitor: %.3fs",
                time.perf_counter() - start
            )

            # --------------------------------------------------
            # PAYLOAD
            # --------------------------------------------------

            payload = {

                "hostname":
                    self.process_monitor.hostname,

                "cpu_percent":
                    cpu_data.get("cpu_percent"),

                "ram_percent":
                    mem_data.get("ram_percent"),

                "disk_percent":
                    disk_data.get("disk_percent"),

                "disk_free_gb":
                    disk_data.get("free_gb"),

                "network_sent_mb":
                    net_metrics.get(
                        "network_sent_mb"
                    ),

                "network_recv_mb":
                    net_metrics.get(
                        "network_recv_mb"
                    ),

                "top_cpu_processes":
                    cpu_data.get(
                        "top_cpu_processes",
                        []
                    ),

                "top_ram_processes":
                    mem_data.get(
                        "top_memory_processes",
                        []
                    )
            }

            # --------------------------------------------------
            # SEND SYSTEM HEALTH
            # --------------------------------------------------

            start = time.perf_counter()

            self.api_client.post_telemetry(
                "systemhealth",
                payload
            )

            logger.info(
                "[TIMING] SystemHealth API POST: %.3fs",
                time.perf_counter() - start
            )

            logger.info(
                "[TIMING] TOTAL System Health: %.3fs",
                time.perf_counter() - total_start
            )

        except Exception as e:

            logger.exception(
                "[HEALTH] System health scan failed: %s",
                e
            )

    # ==========================================================
    # IOC SYNC
    # ==========================================================

    def sync_iocs(self):

        logger.info(
            "[IOC] Syncing IOC Rules from Backend..."
        )

        try:

            self.ioc_engine.sync_iocs()

        except Exception as e:

            logger.exception(
                "[IOC] IOC sync failed: %s",
                e
            )

    # ==========================================================
    # SINGLE RUN
    # ==========================================================

    def run_once(self):

        logger.info(
            "[+] Executing single-pass telemetry audit..."
        )

        self.api_client.authenticate()

        self.sync_iocs()

        self.run_live_process_scan()
        self.run_process_scan()
        self.run_service_scan()
        self.run_eventlog_scan()
        self.run_systemhealth_scan()

        logger.info(
            "[+] Single-pass audit completed."
        )

    # ==========================================================
    # START CONTINUOUS MONITORING
    # ==========================================================

    def start(self):

        logger.info(
            "=========================================================="
        )

        logger.info(
            "  Stitch Sentinel - Windows EDR "
            "Monitoring Agent v2.0.0"
        )

        logger.info(
            "=========================================================="
        )

        # ------------------------------------------------------
        # AUTHENTICATION
        # ------------------------------------------------------

        authenticated = (
            self.api_client.authenticate()
        )

        if not authenticated:

            logger.warning(
                "[!] Backend authentication failed."
            )

        # ------------------------------------------------------
        # ENDPOINT REGISTRATION
        # ------------------------------------------------------

        if authenticated:

            self.register_endpoint()

        # ------------------------------------------------------
        # IOC SYNC
        # ------------------------------------------------------

        self.sync_iocs()

        # ------------------------------------------------------
        # WMI REAL-TIME MONITOR
        # ------------------------------------------------------

        self.wmi_monitor.start_monitoring()

        # ------------------------------------------------------
        # MONITORING INTERVALS
        # ------------------------------------------------------

        live_proc_int = self.config.get(
            "monitoring.live_process_interval_seconds",
            1
        )

        security_proc_int = self.config.get(
            "monitoring.process_security_interval_seconds",
            30
        )

        svc_int = self.config.get(
            "monitoring.service_interval_seconds",
            30
        )

        evt_int = self.config.get(
            "monitoring.eventlog_interval_seconds",
            15
        )

        sys_int = self.config.get(
            "monitoring.systemhealth_interval_seconds",
            5
        )

        ioc_int = self.config.get(
            "monitoring.ioc_sync_interval_seconds",
            60
        )

        heartbeat_int = self.config.get(
            "monitoring.heartbeat_interval_seconds",
            3
        )

        # ------------------------------------------------------
        # CONFIG LOGGING
        # ------------------------------------------------------

        logger.info(
            "[CONFIG] Live Process Interval: %ss",
            live_proc_int
        )

        logger.info(
            "[CONFIG] Security Process Interval: %ss",
            security_proc_int
        )

        logger.info(
            "[CONFIG] Service Interval: %ss",
            svc_int
        )

        logger.info(
            "[CONFIG] Event Log Interval: %ss",
            evt_int
        )

        logger.info(
            "[CONFIG] System Health Interval: %ss",
            sys_int
        )

        logger.info(
            "[CONFIG] IOC Sync Interval: %ss",
            ioc_int
        )

        logger.info(
            "[CONFIG] Heartbeat Interval: %ss",
            heartbeat_int
        )

        # ------------------------------------------------------
        # LIVE PROCESS JOB
        # ------------------------------------------------------

        self.scheduler.add_job(
            live_proc_int,
            self.run_live_process_scan
        )

        # ------------------------------------------------------
        # HEAVY SECURITY PROCESS JOB
        # ------------------------------------------------------

        self.scheduler.add_job(
            security_proc_int,
            self.run_process_scan
        )

        # ------------------------------------------------------
        # SERVICE JOB
        # ------------------------------------------------------

        self.scheduler.add_job(
            svc_int,
            self.run_service_scan
        )

        # ------------------------------------------------------
        # EVENT LOG JOB
        # ------------------------------------------------------

        self.scheduler.add_job(
            evt_int,
            self.run_eventlog_scan
        )

        # ------------------------------------------------------
        # SYSTEM HEALTH JOB
        # ------------------------------------------------------

        self.scheduler.add_job(
            sys_int,
            self.run_systemhealth_scan
        )

        # ------------------------------------------------------
        # IOC JOB
        # ------------------------------------------------------

        self.scheduler.add_job(
            ioc_int,
            self.sync_iocs
        )

        # ------------------------------------------------------
        # HEARTBEAT JOB
        # ------------------------------------------------------

        self.scheduler.add_job(
            heartbeat_int,
            self.send_heartbeat
        )

        # ------------------------------------------------------
        # INITIAL TELEMETRY
        # ------------------------------------------------------

        logger.info(
            "[*] Collecting initial live process snapshot..."
        )

        self.run_live_process_scan()

        logger.info(
            "[*] Collecting initial security process audit..."
        )

        self.run_process_scan()

        self.run_service_scan()
        self.run_eventlog_scan()
        self.run_systemhealth_scan()

        # ------------------------------------------------------
        # FIRST HEARTBEAT
        # ------------------------------------------------------

        if authenticated:

            self.send_heartbeat()

        # ------------------------------------------------------
        # START SCHEDULER
        # ------------------------------------------------------

        self.scheduler.start()

        # ------------------------------------------------------
        # SIGNAL HANDLER
        # ------------------------------------------------------

        def signal_handler(sig, frame):

            logger.info(
                "[!] Signal received. Stopping Agent..."
            )

            self.stop()

            sys.exit(0)

        signal.signal(
            signal.SIGINT,
            signal_handler
        )

        # ------------------------------------------------------
        # AGENT ACTIVE
        # ------------------------------------------------------

        logger.info(
            "[+] Agent continuous monitoring loop active."
        )

        logger.info(
            "[+] Live process monitoring is active."
        )

        logger.info(
            "[+] Heavy security process audit runs every %ss.",
            security_proc_int
        )

        logger.info(
            "[+] Press Ctrl+C to exit."
        )

        # ------------------------------------------------------
        # MAIN LOOP
        # ------------------------------------------------------

        while self.is_running:

            time.sleep(1)

    # ==========================================================
    # STOP AGENT
    # ==========================================================

    def stop(self):

        self.is_running = False

        try:

            self.wmi_monitor.stop()

        except Exception:

            pass

        try:

            self.scheduler.stop()

        except Exception:

            pass


# ==============================================================
# MAIN
# ==============================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Stitch Sentinel Windows EDR Agent"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run single telemetry audit pass and exit"
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to config.json file"
    )

    args = parser.parse_args()

    agent = SentinelAgent(
        config_path=args.config
    )

    if args.once:

        agent.run_once()

    else:

        agent.start()


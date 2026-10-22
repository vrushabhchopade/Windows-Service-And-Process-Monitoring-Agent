import psutil
import logging
from agent.utils import get_hostname

logger = logging.getLogger("AgentLogger")


# Remote administration ports commonly associated
# with lateral movement detection.
ADMIN_PORTS = {
    445: (
        "T1021.002 - SMB/Windows Admin Shares",
        "SMB"
    ),
    135: (
        "T1021.003 - DCOM/RPC Execution",
        "RPC"
    ),
    5985: (
        "T1021.006 - Windows Remote Management (WinRM)",
        "WinRM HTTP"
    ),
    5986: (
        "T1021.006 - Windows Remote Management (WinRM)",
        "WinRM HTTPS"
    ),
    3389: (
        "T1021.001 - Remote Desktop Protocol",
        "RDP"
    )
}


class NetworkMonitor:

    def __init__(self):

        self.hostname = get_hostname()

        # Cache detailed connections.
        # System-health collection can then remain fast.
        self.cached_connections = []
        self.cached_anomalies = []
        self.last_connection_scan = 0.0

        # Detailed network connection scan interval.
        self.connection_scan_interval = 10.0

    def _scan_connections(self):

        connections = []
        anomalies = []

        try:
            raw_conns = psutil.net_connections(
                kind="inet"
            )
        except Exception as e:

            logger.debug(
                f"Network connection scan skipped: {e}"
            )

            return connections, anomalies

        for conn in raw_conns:

            if conn.status != "ESTABLISHED":
                continue

            try:

                if conn.raddr:

                    r_ip = conn.raddr.ip
                    r_port = conn.raddr.port

                else:

                    r_ip = "N/A"
                    r_port = 0

                if conn.laddr:

                    l_ip = conn.laddr.ip
                    l_port = conn.laddr.port

                else:

                    l_ip = "N/A"
                    l_port = 0

                conn_info = {
                    "pid": conn.pid,
                    "local_ip": l_ip,
                    "local_port": l_port,
                    "remote_ip": r_ip,
                    "remote_port": r_port,
                    "status": conn.status,
                    "type": (
                        "TCP"
                        if conn.type == 1
                        else "UDP"
                    )
                }

                connections.append(conn_info)

                # Lateral movement detection
                if r_port in ADMIN_PORTS:

                    mitre_tech, protocol = (
                        ADMIN_PORTS[r_port]
                    )

                    anomalies.append({
                        "type":
                            "LATERAL_MOVEMENT_PORT_CONNECTION",

                        "severity": "HIGH",

                        "description":
                            f"Established connection to "
                            f"remote administration port "
                            f"{r_port} ({protocol}) "
                            f"from process PID {conn.pid}",

                        "mitre": mitre_tech,

                        "remote_ip": r_ip,

                        "remote_port": r_port,

                        "pid": conn.pid
                    })

            except Exception:
                continue

        return connections, anomalies

    def get_metrics(self):

        try:

            # -------------------------------------------------
            # FAST PART
            # -------------------------------------------------

            net_io = psutil.net_io_counters()

            bytes_sent = net_io.bytes_sent
            bytes_recv = net_io.bytes_recv

            sent_mb = round(
                bytes_sent / (1024 ** 2),
                2
            )

            recv_mb = round(
                bytes_recv / (1024 ** 2),
                2
            )

            # -------------------------------------------------
            # DETAILED CONNECTION SCAN
            # -------------------------------------------------

            import time

            current_time = time.monotonic()

            if (
                current_time
                - self.last_connection_scan
                >= self.connection_scan_interval
            ):

                (
                    self.cached_connections,
                    self.cached_anomalies
                ) = self._scan_connections()

                self.last_connection_scan = (
                    current_time
                )

            return {

                "network_sent_mb":
                    sent_mb,

                "network_recv_mb":
                    recv_mb,

                "active_connections":
                    len(self.cached_connections),

                "connections":
                    self.cached_connections,

                "anomalies":
                    self.cached_anomalies,

                "hostname":
                    self.hostname
            }

        except Exception as e:

            logger.error(
                f"Network monitoring error: {e}"
            )

            return {

                "network_sent_mb": 0.0,

                "network_recv_mb": 0.0,

                "active_connections":
                    len(self.cached_connections),

                "connections":
                    self.cached_connections,

                "anomalies":
                    self.cached_anomalies,

                "hostname":
                    self.hostname
            }
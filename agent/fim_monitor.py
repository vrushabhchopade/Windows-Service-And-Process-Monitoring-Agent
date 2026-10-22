import os
import time
import math
import logging
from pathlib import Path
from datetime import datetime
from agent.utils import get_hostname, compute_file_hashes

logger = logging.getLogger("AgentLogger")

# Monitored folder targets
MONITORED_PATHS = [
    r"C:\Windows\System32\Drivers",
    r"C:\Users\Public\Downloads",
    r"C:\Users\Public\Temp"
]

class FIMMonitor:
    def __init__(self):
        self.hostname = get_hostname()
        self.file_state = {}
        self.change_history = []  # List of timestamps of recent modifications

    def get_file_metadata(self, filepath):
        try:
            path = Path(filepath)
            if not path.is_file():
                return None
            stat = path.stat()
            size = stat.st_size
            mtime = stat.st_mtime
            hashes = compute_file_hashes(filepath)
            
            # Simple entropy calculation
            entropy = self._calculate_file_entropy(filepath)

            return {
                "filepath": str(filepath),
                "size": size,
                "mtime": mtime,
                "md5": hashes["md5"],
                "sha256": hashes["sha256"],
                "entropy": entropy
            }
        except Exception:
            return None

    def _calculate_file_entropy(self, filepath):
        """
        Calculates Shannon entropy of a file to detect encrypted/ransomware payloads.
        """
        try:
            if not os.path.isfile(filepath):
                return 0.0
            
            # Read first 1MB only for performance
            with open(filepath, 'rb') as f:
                data = f.read(1024 * 1024)
            
            if not data:
                return 0.0

            entropy = 0
            for x in range(256):
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            return round(entropy, 2)
        except Exception:
            return 0.0

    def scan(self):
        events = []
        current_state = {}
        now = time.time()

        for folder in MONITORED_PATHS:
            # Fallback cross-platform path mapping
            mon_dir = Path(folder) if os.name == 'nt' else Path("logs/")
            if not mon_dir.exists():
                continue

            try:
                # Scans up to 50 files for developer resource containment
                count = 0
                for root, dirs, files in os.walk(mon_dir):
                    if count > 50:
                        break
                    for f in files:
                        filepath = os.path.join(root, f)
                        meta = self.get_file_metadata(filepath)
                        if meta:
                            current_state[meta["filepath"]] = meta
                            count += 1
            except Exception as e:
                logger.debug(f"FIM failed to scan folder {folder}: {e}")

        # Evaluate modifications
        for path, meta in current_state.items():
            if path not in self.file_state:
                events.append({
                    "action": "CREATED",
                    "filepath": path,
                    "sha256": meta["sha256"],
                    "entropy": meta["entropy"],
                    "timestamp": datetime.now().isoformat()
                })
                self.change_history.append(now)
            else:
                prev = self.file_state[path]
                if prev["sha256"] != meta["sha256"]:
                    events.append({
                        "action": "MODIFIED",
                        "filepath": path,
                        "sha256": meta["sha256"],
                        "entropy": meta["entropy"],
                        "timestamp": datetime.now().isoformat()
                    })
                    self.change_history.append(now)

        for path in list(self.file_state.keys()):
            if path not in current_state:
                events.append({
                    "action": "DELETED",
                    "filepath": path,
                    "sha256": self.file_state[path]["sha256"],
                    "entropy": 0.0,
                    "timestamp": datetime.now().isoformat()
                })
                self.change_history.append(now)

        self.file_state = current_state

        # Clean history older than 60s
        self.change_history = [t for t in self.change_history if now - t < 60]

        alerts = []
        # Ransomware detection heuristic: > 10 modifications in 60s
        if len(self.change_history) >= 10:
            high_entropy_files = [e["filepath"] for e in events if e.get("entropy", 0) > 7.5]
            if high_entropy_files:
                alerts.append({
                    "type": "RANSOMWARE_ACTIVITY",
                    "severity": "CRITICAL",
                    "description": f"Ransomware indicators: High-frequency file modifications ({len(self.change_history)} updates/min) detected with high entropy files: {', '.join(high_entropy_files[:3])}",
                    "mitre": "T1486 - Impact: Data Encrypted for Impact"
                })

        return {
            "hostname": self.hostname,
            "timestamp": datetime.now().isoformat(),
            "events": events,
            "alerts": alerts
        }

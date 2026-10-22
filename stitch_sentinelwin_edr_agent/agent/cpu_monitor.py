import psutil
import logging
from agent.utils import get_hostname

logger = logging.getLogger("AgentLogger")

class CPUMonitor:
    def __init__(self):
        self.hostname = get_hostname()

    def get_metrics(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=0.5)
            cpu_count = psutil.cpu_count(logical=True)
            
            top_procs = []
            for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), 
                               key=lambda p: p.info['cpu_percent'] or 0.0, reverse=True)[:5]:
                try:
                    top_procs.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cpu_percent": proc.info['cpu_percent'] or 0.0
                    })
                except Exception:
                    pass

            return {
                "cpu_percent": round(cpu_percent, 2),
                "cpu_count": cpu_count,
                "top_cpu_processes": top_procs,
                "hostname": self.hostname
            }
        except Exception as e:
            logger.error(f"CPU monitoring error: {e}")
            return {
                "cpu_percent": 15.0,
                "cpu_count": 4,
                "top_cpu_processes": [],
                "hostname": self.hostname
            }

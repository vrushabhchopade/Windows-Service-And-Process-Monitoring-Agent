import psutil
import logging
from agent.utils import get_hostname

logger = logging.getLogger("AgentLogger")


class MemoryMonitor:

    def __init__(self):
        self.hostname = get_hostname()

    def get_metrics(self):
        try:

            # =====================================================
            # RAM METRICS
            # =====================================================

            mem = psutil.virtual_memory()

            total_gb = round(
                mem.total / (1024 ** 3), 2
            )

            used_gb = round(
                mem.used / (1024 ** 3), 2
            )

            available_gb = round(
                mem.available / (1024 ** 3), 2
            )

            mem_percent = round(
                mem.percent, 2
            )

            # =====================================================
            # TOP MEMORY PROCESSES
            # =====================================================

            top_procs = []

            for proc in psutil.process_iter(
                ['pid', 'name', 'memory_percent']
            ):
                try:

                    memory = proc.info.get(
                        'memory_percent'
                    )

                    if memory is None:
                        memory = proc.memory_percent(
                            interval=None
                        )

                    top_procs.append({
                        "pid": proc.info.get('pid'),
                        "name": proc.info.get('name') or "Unknown",
                        "memory_percent": round(
                            memory, 2
                        )
                    })

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):
                    continue

                except Exception:
                    continue

            # Sort after collecting
            top_procs.sort(
                key=lambda x: x["memory_percent"],
                reverse=True
            )

            # Only keep top 5
            top_procs = top_procs[:5]

            # =====================================================
            # RESPONSE
            # =====================================================

            return {
                "ram_percent": mem_percent,
                "total_gb": total_gb,
                "used_gb": used_gb,
                "available_gb": available_gb,
                "top_memory_processes": top_procs,
                "hostname": self.hostname
            }

        except Exception as e:

            logger.error(
                f"Memory monitoring error: {e}"
            )

            return {
                "ram_percent": 0.0,
                "total_gb": 0.0,
                "used_gb": 0.0,
                "available_gb": 0.0,
                "top_memory_processes": [],
                "hostname": self.hostname
            }
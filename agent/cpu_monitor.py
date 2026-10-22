import time
import threading
import logging
import ctypes
from ctypes import wintypes

import psutil

from agent.utils import get_hostname

logger = logging.getLogger("AgentLogger")


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class CPUMonitor:

    def __init__(self):
        self.hostname = get_hostname()

        self.cpu_percent = 0.0
        self.top_processes = []

        self.running = True
        self.process_refresh_interval = 5.0

        self._previous_idle = 0
        self._previous_kernel = 0
        self._previous_user = 0

        self._initialize_cpu_counter()

        self.worker = threading.Thread(
            target=self._background_refresh,
            name="CPUProcessMonitor",
            daemon=True
        )
        self.worker.start()

    def _filetime_to_int(self, filetime):
        return (
            (filetime.dwHighDateTime << 32)
            | filetime.dwLowDateTime
        )

    def _get_system_times(self):
        idle = FILETIME()
        kernel = FILETIME()
        user = FILETIME()

        success = ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle),
            ctypes.byref(kernel),
            ctypes.byref(user)
        )

        if not success:
            raise ctypes.WinError()

        return (
            self._filetime_to_int(idle),
            self._filetime_to_int(kernel),
            self._filetime_to_int(user)
        )

    def _initialize_cpu_counter(self):
        try:
            idle, kernel, user = self._get_system_times()

            self._previous_idle = idle
            self._previous_kernel = kernel
            self._previous_user = user

        except Exception as e:
            logger.error(
                f"CPU counter initialization error: {e}"
            )

    def _calculate_cpu_percent(self):
        try:
            idle, kernel, user = self._get_system_times()

            idle_delta = idle - self._previous_idle
            kernel_delta = kernel - self._previous_kernel
            user_delta = user - self._previous_user

            total_delta = kernel_delta + user_delta

            self._previous_idle = idle
            self._previous_kernel = kernel
            self._previous_user = user

            if total_delta <= 0:
                return self.cpu_percent

            busy_delta = total_delta - idle_delta

            cpu = (
                busy_delta / total_delta
            ) * 100.0

            cpu = max(0.0, min(100.0, cpu))

            return round(cpu, 2)

        except Exception as e:
            logger.debug(
                f"CPU calculation error: {e}"
            )
            return self.cpu_percent

    def _collect_top_processes(self):
        processes = []

        try:
            for proc in psutil.process_iter(
                ["pid", "name"]
            ):
                try:
                    pid = proc.info.get("pid")
                    name = (
                        proc.info.get("name")
                        or "Unknown"
                    )

                    cpu = proc.cpu_percent(
                        interval=None
                    )

                    if cpu is None or cpu < 0:
                        cpu = 0.0

                    processes.append({
                        "pid": pid,
                        "name": name,
                        "cpu_percent": round(
                            float(cpu), 2
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

            processes.sort(
                key=lambda item: item["cpu_percent"],
                reverse=True
            )

            self.top_processes = processes[:5]

        except Exception as e:
            logger.debug(
                f"Top CPU process collection error: {e}"
            )

    def _background_refresh(self):
        last_process_refresh = 0.0

        while self.running:

            try:
                # Fast Windows CPU counter
                self.cpu_percent = (
                    self._calculate_cpu_percent()
                )

            except Exception as e:
                logger.debug(
                    f"CPU refresh error: {e}"
                )

            # Expensive process enumeration is done
            # separately every 5 seconds.
            current_time = time.monotonic()

            if (
                current_time - last_process_refresh
                >= self.process_refresh_interval
            ):
                try:
                    self._collect_top_processes()
                    last_process_refresh = current_time

                except Exception as e:
                    logger.debug(
                        f"Top process refresh error: {e}"
                    )

            # Small sampling interval keeps the CPU
            # value continuously updated.
            time.sleep(0.25)

    def get_metrics(self):
        try:
            cpu_count = (
                psutil.cpu_count(logical=True)
                or 1
            )

            return {
                "cpu_percent": self.cpu_percent,
                "cpu_count": cpu_count,
                "top_cpu_processes": list(
                    self.top_processes
                ),
                "hostname": self.hostname
            }

        except Exception as e:
            logger.error(
                f"CPU monitoring error: {e}"
            )

            return {
                "cpu_percent": 0.0,
                "cpu_count": (
                    psutil.cpu_count(logical=True)
                    or 1
                ),
                "top_cpu_processes": [],
                "hostname": self.hostname
            }

    def stop(self):
        self.running = False
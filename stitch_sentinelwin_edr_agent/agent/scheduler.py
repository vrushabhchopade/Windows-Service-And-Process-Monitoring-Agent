import time
import threading
import schedule
import logging

logger = logging.getLogger("AgentLogger")

class AgentScheduler:
    def __init__(self):
        self.running = False
        self.thread = None

    def add_job(self, interval_seconds, func, *args, **kwargs):
        schedule.every(interval_seconds).seconds.do(func, *args, **kwargs)
        logger.info(f"[+] Scheduled job '{func.__name__}' every {interval_seconds}s")

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("[+] Agent Scheduler background thread started")

    def _run_loop(self):
        while self.running:
            schedule.run_pending()
            time.sleep(1)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
        logger.info("[+] Agent Scheduler stopped")

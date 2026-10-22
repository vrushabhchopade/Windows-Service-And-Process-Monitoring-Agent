import time
import threading
import schedule
import logging

logger = logging.getLogger("AgentLogger")


class AgentScheduler:

    def __init__(self):
        self.running = False
        self.thread = None

        # Prevent the same heavy job from running multiple times
        # simultaneously.
        self.job_locks = {}

        # Protect job lock dictionary
        self.lock = threading.Lock()

    def add_job(self, interval_seconds, func, *args, **kwargs):

        # Create a lock for this specific function
        with self.lock:
            if func.__name__ not in self.job_locks:
                self.job_locks[func.__name__] = threading.Lock()

        def threaded_job():

            job_name = func.__name__
            job_lock = self.job_locks[job_name]

            # If the previous execution is still running,
            # don't start another copy of the same job.
            if not job_lock.acquire(blocking=False):
                logger.debug(
                    f"[~] Skipping '{job_name}' "
                    f"because previous execution is still running"
                )
                return

            def run_job():

                start_time = time.perf_counter()

                try:
                    logger.debug(
                        f"[>] Starting job '{job_name}'"
                    )

                    func(*args, **kwargs)

                except Exception as e:

                    logger.exception(
                        f"[!] Job '{job_name}' failed: {e}"
                    )

                finally:

                    elapsed = (
                        time.perf_counter()
                        - start_time
                    )

                    logger.debug(
                        f"[<] Job '{job_name}' "
                        f"finished in {elapsed:.2f}s"
                    )

                    job_lock.release()

            # Run the actual job independently
            worker = threading.Thread(
                target=run_job,
                name=f"AgentJob-{job_name}",
                daemon=True
            )

            worker.start()

        schedule.every(interval_seconds).seconds.do(
            threaded_job
        )

        logger.info(
            f"[+] Scheduled job '{func.__name__}' "
            f"every {interval_seconds}s"
        )

    def start(self):

        self.running = True

        self.thread = threading.Thread(
            target=self._run_loop,
            name="AgentScheduler",
            daemon=True
        )

        self.thread.start()

        logger.info(
            "[+] Agent Scheduler background thread started"
        )

    def _run_loop(self):

        while self.running:

            try:
                schedule.run_pending()

            except Exception as e:

                logger.exception(
                    f"[!] Scheduler error: {e}"
                )

            # Check every 100ms instead of every 1 second
            time.sleep(0.1)

    def stop(self):

        self.running = False

        if self.thread and self.thread.is_alive():

            self.thread.join(
                timeout=3
            )

        logger.info(
            "[+] Agent Scheduler stopped"
        )
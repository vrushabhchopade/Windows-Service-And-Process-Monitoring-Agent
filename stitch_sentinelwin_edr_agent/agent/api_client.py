import time
import random
import requests
import logging
import threading
from collections import deque

logger = logging.getLogger("AgentLogger")

class APIClient:
    def __init__(self, backend_url, username, password):
        self.backend_url = backend_url.rstrip("/")
        self.username = username
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = 0
        self.offline_buffer = deque(maxlen=500)
        self.session = requests.Session()
        self.lock = threading.RLock()

    def authenticate(self):
        with self.lock:
            url = f"{self.backend_url}/api/v1/auth/login/"
            payload = {
                "username": self.username,
                "password": self.password
            }
            try:
                resp = self._request_with_retry("POST", url, json=payload, auth_attempt=True)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    self.access_token = data.get("access") or data.get("token")
                    self.refresh_token = data.get("refresh")
                    self.token_expiry = time.time() + 1800  # 30 mins
                    logger.info(f"[+] Agent authenticated successfully with backend: {self.backend_url}")
                    return True
                else:
                    status_code = resp.status_code if resp else "No Response"
                    logger.warning(f"[-] Auth failed: HTTP {status_code}")
                    return False
            except Exception as e:
                logger.error(f"[!] Error authenticating with backend at {url}: {e}")
                return False

    def _ensure_authenticated(self):
        with self.lock:
            if not self.access_token or time.time() >= self.token_expiry - 60:
                return self.authenticate()
            return True

    def _request_with_retry(self, method, url, auth_attempt=False, **kwargs):
        """
        Executes HTTP requests with exponential backoff and jitter.
        """
        base_backoff = 1.0
        max_backoff = 10.0
        max_retries = 3

        for attempt in range(max_retries):
            try:
                if method.upper() == "POST":
                    resp = self.session.post(url, timeout=10, **kwargs)
                elif method.upper() == "GET":
                    resp = self.session.get(url, timeout=10, **kwargs)
                else:
                    resp = self.session.request(method, url, timeout=10, **kwargs)

                # If authentication call fails with 401, don't retry immediately
                if auth_attempt and resp.status_code == 401:
                    return resp

                if resp.status_code in [200, 201]:
                    return resp
                
                logger.warning(f"[-] Server returned status {resp.status_code} for {url}. Retrying...")
            except requests.RequestException as e:
                logger.warning(f"[-] Network attempt {attempt + 1} failed for {url}: {e}")

            if attempt < max_retries - 1:
                # Exponential backoff with jitter
                sleep_time = min(max_backoff, base_backoff * (2 ** attempt)) + random.uniform(0, 0.5)
                time.sleep(sleep_time)

        return None

    def post_telemetry(self, endpoint, data):
        """
        Sends telemetry payload to Django backend. Buffers offline if request fails.
        """
        with self.lock:
            if not self._ensure_authenticated():
                logger.warning(f"[!] Storing telemetry payload for {endpoint} in offline buffer")
                self.offline_buffer.append((endpoint, data))
                return False

            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            url = f"{self.backend_url}/api/v1/telemetry/{endpoint}/"

            resp = self._request_with_retry("POST", url, headers=headers, json=data)
            if resp and resp.status_code in [200, 201]:
                # Flush offline buffer if successful
                self.flush_offline_buffer()
                return True
            else:
                logger.warning(f"[-] Telemetry post to {endpoint} failed. Storing payload.")
                self.offline_buffer.append((endpoint, data))
                return False

    def fetch_iocs(self):
        """
        Fetches active IOC rules list from backend.
        """
        with self.lock:
            if not self._ensure_authenticated():
                return []
            headers = {"Authorization": f"Bearer {self.access_token}"}
            url = f"{self.backend_url}/api/v1/ioc/"
            try:
                resp = self._request_with_retry("GET", url, headers=headers)
                if resp and resp.status_code == 200:
                    res_json = resp.json()
                    if isinstance(res_json, list):
                        return res_json
                    elif isinstance(res_json, dict) and "results" in res_json:
                        return res_json["results"]
                return []
            except Exception as e:
                logger.error(f"[!] Error fetching IOCs: {e}")
                return []

    def flush_offline_buffer(self):
        with self.lock:
            if not self.offline_buffer:
                return
            logger.info(f"[+] Flushing {len(self.offline_buffer)} buffered telemetry payloads...")
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            # Flush items safely using copy
            to_flush = list(self.offline_buffer)
            self.offline_buffer.clear()
            
            for endpoint, data in to_flush:
                url = f"{self.backend_url}/api/v1/telemetry/{endpoint}/"
                try:
                    resp = self.session.post(url, json=data, headers=headers, timeout=5)
                    if resp.status_code not in [200, 201]:
                        # Re-buffer on failure
                        self.offline_buffer.append((endpoint, data))
                except Exception:
                    self.offline_buffer.append((endpoint, data))
                    break

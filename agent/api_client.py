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

    # ============================================================
    # AUTHENTICATION
    # ============================================================

    def authenticate(self):

        with self.lock:

            url = f"{self.backend_url}/api/v1/auth/login/"

            payload = {
                "username": self.username,
                "password": self.password
            }

            try:

                resp = self._request_with_retry(
                    "POST",
                    url,
                    json=payload,
                    auth_attempt=True
                )

                if resp and resp.status_code == 200:

                    data = resp.json()

                    self.access_token = (
                        data.get("access")
                        or data.get("token")
                    )

                    self.refresh_token = data.get("refresh")

                    self.token_expiry = time.time() + 1800

                    logger.info(
                        f"[+] Agent authenticated successfully "
                        f"with backend: {self.backend_url}"
                    )

                    return True

                else:

                    status_code = (
                        resp.status_code
                        if resp
                        else "No Response"
                    )

                    logger.warning(
                        f"[-] Auth failed: HTTP {status_code}"
                    )

                    return False

            except Exception as e:

                logger.error(
                    f"[!] Error authenticating with backend "
                    f"at {url}: {e}"
                )

                return False

    # ============================================================
    # ENDPOINT REGISTRATION
    # ============================================================

    def register_endpoint(self, endpoint_data):

        """
        Registers this agent/PC with the central backend.
        """

        with self.lock:

            if not self._ensure_authenticated():

                logger.warning(
                    "[!] Cannot register endpoint: "
                    "authentication failed"
                )

                return False

            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }

            url = (
                f"{self.backend_url}"
                f"/api/v1/endpoints/register/"
            )

            try:

                resp = self._request_with_retry(
                    "POST",
                    url,
                    headers=headers,
                    json=endpoint_data
                )

                if resp and resp.status_code == 200:

                    data = resp.json()

                    logger.info(
                        f"[+] Endpoint registered: "
                        f"{data.get('hostname')} "
                        f"({data.get('agent_id')})"
                    )

                    return True

                status_code = (
                    resp.status_code
                    if resp
                    else "No Response"
                )

                logger.warning(
                    f"[-] Endpoint registration failed: "
                    f"HTTP {status_code}"
                )

                return False

            except Exception as e:

                logger.error(
                    f"[!] Endpoint registration error: {e}"
                )

                return False

    # ============================================================
    # HEARTBEAT
    # ============================================================

    def send_heartbeat(self, agent_id):

        """
        Sends a heartbeat to the backend.

        Backend updates:
        - endpoint last_seen
        - endpoint online status
        """

        with self.lock:

            if not self._ensure_authenticated():

                logger.warning(
                    "[!] Heartbeat skipped: "
                    "authentication failed"
                )

                return False

            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }

            url = (
                f"{self.backend_url}"
                f"/api/v1/endpoints/heartbeat/"
            )

            payload = {
                "agent_id": agent_id
            }

            try:

                resp = self._request_with_retry(
                    "POST",
                    url,
                    headers=headers,
                    json=payload
                )

                if resp and resp.status_code == 200:

                    logger.debug(
                        f"[+] Heartbeat sent: {agent_id}"
                    )

                    return True

                status_code = (
                    resp.status_code
                    if resp
                    else "No Response"
                )

                logger.warning(
                    f"[-] Heartbeat failed: "
                    f"HTTP {status_code}"
                )

                return False

            except Exception as e:

                logger.error(
                    f"[!] Heartbeat error: {e}"
                )

                return False

    # ============================================================
    # AUTH CHECK
    # ============================================================

    def _ensure_authenticated(self):

        with self.lock:

            if (
                not self.access_token
                or time.time() >= self.token_expiry - 60
            ):

                return self.authenticate()

            return True

    # ============================================================
    # HTTP REQUEST WITH RETRY
    # ============================================================

    def _request_with_retry(
        self,
        method,
        url,
        auth_attempt=False,
        **kwargs
    ):

        """
        Executes normal HTTP requests with retry/backoff.

        Used for authentication, endpoint registration,
        heartbeat and IOC requests.

        Real-time telemetry does NOT use this function.
        """

        base_backoff = 1.0
        max_backoff = 10.0
        max_retries = 3

        for attempt in range(max_retries):

            try:

                if method.upper() == "POST":

                    resp = self.session.post(
                        url,
                        timeout=10,
                        **kwargs
                    )

                elif method.upper() == "GET":

                    resp = self.session.get(
                        url,
                        timeout=10,
                        **kwargs
                    )

                else:

                    resp = self.session.request(
                        method,
                        url,
                        timeout=10,
                        **kwargs
                    )

                # Authentication failure:
                # do not retry immediately
                if (
                    auth_attempt
                    and resp.status_code == 401
                ):

                    return resp

                if resp.status_code in [200, 201]:

                    return resp

                logger.warning(
                    f"[-] Server returned status "
                    f"{resp.status_code} for {url}. "
                    f"Retrying..."
                )

            except requests.RequestException as e:

                logger.warning(
                    f"[-] Network attempt "
                    f"{attempt + 1} failed for {url}: {e}"
                )

            if attempt < max_retries - 1:

                sleep_time = (
                    min(
                        max_backoff,
                        base_backoff * (2 ** attempt)
                    )
                    + random.uniform(0, 0.5)
                )

                time.sleep(sleep_time)

        return None

    # ============================================================
    # FAST REAL-TIME TELEMETRY
    # ============================================================

    def post_telemetry(self, endpoint, data):

        """
        Sends real-time telemetry to Django backend.

        CPU/RAM/System Health telemetry is time-sensitive,
        therefore it uses a fast single HTTP request instead
        of the normal retry/backoff mechanism.

        If the backend is temporarily unavailable, the
        payload is stored in the offline buffer.
        """

        # --------------------------------------------------------
        # Authentication check
        # --------------------------------------------------------

        if not self._ensure_authenticated():

            logger.warning(
                f"[!] Authentication failed for telemetry: "
                f"{endpoint}"
            )

            self.offline_buffer.append(
                (endpoint, data)
            )

            return False

        # --------------------------------------------------------
        # Headers
        # --------------------------------------------------------

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

        # --------------------------------------------------------
        # Endpoint
        # --------------------------------------------------------

        url = (
            f"{self.backend_url}"
            f"/api/v1/telemetry/{endpoint}/"
        )

        try:

            # ----------------------------------------------------
            # FAST SINGLE REQUEST
            #
            # connect timeout = 1 second
            # read timeout    = 2 seconds
            #
            # No exponential retry here.
            # ----------------------------------------------------

            start_time = time.perf_counter()

            logger.info(
                f"[TELEMETRY POST START] {endpoint} -> {url}"
            )

            resp = self.session.post(
                url,
                headers=headers,
                json=data,
                timeout=(1, 2)
            )

            elapsed = (
                time.perf_counter() - start_time
            )

            # ----------------------------------------------------
            # TELEMETRY RESPONSE DEBUG
            # ----------------------------------------------------

            logger.info(
                f"[TELEMETRY RESPONSE] {endpoint} "
                f"HTTP {resp.status_code} "
                f"({elapsed:.3f}s)"
            )

            # ----------------------------------------------------
            # SUCCESS
            # ----------------------------------------------------

            if resp.status_code in [200, 201]:

                logger.debug(
                    f"[+] Telemetry sent: "
                    f"{endpoint} "
                    f"({elapsed:.3f}s)"
                )

                return True

            # ----------------------------------------------------
            # AUTHENTICATION EXPIRED
            # ----------------------------------------------------

            if resp.status_code == 401:

                logger.warning(
                    f"[-] Telemetry authentication expired: "
                    f"{endpoint}"
                )

                self.access_token = None
                self.token_expiry = 0

                self.offline_buffer.append(
                    (endpoint, data)
                )

                return False

            # ----------------------------------------------------
            # SERVER ERROR
            # ----------------------------------------------------

            logger.warning(
                f"[-] Telemetry failed: "
                f"{endpoint} "
                f"HTTP {resp.status_code} "
                f"({elapsed:.3f}s)"
            )

            self.offline_buffer.append(
                (endpoint, data)
            )

            return False

        # --------------------------------------------------------
        # TIMEOUT
        # --------------------------------------------------------

        except requests.Timeout:

            logger.warning(
                f"[-] Telemetry timeout: "
                f"{endpoint}"
            )

            self.offline_buffer.append(
                (endpoint, data)
            )

            return False

        # --------------------------------------------------------
        # NETWORK ERROR
        # --------------------------------------------------------

        except requests.RequestException as e:

            logger.warning(
                f"[-] Telemetry network error: "
                f"{endpoint}: {e}"
            )

            self.offline_buffer.append(
                (endpoint, data)
            )

            return False

        # --------------------------------------------------------
        # UNEXPECTED ERROR
        # --------------------------------------------------------

        except Exception as e:

            logger.error(
                f"[!] Telemetry error: "
                f"{endpoint}: {e}"
            )

            self.offline_buffer.append(
                (endpoint, data)
            )

            return False

    # ============================================================
    # FETCH IOC RULES
    # ============================================================

    def fetch_iocs(self):

        """
        Fetches active IOC rules list from backend.
        """

        with self.lock:

            if not self._ensure_authenticated():

                return []

            headers = {
                "Authorization":
                    f"Bearer {self.access_token}"
            }

            url = (
                f"{self.backend_url}"
                f"/api/v1/ioc/"
            )

            try:

                resp = self._request_with_retry(
                    "GET",
                    url,
                    headers=headers
                )

                if resp and resp.status_code == 200:

                    res_json = resp.json()

                    if isinstance(res_json, list):

                        return res_json

                    elif (
                        isinstance(res_json, dict)
                        and "results" in res_json
                    ):

                        return res_json["results"]

                return []

            except Exception as e:

                logger.error(
                    f"[!] Error fetching IOCs: {e}"
                )

                return []

    # ============================================================
    # FLUSH OFFLINE BUFFER
    # ============================================================

    def flush_offline_buffer(self):

        with self.lock:

            if not self.offline_buffer:

                return

            logger.info(
                f"[+] Flushing "
                f"{len(self.offline_buffer)} "
                f"buffered telemetry payloads..."
            )

            headers = {
                "Authorization":
                    f"Bearer {self.access_token}",

                "Content-Type":
                    "application/json"
            }

            # Copy safely
            to_flush = list(
                self.offline_buffer
            )

            self.offline_buffer.clear()

            for endpoint, data in to_flush:

                url = (
                    f"{self.backend_url}"
                    f"/api/v1/telemetry/"
                    f"{endpoint}/"
                )

                try:

                    resp = self.session.post(
                        url,
                        json=data,
                        headers=headers,
                        timeout=5
                    )

                    logger.info(
                        f"[BUFFER RESPONSE] {endpoint} "
                        f"HTTP {resp.status_code}"
                    )

                    if resp.status_code not in [200, 201]:

                        self.offline_buffer.append(
                            (endpoint, data)
                        )

                except Exception as e:

                    logger.warning(
                        f"[BUFFER ERROR] {endpoint}: {e}"
                    )

                    self.offline_buffer.append(
                        (endpoint, data)
                    )

                    break
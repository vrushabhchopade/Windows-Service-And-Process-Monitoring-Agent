import os
import json
from pathlib import Path

class AgentConfig:
    def __init__(self, config_path=None):
        if config_path is None:
            base_dir = Path(__file__).resolve().parent.parent
            config_path = base_dir / "config" / "config.json"
        
        self.config_path = Path(config_path)
        self.data = self._load_defaults()
        if self.config_path.exists():
            self._load_file()
        self._load_env_overrides()

    def _load_defaults(self):
        return {
            "backend_url": os.getenv("SENTINEL_BACKEND_URL", "http://127.0.0.1:8000"),
            "api_version": "v1",
            "agent_id": os.getenv("SENTINEL_AGENT_ID", "WIN-EDR-AGENT-01"),
            "auth": {
                "username": os.getenv("SENTINEL_AGENT_USER", "admin"),
                "password": os.getenv("SENTINEL_AGENT_PASS", "admin123")
            },
            "monitoring": {
                "process_interval_seconds": 10,
                "service_interval_seconds": 30,
                "eventlog_interval_seconds": 15,
                "systemhealth_interval_seconds": 5,
                "ioc_sync_interval_seconds": 60
            },
            "detection": {
                "cpu_threshold_percent": 85.0,
                "memory_threshold_percent": 90.0,
                "flag_temp_execution": True,
                "flag_lolbins": True,
                "flag_unsigned": True
            },
            "logging": {
                "level": "INFO",
                "log_to_file": True,
                "log_file_path": "logs/agent.log",
                "max_bytes": 10485760,
                "backup_count": 5
            }
        }

    def _load_file(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                file_data = json.load(f)
                self._update_dict(self.data, file_data)
        except Exception as e:
            print(f"[!] Warning: Failed to load config from {self.config_path}: {e}")

    def _update_dict(self, d, u):
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._update_dict(d[k], v)
            else:
                d[k] = v

    def _load_env_overrides(self):
        if os.getenv("SENTINEL_BACKEND_URL"):
            self.data["backend_url"] = os.getenv("SENTINEL_BACKEND_URL")
        if os.getenv("SENTINEL_AGENT_USER"):
            self.data["auth"]["username"] = os.getenv("SENTINEL_AGENT_USER")
        if os.getenv("SENTINEL_AGENT_PASS"):
            self.data["auth"]["password"] = os.getenv("SENTINEL_AGENT_PASS")

    def get(self, key, default=None):
        keys = key.split(".")
        val = self.data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

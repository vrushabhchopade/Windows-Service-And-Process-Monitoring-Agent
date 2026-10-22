import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory for the backend
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file from the backend folder
load_dotenv(BASE_DIR / ".env")

class Settings:
    PROJECT_NAME: str = "SentinelShield: Advanced Intrusion Detection & Web Protection System"
    VERSION: str = "2.4.9-soc"
    API_V1_STR: str = "/api"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
    
    # Database URL: default to local SQLite database in backend directory
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'sentinelshield.db'}")
    
    # CORS Origins
    _raw_cors = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:8000"
    )
    CORS_ORIGINS: list[str] = [origin.strip() for origin in _raw_cors.split(",") if origin.strip()]
    
    # Rate Limiting configuration
    DEFAULT_RATE_LIMIT: int = int(os.getenv("DEFAULT_RATE_LIMIT", "120"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "True").lower() in ("true", "1", "yes")
    
    # Proxy trust configuration
    _raw_proxies = os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1")
    TRUSTED_PROXIES: list[str] = [ip.strip() for ip in _raw_proxies.split(",") if ip.strip()]

settings = Settings()

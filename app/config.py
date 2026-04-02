from __future__ import annotations
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/secure_medical_db"
    SECRET_KEY: str = "change-this-super-secret-key-in-production-32chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    APP_NAME: str = "SecureData Monitor"
    APP_ENV: str = "development"
    LOG_FILE: str = "logs/security.log"
    ALLOWED_HOURS_START: int = 6
    ALLOWED_HOURS_END: int = 22
    MAX_FAILED_ATTEMPTS: int = 3
    FAILED_ATTEMPTS_WINDOW: int = 120  # seconds
    RATE_LIMIT_REQUESTS: int = 20
    RATE_LIMIT_WINDOW: int = 60  # seconds
    SENSITIVE_DATA_THRESHOLD: int = 20  # per minute → critical alert

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
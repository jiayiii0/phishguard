from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "PhishGuard"
    api_prefix: str = "/api/v1"
    database_url: str = f"sqlite:///{BASE_DIR / 'phishguard.db'}"
    model_dir: Path = BASE_DIR / "backend" / "ml" / "artifacts"
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    enable_network_intel: bool = False
    enable_shap: bool = False

    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()

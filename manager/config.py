"""
manager/config.py — Pydantic settings (env-driven configuration).
"""

from __future__ import annotations
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Database ──────────────────────────────────────────────────────────────
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "otrap"
    postgres_user: str = "otrap"
    postgres_password: str = "changeme"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"
    redis_password: str = ""

    @property
    def redis_url_with_auth(self) -> str:
        if self.redis_password:
            return f"redis://:{self.redis_password}@redis:6379/0"
        return self.redis_url

    # ── Security ──────────────────────────────────────────────────────────────
    api_secret_key: str = "CHANGE_ME_64_CHAR_SECRET"
    encryption_key: str = "CHANGE_ME_32_CHAR_KEY___________"  # AES-256 for secrets at rest
    session_secure: bool = True
    session_same_site: str = "strict"
    session_max_age_hours: int = 8

    # ── Initial Admin ─────────────────────────────────────────────────────────
    initial_admin_username: str = "admin"
    initial_admin_email: str = "admin@example.com"
    initial_admin_password: str = "CHANGE_ME_PASSWORD"

    # ── gRPC ──────────────────────────────────────────────────────────────────
    grpc_host: str = "127.0.0.1"
    grpc_port: int = 9443
    join_token_ttl_hours: int = 24
    sensor_public_manager_addr: str = "127.0.0.1:9443"
    sensor_image_ref: str = "ghcr.io/otrap/sensor:latest"
    sensor_repo_url: str = "https://github.com/Janberkb/OTrap-v2-ICS-Honeypot-Intelligence-Platform.git"
    installer_base_url_override: str = ""

    @property
    def installer_base_url(self) -> str:
        """HTTP URL for the manager API used in installer curl commands."""
        if self.installer_base_url_override:
            return self.installer_base_url_override.rstrip("/")
        try:
            host, _ = self.sensor_public_manager_addr.rsplit(":", 1)
            return f"http://{host}:{self.management_port}"
        except Exception:
            return f"http://localhost:{self.management_port}"

    # ── Management ────────────────────────────────────────────────────────────
    management_host: str = "0.0.0.0"
    management_port: int = 8080
    cors_origins: str = ""
    docs_enabled: bool = False

    # ── LLM ───────────────────────────────────────────────────────────────────
    llm_enabled: bool = False
    llm_engine_url: str = "http://llm_engine:8001"

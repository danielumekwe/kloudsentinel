from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Single source of runtime configuration, loaded from environment variables
    (prefixed ``SENTINEL_``) and optionally a ``.env`` file. Every other module
    receives configuration through this object via dependency injection — none
    of them read `os.environ` directly, which keeps configuration testable and
    overridable per-test without monkeypatching the environment.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SENTINEL_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    app_name: str = "sentinel-core"
    environment: Literal["development", "test", "staging", "production"] = "production"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    database_url: str = "sqlite+aiosqlite:////data/sentinel.db"
    database_echo: bool = False

    cors_allow_origins: list[str] = Field(default_factory=list)

    discovery_scan_interval_minutes: int = 360
    integrity_scan_interval_minutes: int = 60
    inventory_scan_interval_minutes: int = 240
    monitoring_scan_interval_minutes: int = 30
    log_ingestion_interval_minutes: int = 2

    wordpress_excluded_relative_paths: list[str] = Field(
        default_factory=lambda: ["wp-content/uploads", "wp-content/cache"]
    )

    # File integrity monitoring scans whole cPanel account home directories,
    # so its exclusions cover both account-wide noise (mail, logs, tmp) and
    # WordPress media/cache subtrees, matched anywhere in a file's path.
    integrity_excluded_relative_paths: list[str] = Field(
        default_factory=lambda: [
            "mail",
            "logs",
            "tmp",
            ".cache",
            ".trash",
            ".cagefs",
            "wp-content/uploads",
            "wp-content/cache",
        ]
    )
    integrity_max_file_size_bytes: int = 26_214_400

    event_dedup_window_minutes: int = 60

    cpanel_etc_directory: str = "/etc"
    cpanel_home_base_directory: str = "/home"
    cpanel_suspended_directory: str = "/var/cpanel/suspended"
    wordpress_detection_max_depth: int = 4

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def is_test(self) -> bool:
        return self.environment == "test"


@lru_cache
def get_settings() -> Settings:
    return Settings()

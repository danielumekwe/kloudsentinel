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

    # Safety switch gating every mutation-capable endpoint (quarantine,
    # restore, delete) and the offline `scan-archive --apply-quarantine`
    # flag. "observe" blocks all of them — detection/scanning is unaffected
    # either way, since scanning never writes to the host filesystem.
    # "manual" is today's real behavior: remediation only ever happens when
    # an authenticated operator explicitly calls it. "active" is reserved
    # for future automatic remediation (not yet implemented) and currently
    # behaves identically to "manual".
    mode: Literal["observe", "manual", "active"] = "observe"

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

    # Where quarantined files are moved to. Deliberately outside every
    # account's home directory: FilesystemFileScanner only walks
    # account.home_directory, so anything here is invisible to future scans
    # and unreachable by the web server regardless of permissions.
    quarantine_root_directory: str = "/var/lib/sentinel/quarantine"

    event_dedup_window_minutes: int = 60

    # Security Intelligence Engine (forensics + intelligence contexts): watches
    # for freshly-dropped script-like files and correlates the resulting
    # SecurityEvents into Incidents, so e.g. six unrelated-looking
    # /tmp/update_*.php alerts are recognized as one attack instead of six.
    forensics_temp_directories: list[str] = Field(
        default_factory=lambda: ["/tmp", "/var/tmp", "/dev/shm"]
    )
    forensics_watched_extensions: list[str] = Field(
        default_factory=lambda: [".php", ".pl", ".cgi", ".sh"]
    )
    forensics_scan_interval_minutes: int = 5
    correlation_interval_minutes: int = 5
    correlation_time_window_minutes: int = 60

    cpanel_etc_directory: str = "/etc"
    cpanel_home_base_directory: str = "/home"
    cpanel_suspended_directory: str = "/var/cpanel/suspended"
    wordpress_detection_max_depth: int = 4

    # Validated by `sentinel doctor` and at process startup, but not read by
    # any scan logic yet — reserved for the future log_collection context and
    # for confirming a host is genuinely a cPanel/WHM server before trusting
    # its other paths.
    proc_directory: str = "/proc"
    var_log_directory: str = "/var/log"
    cpanel_binaries_directory: str = "/usr/local/cpanel"

    # Base URL the CLI's `sentinel health` command calls to check API
    # liveness/readiness — the CLI is a third, separate process from the API
    # and worker, so this is the only way it can observe the API at all.
    api_base_url: str = "http://localhost:8443"

    # WordPress Security Engine: composes the discovery/inventory/integrity/
    # forensics/intelligence contexts above with WordPress-specific policy,
    # rather than duplicating them. See docs/architecture for the reuse map.
    wordpress_discovery_excluded_directory_markers: list[str] = Field(
        default_factory=lambda: [
            "virtfs",
            ".trash",
            "backup",
            "backups",
            "_bak",
            ".bak",
            "-old",
            "_old",
            "old_site",
            "staging",
        ]
    )
    # The 8 files explicitly named in the incident brief — checked for
    # elevated severity on any change and, when a hash is known, compared
    # against WordPress.org's official core checksums.
    wordpress_critical_relative_paths: list[str] = Field(
        default_factory=lambda: [
            "index.php",
            "wp-config.php",
            "wp-settings.php",
            "wp-load.php",
            "wp-blog-header.php",
            "wp-content/db.php",
            "wp-content/object-cache.php",
            "wp-content/advanced-cache.php",
        ]
    )
    wordpress_dropin_relative_paths: list[str] = Field(
        default_factory=lambda: [
            "wp-content/db.php",
            "wp-content/object-cache.php",
            "wp-content/advanced-cache.php",
        ]
    )
    # Substrings checked (case-insensitively) against each crontab command —
    # not a malware signature engine, just the handful of shell idioms that
    # show up in cron-based persistence (download-and-execute, obfuscation).
    wordpress_suspicious_cron_markers: list[str] = Field(
        default_factory=lambda: [
            "base64_decode",
            "eval(",
            "curl ",
            "wget ",
            "| bash",
            "| sh",
            "-o- | sh",
        ]
    )
    # cPanel/CloudLinux convention: one crontab file per system user, named
    # after the username, under this directory.
    wordpress_crontab_directory: str = "/var/spool/cron"
    wordpress_inventory_scan_interval_minutes: int = 240
    wordpress_integrity_audit_interval_minutes: int = 60
    wordpress_forensic_scan_interval_minutes: int = 15

    # WordPress.org's public checksums API — used only to populate the
    # local `CoreChecksumRecord` reference cache (once per wp_version, not
    # per scan), never called on the hot path of a routine integrity scan.
    wordpress_core_checksums_api_base_url: str = "https://api.wordpress.org/core/checksums/1.0/"
    wordpress_core_checksums_locale: str = "en_US"

    # Auto-quarantine: only takes effect when `mode == "active"`. A
    # circuit breaker caps how many CRITICAL findings one account can have
    # auto-quarantined in a single run — beyond the cap, the rest are left
    # untouched and one alert event is raised instead of continuing to act
    # unattended.
    auto_quarantine_max_per_account_per_run: int = 5
    auto_quarantine_interval_minutes: int = 20

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def is_test(self) -> bool:
        return self.environment == "test"


@lru_cache
def get_settings() -> Settings:
    return Settings()

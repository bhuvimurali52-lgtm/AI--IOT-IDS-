"""Application configuration loaded from environment variables."""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_DEV_CORS_DEFAULT = "http://127.0.0.1:8502,http://localhost:8502"


class Settings(BaseSettings):
    """Central configuration for the IoT IDS application.

    Values are loaded from environment variables and an optional `.env` file.
    Secrets must never be hard-coded in source.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    app_name: str = "AI-Powered IoT Intrusion Detection"
    app_version: str = "0.8.0"
    app_env: str = Field(
        default="development",
        validation_alias=AliasChoices("APP_ENV", "ENVIRONMENT"),
    )
    debug: bool = True

    # API / dashboard
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    dashboard_port: int = Field(default=8502, ge=1, le=65535)
    # Dashboard HTTP base URL (use 127.0.0.1, not 0.0.0.0).
    dashboard_api_url: str = "http://127.0.0.1:8000"

    # CORS: comma-separated origins. Wildcard is rejected in production.
    # Never pair wildcard origins with credentials.
    cors_allowed_origins: str = _DEV_CORS_DEFAULT
    cors_allow_credentials: bool = False

    # Logging
    log_level: str = "INFO"
    log_dir: Path = Path("logs")

    # Paths (Phase 1/2)
    data_raw_dir: Path = Path("data/raw")
    data_processed_dir: Path = Path("data/processed")
    data_sample_dir: Path = Path("data/sample")
    models_dir: Path = Path("models")

    # Dataset configuration (Phase 2 CSV pipeline)
    dataset_path: Path = Path("data/raw/dataset.csv")
    target_column: str = "label"
    test_size: float = Field(default=0.2, gt=0.0, lt=1.0)
    random_state: int = 42

    # Legacy SQLAlchemy-style URL (Phase 1 placeholder compatibility)
    database_url: str = "sqlite:///./iot_ids.db"

    # Phase 3 — IDS runtime
    ids_mode: str = Field(default="synthetic")
    capture_interface: str | None = None
    capture_duration: float = Field(default=10.0, gt=0.0, le=3600.0)
    capture_packet_count: int = Field(default=100, ge=1, le=1_000_000)
    capture_bpf_filter: str | None = None
    model_path: Path = Path("models/anomaly_detector.joblib")
    preprocessor_path: Path = Path("models/baseline_preprocessor.joblib")
    database_path: Path = Path("data/ids.db")
    anomaly_contamination: float = Field(default=0.05, gt=0.0, lt=0.5)
    n_estimators: int = Field(default=100, ge=1, le=5000)
    alert_risk_threshold: int = Field(default=60, ge=0, le=100)

    # Phase 4 — live flow completion / capture session
    flow_timeout_seconds: float = Field(default=5.0, ge=0.5, le=300.0)
    live_capture_background: bool = True

    # Risk severity upper bounds: Low / Medium / High; above High => Critical
    risk_low_max: int = Field(default=29, ge=0, le=100)
    risk_medium_max: int = Field(default=59, ge=0, le=100)
    risk_high_max: int = Field(default=79, ge=0, le=100)

    # Retention: 0 disables automatic deletion. Never purge unless explicitly > 0
    # and a documented maintenance call is made.
    ids_retention_days: int = Field(default=0, ge=0, le=3650)

    # Optional API list size default (routes still clamp Query limits).
    api_list_limit_default: int = Field(default=50, ge=1, le=500)
    api_list_limit_max: int = Field(default=500, ge=1, le=5000)

    @field_validator("ids_mode")
    @classmethod
    def _validate_ids_mode(cls, value: str) -> str:
        mode = str(value or "").strip().lower()
        if mode not in {"synthetic", "live"}:
            raise ValueError("IDS_MODE must be 'synthetic' or 'live'")
        return mode

    @field_validator("app_env")
    @classmethod
    def _validate_app_env(cls, value: str) -> str:
        env = str(value or "development").strip().lower()
        if env not in {"development", "test", "production"}:
            raise ValueError("APP_ENV must be development, test, or production")
        return env

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = str(value or "INFO").strip().upper()
        if level not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"LOG_LEVEL must be one of {sorted(_VALID_LOG_LEVELS)}"
            )
        return level

    @field_validator("api_host")
    @classmethod
    def _validate_api_host(cls, value: str) -> str:
        host = str(value or "127.0.0.1").strip()
        if not host:
            raise ValueError("API_HOST must not be empty")
        return host

    @model_validator(mode="after")
    def _validate_cross_fields(self) -> Settings:
        if not (self.risk_low_max < self.risk_medium_max < self.risk_high_max):
            raise ValueError(
                "Risk bounds must satisfy RISK_LOW_MAX < RISK_MEDIUM_MAX < RISK_HIGH_MAX"
            )
        origins = self.cors_origin_list()
        if self.app_env == "production" and "*" in origins:
            raise ValueError(
                "CORS_ALLOWED_ORIGINS must not include '*' in production. "
                "Set explicit origins (for example http://127.0.0.1:8502)."
            )
        if "*" in origins and bool(self.cors_allow_credentials):
            raise ValueError(
                "CORS credentials cannot be enabled with wildcard origins."
            )
        self.cors_allow_credentials = False
        return self

    @property
    def environment(self) -> str:
        """Backward-compatible alias for APP_ENV."""
        return self.app_env

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def cors_origin_list(self) -> list[str]:
        raw = (self.cors_allowed_origins or "").strip()
        if not raw:
            return [] if self.is_production else [
                origin.strip() for origin in _DEV_CORS_DEFAULT.split(",")
            ]
        return [part.strip() for part in raw.split(",") if part.strip()]

    def resolved_dashboard_api_url(self) -> str:
        """Return the dashboard→API base URL, aligned with ``api_port`` when unset."""
        url = (self.dashboard_api_url or "").strip()
        if not url:
            return f"http://127.0.0.1:{int(self.api_port)}"
        return url.rstrip("/")

    def public_status_fields(self) -> dict[str, str | int | bool]:
        """Non-secret configuration snapshot for health/status (no env dump)."""
        return {
            "app_env": self.app_env,
            "debug": bool(self.debug) and not self.is_production,
            "api_port": int(self.api_port),
            "dashboard_port": int(self.dashboard_port),
            "ids_mode": self.ids_mode,
            "log_level": self.log_level,
        }


def validate_runtime_paths(settings: Settings) -> list[str]:
    """Return actionable warnings. Does not require Npcap or a trained model."""
    warnings: list[str] = []
    db_parent = Path(settings.database_path).parent
    if str(db_parent) not in {"", "."} and not db_parent.exists():
        try:
            db_parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            warnings.append(
                f"Cannot create database directory '{db_parent}': {exc}. "
                "Set DATABASE_PATH to a writable location."
            )
    model_path = Path(settings.model_path)
    if not model_path.exists():
        warnings.append(
            f"Model artifact not found at {model_path}. "
            "Synthetic/live inference will remain unavailable until the "
            "existing IsolationForest artifact is present. "
            "Do not retrain automatically."
        )
    log_dir = Path(settings.log_dir)
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        warnings.append(f"Cannot create log directory '{log_dir}': {exc}")
    return warnings


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()

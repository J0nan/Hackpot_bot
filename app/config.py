"""Environment-only configuration, validated fail-fast at startup.

All values come from docker compose env vars (Spec S6). This module is the
shared contract for every other component: import `Settings` and read fields,
never call os.environ elsewhere.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Any

from cryptography.fernet import Fernet, InvalidToken  # noqa: F401  (key validation)
from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.logging_config import LEVELS

# github.com owner/repo (owner max 39, repo max 100 chars)
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38})/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$")
# Hackpot leaf category path: "NN_Domain_Name/Sub_Category"
LEAF_PATH_RE = re.compile(r"^\d{2}_[A-Za-z0-9_]+/[A-Za-z0-9_]+$")
# System One contract limit: choice options 1-255.
MAX_CATEGORIES = 255


class Settings(BaseSettings):
    """Bot settings loaded from the environment (docker compose)."""

    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    telegram_bot_token: SecretStr
    authorized_user_ids: Annotated[frozenset[int], NoDecode] = Field(
        validation_alias=AliasChoices("AUTHORIZED_USERS", "authorized_users")
    )
    target_repo: str = "J0nan/Hackpot"
    target_branch: str = "main"
    categories: Annotated[dict[str, str], NoDecode] = Field(
        validation_alias=AliasChoices("CATEGORIES_JSON", "categories")
    )
    qwen_api_url: str = Field(validation_alias=AliasChoices("QWEN_API_URL", "qwen_api_url"))
    qwen_api_key: SecretStr = Field(validation_alias=AliasChoices("QWEN_API_KEY", "qwen_api_key"))
    qwen_model: str = Field(default="decision-model-preview",
                            validation_alias=AliasChoices("QWEN_MODEL", "qwen_model"))
    confidence_threshold: float = Field(default=0.15, ge=0.0, le=1.0)
    max_candidates_shown: int = Field(default=3, ge=1, le=10)
    db_path: Path = Field(default=Path("data/hackpot.sqlite3"))
    fernet_key: SecretStr = Field(
        validation_alias=AliasChoices("SECRETS_ENCRYPTION_KEY", "fernet_key")
    )
    rate_limit_per_min: int = Field(default=10, ge=1, le=1000)
    # LOG_LEVEL (env, case-insensitive via model_config) — drives setup_logging.
    # Default keeps every existing Settings construction green (S6).
    log_level: str = "INFO"

    @field_validator("authorized_user_ids", mode="before")
    @classmethod
    def _parse_users(cls, value: Any) -> Any:
        """Accept comma-separated Telegram user IDs or an iterable."""
        if isinstance(value, str):
            parts = [p.strip() for p in value.split(",") if p.strip()]
            value = frozenset(int(p) for p in parts)
        return value

    @field_validator("authorized_user_ids")
    @classmethod
    def _check_users(cls, value: frozenset[int]) -> frozenset[int]:
        if not value:
            raise ValueError("AUTHORIZED_USERS must contain at least one user ID")
        if any(uid <= 0 for uid in value):
            raise ValueError("AUTHORIZED_USERS must be positive Telegram user IDs")
        return value

    @field_validator("categories", mode="before")
    @classmethod
    def _parse_categories(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = json.loads(value)
        return value

    @field_validator("categories")
    @classmethod
    def _check_categories(cls, value: dict[str, str]) -> dict[str, str]:
        if not isinstance(value, dict) or not value:
            raise ValueError("CATEGORIES_JSON must be a non-empty JSON object")
        if len(value) > MAX_CATEGORIES:
            raise ValueError(f"CATEGORIES_JSON exceeds the {MAX_CATEGORIES}-option model limit")
        for path, criteria in value.items():
            if not LEAF_PATH_RE.match(path):
                raise ValueError(f"invalid leaf category path: {path!r}")
            if not isinstance(criteria, str) or not criteria.strip():
                raise ValueError(f"missing decision criteria for category {path!r}")
        return {k: v.strip() for k, v in value.items()}

    @field_validator("target_repo")
    @classmethod
    def _check_repo(cls, value: str) -> str:
        if not REPO_RE.match(value):
            raise ValueError(f"TARGET_REPO must be 'owner/repo', got {value!r}")
        return value

    @field_validator("qwen_api_url")
    @classmethod
    def _check_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("QWEN_API_URL must be an https:// URL")
        return value.rstrip("/")

    @field_validator("log_level")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        cleaned = (value or "").strip().upper()
        if cleaned not in LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of {', '.join(LEVELS)}, got {value!r}")
        return cleaned

    @field_validator("fernet_key")
    @classmethod
    def _check_fernet(cls, value: SecretStr) -> SecretStr:
        try:
            Fernet(value.get_secret_value().encode())
        except Exception as exc:  # noqa: BLE001 - must wrap any key error
            raise ValueError("SECRETS_ENCRYPTION_KEY is not a valid Fernet key") from exc
        return value

    @model_validator(mode="after")
    def _check_secrets_nonempty(self) -> "Settings":
        if not self.telegram_bot_token.get_secret_value().strip():
            raise ValueError("TELEGRAM_BOT_TOKEN must not be empty")
        if not self.qwen_api_key.get_secret_value().strip():
            raise ValueError("QWEN_API_KEY must not be empty")
        return self

    def folder_or_reject(self, folder: str) -> str:
        """Return folder only if it is an exact configured leaf path (anti-traversal)."""
        if folder not in self.categories:
            raise ValueError(f"unknown category: {folder!r}")
        return folder

    def readme_path(self, folder: str) -> str:
        """Path of the leaf README inside the target repo (S13)."""
        return f"{self.folder_or_reject(folder)}/README.md"

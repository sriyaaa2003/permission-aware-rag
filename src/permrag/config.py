"""Deployment settings (environment). Changing them requires a restart. Secrets are env-only."""

from __future__ import annotations

from functools import lru_cache

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PR_", env_file=".env", extra="ignore")

    db_path: str = "permrag.db"
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    log_level: str = "INFO"

    # --- authentication: tokens are issued by your identity provider (or `permrag token` in dev)
    jwt_key: SecretStr | None = None  # HS256 shared secret, or PEM public key for RS256/ES256
    jwt_algorithm: str = "HS256"
    jwt_issuer: str | None = None
    jwt_leeway_seconds: int = 10
    admin_role_name: str = "admin"
    rate_limit_per_minute: int = 60  # per user, in-process; 0 disables

    # --- audit log integrity: HMAC key kept outside the database
    audit_hmac_key: SecretStr | None = None
    audit_log_query_text: bool = False

    # --- retrieval / chunking
    default_top_k: int = 5
    max_top_k: int = 20
    chunk_chars: int = 800
    chunk_overlap_chars: int = 100
    max_context_chars: int = 6000
    max_document_chars: int = 2_000_000

    # --- generation (optional: /v1/search works without it)
    llm_provider: str | None = None  # "anthropic" | "openai_compat"
    llm_model_id: str | None = None
    llm_base_url: str | None = None
    llm_api_key_env: str | None = None  # name of the env var that holds the key
    llm_max_tokens: int = 600
    llm_temperature: float = 0.0
    llm_timeout_seconds: float = 60.0
    abstain_token: str = "INSUFFICIENT_CONTEXT"  # noqa: S105 (sentinel string, not a secret)

    @model_validator(mode="after")
    def _key_strength(self) -> Settings:
        if self.jwt_key and self.jwt_algorithm.startswith("HS"):
            if len(self.jwt_key.get_secret_value().encode()) < 32:
                raise ValueError("PR_JWT_KEY must be at least 32 bytes for HS* algorithms")
        if self.audit_hmac_key and len(self.audit_hmac_key.get_secret_value().encode()) < 16:
            raise ValueError("PR_AUDIT_HMAC_KEY must be at least 16 bytes")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

"""Bearer-token verification. Tokens prove *who* the caller is; what they may do is always read
from the database (see access.load_user)."""

from __future__ import annotations

import time
from dataclasses import dataclass

import jwt

from .config import Settings


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class TokenClaims:
    user_id: str
    tenant_id: str


def verify_token(token: str, settings: Settings) -> TokenClaims:
    if settings.jwt_key is None:
        raise AuthError("server has no JWT key configured")
    try:
        claims = jwt.decode(
            token,
            settings.jwt_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],  # never trust the token's own alg header
            issuer=settings.jwt_issuer,
            leeway=settings.jwt_leeway_seconds,
            options={
                "require": ["exp", "sub", "tid"],
                "verify_iss": settings.jwt_issuer is not None,
            },
        )
    except jwt.PyJWTError as exc:
        raise AuthError(f"invalid token: {type(exc).__name__}") from exc
    return TokenClaims(user_id=str(claims["sub"]), tenant_id=str(claims["tid"]))


def mint_token(settings: Settings, user_id: str, tenant_id: str, ttl_seconds: int = 3600) -> str:
    """Development/testing issuer (symmetric algorithms only). Production tokens should come
    from your identity provider."""
    if settings.jwt_key is None:
        raise AuthError("PR_JWT_KEY is not set")
    if not settings.jwt_algorithm.startswith("HS"):
        raise AuthError("minting is only supported for HS* algorithms")
    now = int(time.time())
    payload: dict[str, object] = {
        "sub": user_id,
        "tid": tenant_id,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if settings.jwt_issuer:
        payload["iss"] = settings.jwt_issuer
    return jwt.encode(
        payload, settings.jwt_key.get_secret_value(), algorithm=settings.jwt_algorithm
    )

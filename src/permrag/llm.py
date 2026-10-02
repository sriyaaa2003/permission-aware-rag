"""LLM provider interface plus Anthropic and OpenAI-compatible HTTP implementations.

The OpenAI-compatible client covers OpenAI, Ollama, vLLM, LM Studio and any server exposing
``/chat/completions``. Provider failures are raised as :class:`LLMError` with a ``retryable`` flag;
nothing here fabricates a response.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Protocol

import httpx


class LLMError(Exception):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class LLMResult:
    text: str
    input_tokens: int
    output_tokens: int
    latency_ms: float


class LLMProvider(Protocol):
    def generate(
        self, system: str, user: str, *, max_tokens: int, temperature: float
    ) -> LLMResult: ...


def _check_status(resp: httpx.Response) -> None:
    if resp.status_code == 200:
        return
    retryable = resp.status_code in (408, 409, 425, 429) or resp.status_code >= 500
    raise LLMError(f"HTTP {resp.status_code}: {resp.text[:300]}", retryable=retryable)


class AnthropicProvider:
    def __init__(self, model_id: str, api_key: str, *, base_url: str | None, timeout: float):
        self.model_id = model_id
        self._key = api_key
        self._base = (base_url or "https://api.anthropic.com").rstrip("/")
        self._timeout = timeout

    def generate(self, system: str, user: str, *, max_tokens: int, temperature: float) -> LLMResult:
        start = time.perf_counter()
        try:
            resp = httpx.post(
                f"{self._base}/v1/messages",
                headers={
                    "x-api-key": self._key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model_id,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
                timeout=self._timeout,
            )
        except httpx.TransportError as exc:
            raise LLMError(f"transport error: {exc}", retryable=True) from exc
        _check_status(resp)
        body = resp.json()
        text = "".join(
            b.get("text", "") for b in body.get("content", []) if b.get("type") == "text"
        )
        usage = body.get("usage", {})
        return LLMResult(
            text=text,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            latency_ms=(time.perf_counter() - start) * 1000,
        )


class OpenAICompatProvider:
    def __init__(self, model_id: str, api_key: str | None, *, base_url: str | None, timeout: float):
        self.model_id = model_id
        self._key = api_key
        self._base = (base_url or "https://api.openai.com/v1").rstrip("/")
        self._timeout = timeout

    def generate(self, system: str, user: str, *, max_tokens: int, temperature: float) -> LLMResult:
        start = time.perf_counter()
        headers = {"content-type": "application/json"}
        if self._key:
            headers["authorization"] = f"Bearer {self._key}"
        try:
            resp = httpx.post(
                f"{self._base}/chat/completions",
                headers=headers,
                json={
                    "model": self.model_id,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
                timeout=self._timeout,
            )
        except httpx.TransportError as exc:
            raise LLMError(f"transport error: {exc}", retryable=True) from exc
        _check_status(resp)
        body = resp.json()
        try:
            text = body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"malformed response: {str(body)[:200]}", retryable=False) from exc
        usage = body.get("usage", {})
        return LLMResult(
            text=text,
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
            latency_ms=(time.perf_counter() - start) * 1000,
        )


def build_provider(
    provider: str,
    model_id: str,
    *,
    base_url: str | None,
    api_key_env: str | None,
    timeout: float,
) -> LLMProvider:
    """Create a provider from a ``models`` row. The key is read from the named env variable."""
    api_key = os.environ.get(api_key_env) if api_key_env else None
    if provider == "anthropic":
        if not api_key:
            raise LLMError(f"environment variable {api_key_env!r} is not set", retryable=False)
        return AnthropicProvider(model_id, api_key, base_url=base_url, timeout=timeout)
    if provider == "openai_compat":
        if api_key_env and not api_key:
            raise LLMError(f"environment variable {api_key_env!r} is not set", retryable=False)
        return OpenAICompatProvider(model_id, api_key, base_url=base_url, timeout=timeout)
    raise LLMError(f"unknown provider {provider!r}", retryable=False)

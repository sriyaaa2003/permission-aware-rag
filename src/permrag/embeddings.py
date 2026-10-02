"""Embedding provider interface and the default local ONNX implementation (fastembed)."""

from __future__ import annotations

import threading
from typing import Any, Protocol

import numpy as np


class Embedder(Protocol):
    """Returns L2-normalised float32 vectors, shape (len(texts), dim)."""

    def embed(self, texts: list[str]) -> np.ndarray: ...


class FastEmbedEmbedder:
    """Local embedding model. The model is downloaded on first use and cached by fastembed."""

    def __init__(self, model_name: str) -> None:
        self.model_name = model_name
        self._model: Any = None
        self._lock = threading.Lock()

    def _load(self) -> Any:
        with self._lock:
            if self._model is None:
                from fastembed import TextEmbedding

                self._model = TextEmbedding(self.model_name)
        return self._model

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, 0), dtype=np.float32)
        model = self._load()
        vecs = np.asarray(list(model.embed(texts)), dtype=np.float32)
        return normalise(vecs)


def normalise(vecs: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    out: np.ndarray = (vecs / norms).astype(np.float32)
    return out


def to_blob(vec: np.ndarray) -> bytes:
    return np.asarray(vec, dtype=np.float32).tobytes()


def from_blob(blob: bytes) -> np.ndarray:
    return np.frombuffer(blob, dtype=np.float32)

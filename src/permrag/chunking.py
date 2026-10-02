"""Sentence-aware text chunking."""

from __future__ import annotations

import re


def chunk_text(text: str, chunk_chars: int, overlap: int) -> list[str]:
    """Split on paragraph then sentence boundaries into chunks of about ``chunk_chars``."""
    if overlap >= chunk_chars:
        raise ValueError("overlap must be smaller than chunk size")
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n{2,}", text) if s.strip()]
    chunks: list[str] = []
    current = ""
    for sent in sentences:
        while len(sent) > chunk_chars:  # a single over-long sentence
            if current:
                chunks.append(current)
                current = ""
            chunks.append(sent[:chunk_chars])
            sent = sent[chunk_chars - overlap :]
        if current and len(current) + len(sent) + 1 > chunk_chars:
            chunks.append(current)
            tail = current[-overlap:] if overlap else ""
            current = (tail + " " + sent).strip()
        else:
            current = f"{current} {sent}".strip()
    if current:
        chunks.append(current)
    return chunks

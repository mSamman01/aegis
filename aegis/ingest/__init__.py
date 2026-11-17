"""Ingest: turn raw alerts from a source system into normalized Events."""

from aegis.ingest.wazuh import (
    AlertError,
    IngestIssue,
    IngestResult,
    ingest_file,
    ingest_text,
    normalize_alert,
)

__all__ = [
    "AlertError",
    "IngestIssue",
    "IngestResult",
    "ingest_file",
    "ingest_text",
    "normalize_alert",
]

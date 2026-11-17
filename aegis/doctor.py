"""Environment checks: is this machine ready to run Aegis?"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_OLLAMA_URL = "http://localhost:11434"
MIN_PYTHON = (3, 10)

OK, WARN, FAIL = "OK", "WARN", "FAIL"


@dataclass(frozen=True)
class Check:
    status: str  # OK / WARN / FAIL
    message: str


def ollama_url() -> str:
    return os.environ.get("AEGIS_OLLAMA_URL", DEFAULT_OLLAMA_URL).rstrip("/")


def check_python(version: tuple[int, ...] | None = None) -> Check:
    version = tuple(version or sys.version_info[:3])
    text = ".".join(str(part) for part in version)
    if version[:2] >= MIN_PYTHON:
        return Check(OK, f"Python {text}")
    wanted = ".".join(str(part) for part in MIN_PYTHON)
    return Check(FAIL, f"Python {text} is too old; Aegis needs {wanted} or newer")


def check_ollama(url: str | None = None, timeout: float = 3.0) -> Check:
    """Ask the local Ollama server which models are installed."""
    url = (url or ollama_url()).rstrip("/")
    try:
        with urllib.request.urlopen(f"{url}/api/tags", timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return Check(
            FAIL,
            f"Ollama not reachable at {url} ({reason}). "
            "Open the Ollama app or run: ollama serve",
        )
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        return Check(FAIL, f"Unexpected answer from {url}/api/tags")
    if not models:
        return Check(WARN, f"Ollama is running at {url} but no models are pulled yet")
    described = []
    for model in models:
        if not isinstance(model, dict):
            continue
        name = str(model.get("name") or model.get("model") or "?")
        size = model.get("size")
        if isinstance(size, (int, float)) and not isinstance(size, bool):
            described.append(f"{name} ({size / 1e9:.1f} GB)")
        else:
            described.append(name)
    version = ollama_version(url, timeout)
    label = f"Ollama {version}" if version else "Ollama"
    return Check(OK, f"{label} at {url} - {len(described)} model(s): " + ", ".join(described))


def ollama_version(url: str, timeout: float = 3.0) -> str | None:
    try:
        with urllib.request.urlopen(f"{url}/api/version", timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None
    version = payload.get("version") if isinstance(payload, dict) else None
    return version if isinstance(version, str) and version else None


def run_checks() -> list[Check]:
    return [check_python(), check_ollama()]

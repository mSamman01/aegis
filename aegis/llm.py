"""A minimal client for a local Ollama server (standard library only).

One function, one request: ``chat`` posts to ``/api/chat`` with streaming off
and returns the raw JSON answer. The model can only return text; this module
gives it no tools.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:4b"


class LLMError(RuntimeError):
    """The model could not be reached or did not give a usable HTTP answer."""


def ollama_url() -> str:
    return os.environ.get("AEGIS_OLLAMA_URL", DEFAULT_OLLAMA_URL).rstrip("/")


def default_model() -> str:
    return os.environ.get("AEGIS_MODEL", DEFAULT_MODEL)


def chat(request: dict[str, Any], *, url: str | None = None, timeout: float = 300.0) -> dict[str, Any]:
    """Send one chat request to Ollama and return its JSON answer."""
    url = (url or ollama_url()).rstrip("/")
    model = request.get("model", "?")
    _check_reachable(url, timeout)
    body = json.dumps(request).encode("utf-8")
    http_request = urllib.request.Request(
        f"{url}/api/chat", data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(http_request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = _error_text(exc.read())
        if exc.code == 404:
            raise LLMError(
                f"Ollama does not have the model {model!r} ({detail}). Get it with: ollama pull {model}"
            ) from exc
        raise LLMError(f"Ollama answered HTTP {exc.code}: {detail}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise LLMError(f"no answer from the model within {timeout:g} s (try --timeout with a larger value)") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise LLMError(
                f"no answer from the model within {timeout:g} s (try --timeout with a larger value)"
            ) from exc
        raise LLMError(
            f"Ollama not reachable at {url} ({exc.reason}). Open the Ollama app or run: ollama serve"
        ) from exc
    except OSError as exc:
        raise LLMError(f"connection to Ollama at {url} failed: {exc}") from exc

    try:
        answer = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LLMError("Ollama's answer was not JSON") from exc
    if not isinstance(answer, dict):
        raise LLMError("Ollama's answer was not a JSON object")
    if answer.get("error"):
        raise LLMError(f"Ollama reported an error: {answer['error']}")
    message = answer.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise LLMError("Ollama's answer has no message content")
    return answer


def _check_reachable(url: str, timeout: float) -> None:
    """Fail fast, and clearly, when nothing is listening at ``url``.

    Waiting for the model can rightly take minutes; finding out that Ollama is
    not running should not. A quick connection test keeps "not running" and
    "still thinking" apart on every operating system.
    """
    parts = urllib.parse.urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        socket.create_connection((parts.hostname or "localhost", port), timeout=min(timeout, 5.0)).close()
    except OSError as exc:
        raise LLMError(
            f"Ollama not reachable at {url} ({exc}). Open the Ollama app or run: ollama serve"
        ) from exc


def _error_text(raw: bytes) -> str:
    try:
        data = json.loads(raw.decode("utf-8"))
        if isinstance(data, dict) and data.get("error"):
            return str(data["error"])
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    text = raw.decode("utf-8", "replace").strip()
    return text[:200] or "no details"

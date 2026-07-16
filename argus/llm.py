"""
Local LLM backend client.

Thin wrapper over the Ollama HTTP API. Everything here is local-only by design:
the base URL points at localhost. If the daemon is unreachable, calls fail
loudly rather than silently falling back to any cloud service.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

log = logging.getLogger("argus.llm")


class LLMUnavailable(RuntimeError):
    """Raised when the local Ollama backend cannot be reached."""


class OllamaClient:
    """Minimal Ollama /api/generate client. No third-party dependencies."""

    def __init__(self, host: str, timeout_s: int = 120) -> None:
        self.host = host.rstrip("/")
        self.timeout_s = timeout_s

    def generate(self, model: str, prompt: str, *, temperature: float = 0.0,
                 system: str | None = None) -> str:
        """
        Single-shot, stateless generation. Stateless is deliberate: it mirrors
        ShellGPT's --shell prompt isolation, the mechanism the thesis identifies
        as enabling reliable security-sensitive command generation.
        """
        payload: dict = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system

        data = json.dumps(payload).encode("utf-8")
        url = f"{self.host}/api/generate"
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body.get("response", "").strip()
        except urllib.error.URLError as exc:
            raise LLMUnavailable(
                f"Cannot reach local Ollama at {self.host}: {exc}. "
                f"Start it with `ollama serve` and pull the model with "
                f"`ollama pull {model}`."
            ) from exc

    def health(self) -> bool:
        """Return True if the local daemon answers."""
        try:
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except urllib.error.URLError:
            return False

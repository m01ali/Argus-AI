"""
Local LLM backend client.

Thin wrapper over the Ollama HTTP API. Everything here is local-only by design:
the base URL points at localhost. If the daemon is unreachable, calls fail
loudly rather than silently falling back to any cloud service.
"""

from __future__ import annotations

import json
import logging
import socket
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
                 system: str | None = None, max_tokens: int | None = None,
                 think: bool | None = None) -> str:
        """
        Single-shot, stateless generation. Stateless is deliberate: it mirrors
        ShellGPT's --shell prompt isolation, the mechanism the thesis identifies
        as enabling reliable security-sensitive command generation.

        max_tokens (Ollama's "num_predict" option) bounds worst-case
        generation length — short structured outputs (a command, a JSON
        verdict) don't need a 1000+ token runway, and capping it bounds
        worst-case latency.

        think=False disables the reasoning trace on models that support one
        (e.g. Qwen3-family "thinking" models). Without this, a low max_tokens
        can be entirely consumed by internal reasoning before the model ever
        emits its actual answer, silently producing an empty response
        (Ollama reports this as done_reason="length" with the real content
        sitting in a separate, unused "thinking" field). Ollama ignores this
        flag harmlessly for models that don't support it. Verified directly
        against the Ollama API and reproduced inside the kali container with
        qwen3.5:9b as executor — not an artifact of the test environment.
        """
        options: dict = {"temperature": temperature}
        if max_tokens is not None:
            options["num_predict"] = max_tokens
        payload: dict = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }
        if system:
            payload["system"] = system
        if think is not None:
            payload["think"] = think

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
        except (socket.timeout, TimeoutError) as exc:
            raise LLMUnavailable(
                f"Request to {model} at {self.host} exceeded the "
                f"{self.timeout_s}s timeout. On VRAM-constrained hosts this "
                f"usually means Ollama was still cold-loading the model after "
                f"evicting a different one — raise "
                f"ModelConfig.request_timeout_s, or pre-warm the model with "
                f"`ollama run {model} \"\"` before starting the run."
            ) from exc

    def health(self) -> bool:
        """Return True if the local daemon answers."""
        try:
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except urllib.error.URLError:
            return False

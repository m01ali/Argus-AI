"""
Argus-AI configuration.

Central place for deployment knobs: which Ollama models back each stage,
where the sandbox lives, scope authorisation, and report output.

Argus-AI is privacy-first by construction: every model call targets a LOCAL
Ollama endpoint. No engagement data leaves the host. This mirrors PLPF
Outcome A (ShellGPT + LLaMA3:8B) for execution and Outcome B (Gemma3:12B
advisory) for remediation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ModelConfig:
    """Per-stage local model assignment (all served by Ollama)."""

    # Discovery + validation: stateless shell-native execution (PLPF Outcome A).
    executor_model: str = "llama3:8b"
    # Patch proposal: conversational advisory model (PLPF Outcome B).
    advisor_model: str = "gemma3:12b"
    # Local Ollama endpoint. Never a cloud URL — this is the privacy guarantee.
    ollama_host: str = "http://localhost:11434"
    # Sampling. temperature=0 for executor keeps command generation deterministic;
    # the thesis temperature-ablation work will sweep this.
    executor_temperature: float = 0.0
    advisor_temperature: float = 0.3
    request_timeout_s: int = 120


@dataclass
class SandboxConfig:
    """Validation sandbox boundary."""

    # Working directory for exploit-verification artefacts.
    workdir: Path = field(default_factory=lambda: Path("/tmp/argus-sandbox"))
    # Hard ceiling on any single validation command (seconds).
    command_timeout_s: int = 90
    # If True, validation commands run; if False, they are only logged (dry-run).
    enabled: bool = True


@dataclass
class ScopeConfig:
    """
    Authorisation gate. Argus-AI refuses to act on any host not explicitly
    listed here. This is the responsible-use boundary: no scanning,
    validating, or patching against unlisted targets.
    """

    authorized_targets: list[str] = field(default_factory=list)
    # The operator must set this True to confirm they have written authorisation
    # to test every host in authorized_targets.
    authorization_confirmed: bool = False

    def is_in_scope(self, target: str) -> bool:
        return target in self.authorized_targets

    def assert_authorized(self) -> None:
        if not self.authorization_confirmed:
            raise PermissionError(
                "Scope authorisation not confirmed. Set "
                "ScopeConfig.authorization_confirmed = True only if you hold "
                "written authorisation to test every host in authorized_targets."
            )
        if not self.authorized_targets:
            raise PermissionError("No authorized targets defined; refusing to run.")


@dataclass
class ReportConfig:
    output_dir: Path = field(default_factory=lambda: Path("./argus-reports"))
    # Human-in-the-loop gate before any patch is applied.
    require_patch_authorization: bool = True


@dataclass
class ArgusConfig:
    models: ModelConfig = field(default_factory=ModelConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    # Maximum discovery→validation→patch→rescan iterations before stopping.
    max_loop_iterations: int = 3

    @classmethod
    def from_env(cls) -> "ArgusConfig":
        """Build config from environment variables (handy for CI / scripted runs)."""
        cfg = cls()
        if host := os.getenv("ARGUS_OLLAMA_HOST"):
            cfg.models.ollama_host = host
        if exe := os.getenv("ARGUS_EXECUTOR_MODEL"):
            cfg.models.executor_model = exe
        if adv := os.getenv("ARGUS_ADVISOR_MODEL"):
            cfg.models.advisor_model = adv
        if targets := os.getenv("ARGUS_TARGETS"):
            cfg.scope.authorized_targets = [t.strip() for t in targets.split(",") if t.strip()]
        if os.getenv("ARGUS_AUTHORIZED") == "1":
            cfg.scope.authorization_confirmed = True
        return cfg

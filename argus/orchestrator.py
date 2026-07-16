"""
Argus-AI orchestrator.

Composes the four stages into the closed loop:

    Discovery → Validation → Patch Proposal → [human authorises] → apply → Re-scan
        ↑                                                                      │
        └──────────────────────────────────────────────────────────────────────┘

The loop repeats until no confirmed finding remains, or max_loop_iterations is
reached. Patch application is gated on an explicit human-in-the-loop callback —
Argus-AI never applies a change autonomously.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from .config import ArgusConfig
from .llm import OllamaClient
from .models import Finding, LoopResult, ValidationVerdict, PatchStatus
from .stages import (
    DiscoveryStage, ValidationStage, PatchProposalStage, RescanStage,
)

log = logging.getLogger("argus.orchestrator")

# A patch-authorisation callback receives a Finding and returns True to apply.
PatchAuthorizer = Callable[[Finding], bool]


def deny_all(_: Finding) -> bool:
    """Default authoriser: applies nothing. Safe by default."""
    return False


class Argus:
    def __init__(self, cfg: ArgusConfig, *, authorizer: PatchAuthorizer = deny_all,
                 patch_applier: Callable[[Finding], bool] | None = None) -> None:
        self.cfg = cfg
        self.llm = OllamaClient(cfg.models.ollama_host, cfg.models.request_timeout_s)
        self.authorizer = authorizer
        # patch_applier actually performs the change on the target; if None, the
        # framework records authorisation but does not mutate anything.
        self.patch_applier = patch_applier

        self.discovery = DiscoveryStage(cfg, self.llm)
        self.validation = ValidationStage(cfg, self.llm)
        self.patcher = PatchProposalStage(cfg, self.llm)
        self.rescan = RescanStage(cfg, self.llm, self.discovery, self.validation)

    def preflight(self) -> None:
        """Fail fast on misconfiguration before any scanning happens."""
        self.cfg.scope.assert_authorized()
        if not self.llm.health():
            log.warning("Local Ollama backend not reachable at %s — "
                        "stages will raise LLMUnavailable when called.",
                        self.cfg.models.ollama_host)

    def run_once(self, target: str, iteration: int) -> LoopResult:
        log.info("=== Iteration %d on %s ===", iteration, target)

        # (1) Discovery
        findings = self.discovery.run(target)
        log.info("Discovery produced %d candidate findings", len(findings))

        # (2) Validation
        findings = self.validation.run(findings)
        confirmed = [f for f in findings if f.verdict == ValidationVerdict.CONFIRMED]
        log.info("Validation confirmed %d/%d findings", len(confirmed), len(findings))

        # (3) Patch Proposal (confirmed only)
        findings = self.patcher.run(findings)

        # Human-in-the-loop patch authorisation + application
        patched = 0
        for f in confirmed:
            if f.patch_status != PatchStatus.PROPOSED:
                continue
            if self.cfg.report.require_patch_authorization and not self.authorizer(f):
                f.patch_status = PatchStatus.REJECTED
                continue
            applied = self.patch_applier(f) if self.patch_applier else True
            f.patch_status = PatchStatus.APPLIED if applied else PatchStatus.REJECTED
            if applied:
                patched += 1

        # (4) Re-scan — only worthwhile if something was applied
        resolved = 0
        if patched:
            findings = self.rescan.run(target, findings)
            resolved = sum(1 for f in findings if f.resolved_after_patch)

        result = LoopResult(
            iteration=iteration, findings=findings,
            confirmed_count=len(confirmed), patched_count=patched,
            resolved_count=resolved,
        )
        log.info(result.summary())
        return result

    def run(self, target: str) -> list[LoopResult]:
        """Run the closed loop until clean or until max iterations."""
        self.preflight()
        results: list[LoopResult] = []
        for i in range(1, self.cfg.max_loop_iterations + 1):
            res = self.run_once(target, i)
            results.append(res)
            outstanding = [
                f for f in res.findings
                if f.verdict == ValidationVerdict.CONFIRMED
                and not f.resolved_after_patch
            ]
            if not outstanding:
                log.info("No outstanding confirmed findings — loop closed.")
                break
        return results

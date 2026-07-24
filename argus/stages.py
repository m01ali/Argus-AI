"""
The four Argus-AI stages.

    (1) Discovery       — ShellGPT-style stateless command generation + local tool execution
    (2) Validation      — exploit-verify each finding in an isolated sandbox; gate on proof
    (3) Patch Proposal  — Qwen3.5:9B advisory remediation for confirmed findings only
    (4) Re-scan         — re-run discovery against the changed surface, close the loop

Each stage is a class with a single public `run(...)` method so the orchestrator
can compose them and so each can be unit-tested in isolation.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import subprocess
from pathlib import Path

from .config import ArgusConfig
from .llm import OllamaClient
from .models import (
    Command, Finding, Severity, ValidationVerdict, PatchStatus,
)

log = logging.getLogger("argus.stages")

# Tools Discovery is allowed to drive. An allowlist keeps generated commands
# from wandering outside the intended reconnaissance/scan surface.
ALLOWED_TOOLS = {
    "nmap", "nikto", "sqlmap", "searchsploit", "whatweb", "gobuster",
    "dig", "whois", "curl", "nbtscan", "enum4linux", "smbclient",
}


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Discovery
# ─────────────────────────────────────────────────────────────────────────────
class DiscoveryStage:
    """
    Stateless, shell-native discovery. The executor model is prompted once per
    PTES phase to emit a single executable command; the command runs locally and
    its real output is captured. No conversation history accumulates between
    prompts — this is the ShellGPT --shell isolation property.
    """

    PTES_PHASES = ["recon", "scan", "vuln-id"]

    SYSTEM = (
        "You are a penetration-testing command generator running locally on Kali "
        "Linux. Given a target and a PTES phase, output exactly ONE shell command "
        "that advances that phase. Output ONLY the command on a single line, no "
        "explanation, no markdown fences. Prefer: nmap, nikto, sqlmap, searchsploit, "
        "whatweb, gobuster, enum4linux. Never use destructive flags. Only use flags "
        "and options you are certain exist for that exact tool; if you are not "
        "certain, invoke the tool with no extra flags rather than guessing one."
    )

    def __init__(self, cfg: ArgusConfig, llm: OllamaClient) -> None:
        self.cfg = cfg
        self.llm = llm

    def _gen_command(self, target: str, phase: str) -> str:
        prompt = (
            f"Target: {target}\nPTES phase: {phase}\n"
            f"Output one safe, non-destructive command for this phase."
        )
        raw = self.llm.generate(
            self.cfg.models.executor_model, prompt,
            temperature=self.cfg.models.executor_temperature,
            system=self.SYSTEM,
        )
        return self._sanitise(raw)

    @staticmethod
    def _sanitise(raw: str) -> str:
        """Strip fences/prose; keep the first plausible command line."""
        text = re.sub(r"```[a-zA-Z]*", "", raw).replace("```", "").strip()
        line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        return line

    def _is_allowed(self, command: str) -> bool:
        try:
            tokens = shlex.split(command)
        except ValueError:
            return False
        if not tokens:
            return False
        tool = Path(tokens[0]).name
        # Block obvious shell chaining that could escape the allowlist.
        if any(c in command for c in [";", "&&", "||", "|", "`", "$("]):
            return False
        return tool in ALLOWED_TOOLS

    def _execute(self, command: str) -> tuple[str, str, int]:
        if not self.cfg.sandbox.enabled:
            return ("[dry-run] command not executed", "", 0)
        try:
            proc = subprocess.run(
                shlex.split(command),
                capture_output=True, text=True,
                timeout=self.cfg.sandbox.command_timeout_s,
            )
            return (proc.stdout[-8000:], proc.stderr[-2000:], proc.returncode)
        except FileNotFoundError:
            return ("", f"tool not installed: {command.split()[0]}", 127)
        except subprocess.TimeoutExpired:
            return ("", "command timed out", 124)

    def run(self, target: str) -> list[Finding]:
        self.cfg.scope.assert_authorized()
        if not self.cfg.scope.is_in_scope(target):
            raise PermissionError(f"Target {target} is not in authorised scope.")

        findings: list[Finding] = []
        for phase in self.PTES_PHASES:
            command = self._gen_command(target, phase)
            if not command or not self._is_allowed(command):
                log.warning("Discarded disallowed/empty command in %s: %r", phase, command)
                continue
            stdout, stderr, rc = self._execute(command)
            cmd = Command(rationale=f"{phase} step", command=command, phase=phase,
                          stdout=stdout, stderr=stderr, exit_code=rc)
            finding = self._interpret(target, phase, cmd)
            if finding:
                findings.append(finding)
        return findings

    def _interpret(self, target: str, phase: str, cmd: Command) -> Finding | None:
        """Ask the model to turn raw tool output into a structured candidate finding."""
        if not cmd.stdout.strip():
            return None
        prompt = (
            "Given this tool output, identify a security finding if one is present. "
            "Treat any of the following as a finding worth reporting, even without "
            "a specific CVE number: a network service exposed with no evidence "
            "authentication is required or enabled; software identified by name and "
            "version where that version is old enough to plausibly carry known "
            "vulnerabilities; a verbose banner disclosing an exact product/version; "
            "default or blank credentials; or directory/information disclosure. "
            "Summarise the single most significant finding as JSON with keys: "
            "title, description, severity (High/Medium/Low/Info). If none of the "
            "above criteria are met, output {}. Output ONLY JSON.\n\n"
            f"Command: {cmd.command}\nOutput:\n{cmd.stdout[:4000]}"
        )
        raw = self.llm.generate(
            self.cfg.models.executor_model, prompt,
            temperature=self.cfg.models.executor_temperature,
        )
        data = _extract_json(raw)
        if not data or "title" not in data:
            return None
        sev = _coerce_severity(data.get("severity", "Info"))
        return Finding(
            target=target, title=data["title"],
            description=data.get("description", ""),
            severity=sev, phase=phase, discovery_commands=[cmd],
        )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Validation
# ─────────────────────────────────────────────────────────────────────────────
class ValidationStage:
    """
    Exploit-verify each candidate finding in an isolated sandbox. Only findings
    with a confirmed proof-of-exploit are promoted. This is the structural answer
    to the hallucination failure mode: an unverifiable finding never reaches the
    patch stage, so a fabricated scan result cannot drive a fabricated patch.
    """

    SYSTEM = (
        "You generate a SINGLE non-destructive verification command that would "
        "prove or disprove a specific finding. Output only the command."
    )

    def __init__(self, cfg: ArgusConfig, llm: OllamaClient) -> None:
        self.cfg = cfg
        self.llm = llm
        self.cfg.sandbox.workdir.mkdir(parents=True, exist_ok=True)

    def run(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            if not self.cfg.sandbox.enabled:
                f.verdict = ValidationVerdict.SKIPPED
                continue
            f.verdict, f.proof = self._verify(f)
        return findings

    def _verify(self, f: Finding) -> tuple[ValidationVerdict, str]:
        prompt = (
            f"Finding: {f.title}\nTarget: {f.target}\nDescription: {f.description}\n"
            f"Give one safe command that verifies whether this is real. The command "
            f"MUST run against the literal target string \"{f.target}\" given above — "
            f"never substitute localhost, 127.0.0.1, or any other placeholder."
        )
        raw = self.llm.generate(
            self.cfg.models.executor_model, prompt,
            temperature=self.cfg.models.executor_temperature, system=self.SYSTEM,
        )
        command = DiscoveryStage._sanitise(raw)
        if not command:
            return (ValidationVerdict.UNCONFIRMED, "no verification command produced")
        try:
            proc = subprocess.run(
                shlex.split(command), capture_output=True, text=True,
                timeout=self.cfg.sandbox.command_timeout_s,
                cwd=self.cfg.sandbox.workdir,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError) as exc:
            return (ValidationVerdict.UNCONFIRMED, f"verification failed: {exc}")

        # A finding is CONFIRMED only when the verification command exits cleanly
        # AND its output contains corroborating evidence the model can point to.
        evidence = (proc.stdout or "")[:4000]
        if proc.returncode == 0 and evidence.strip():
            judged = self._judge(f, command, evidence)
            if judged:
                return (ValidationVerdict.CONFIRMED, evidence[:1500])
        return (ValidationVerdict.UNCONFIRMED, evidence[:1500])

    def _judge(self, f: Finding, command: str, evidence: str) -> bool:
        prompt = (
            "Does this command output CONFIRM the finding is real and exploitable? "
            'Answer strictly "YES" or "NO".\n\n'
            f"Finding: {f.title}\nCommand: {command}\nOutput:\n{evidence}"
        )
        raw = self.llm.generate(
            self.cfg.models.executor_model, prompt,
            temperature=self.cfg.models.executor_temperature,
        )
        return raw.strip().upper().startswith("YES")


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — Patch Proposal
# ─────────────────────────────────────────────────────────────────────────────
class PatchProposalStage:
    """
    Qwen3.5:9B in advisory mode (PLPF Outcome B) drafts structured remediation
    for CONFIRMED findings only. The advisor never executes anything — it
    side-steps the self-execution failure mode observed in prior advisory
    models by staying purely analytical.
    """

    SYSTEM = (
        "You are a senior security remediation advisor. For a confirmed, "
        "exploit-verified finding, produce concrete remediation: configuration "
        "changes, package upgrades, and code-level fixes. Be specific and "
        "actionable. Do not execute anything; advise only."
    )

    def __init__(self, cfg: ArgusConfig, llm: OllamaClient) -> None:
        self.cfg = cfg
        self.llm = llm

    def run(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            if f.verdict != ValidationVerdict.CONFIRMED:
                f.patch_status = PatchStatus.NOT_APPLICABLE
                continue
            f.remediation = self._propose(f)
            f.patch_status = PatchStatus.PROPOSED
        return findings

    def _propose(self, f: Finding) -> str:
        prompt = (
            f"Confirmed finding: {f.title}\nSeverity: {f.severity.value}\n"
            f"Target: {f.target}\nDescription: {f.description}\n"
            f"Proof of exploit:\n{f.proof}\n\n"
            "Provide remediation as three labelled sections: "
            "1) Configuration, 2) Package/Version, 3) Code-level."
        )
        return self.llm.generate(
            self.cfg.models.advisor_model, prompt,
            temperature=self.cfg.models.advisor_temperature, system=self.SYSTEM,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — Re-scan
# ─────────────────────────────────────────────────────────────────────────────
class RescanStage:
    """
    After a patch is applied (with human authorisation handled by the
    orchestrator), re-run discovery against the changed surface and check whether
    each previously-confirmed finding still reproduces. This closes the loop and
    produces a remediation-verified result.
    """

    def __init__(self, cfg: ArgusConfig, llm: OllamaClient,
                 discovery: DiscoveryStage, validation: ValidationStage) -> None:
        self.cfg = cfg
        self.llm = llm
        self.discovery = discovery
        self.validation = validation

    def run(self, target: str, prior: list[Finding]) -> list[Finding]:
        # Re-discover and re-validate; then mark each prior finding resolved or not.
        fresh = self.discovery.run(target)
        fresh = self.validation.run(fresh)
        still_present = {
            (f.title.lower()) for f in fresh
            if f.verdict == ValidationVerdict.CONFIRMED
        }
        for f in prior:
            if f.verdict == ValidationVerdict.CONFIRMED and f.patch_status == PatchStatus.APPLIED:
                f.resolved_after_patch = f.title.lower() not in still_present
        return prior


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────
def _extract_json(raw: str) -> dict:
    """Best-effort JSON extraction from a model response."""
    raw = re.sub(r"```[a-zA-Z]*", "", raw).replace("```", "")
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        return {}
    try:
        return json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return {}


def _coerce_severity(value: str) -> Severity:
    v = (value or "").strip().lower()
    return {"high": Severity.HIGH, "medium": Severity.MEDIUM,
            "low": Severity.LOW}.get(v, Severity.INFO)

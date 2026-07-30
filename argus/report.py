"""
Remediation-verified report generation.

Emits both a machine-readable JSON record and a human-readable Markdown report
documenting the full loop: what was found, what was confirmed by proof-of-exploit,
what remediation was proposed, and what was verified resolved on re-scan.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .models import LoopResult, ValidationVerdict, PatchStatus


def _safe_slug(value: str) -> str:
    """Filesystem-safe slug for a target name or model tag."""
    return value.replace(":", "_").replace("/", "_").replace(".", "-")


def write_reports(results: list[LoopResult], target: str, out_dir: Path,
                   executor_model: str, advisor_model: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe_target = _safe_slug(target)
    safe_exec = _safe_slug(executor_model)
    safe_adv = _safe_slug(advisor_model)
    model_tag = safe_exec if safe_exec == safe_adv else f"{safe_exec}_{safe_adv}"
    base = str(out_dir / f"argus-{safe_target}-{model_tag}-{stamp}")

    json_path = Path(base + ".json")
    md_path = Path(base + ".md")

    json_path.write_text(json.dumps(
        {"target": target,
         "executor_model": executor_model,
         "advisor_model": advisor_model,
         "iterations": [
             {"iteration": r.iteration,
              "confirmed": r.confirmed_count,
              "patched": r.patched_count,
              "resolved": r.resolved_count,
              "findings": [f.to_dict() for f in r.findings]}
             for r in results]},
        indent=2,
    ))

    md_path.write_text(_render_markdown(results, target, executor_model, advisor_model))
    return md_path, json_path


def _render_markdown(results: list[LoopResult], target: str,
                      executor_model: str, advisor_model: str) -> str:
    lines: list[str] = []
    lines.append(f"# Argus-AI Remediation-Verified Report")
    lines.append("")
    lines.append(f"**Target:** `{target}`  ")
    if executor_model == advisor_model:
        lines.append(f"**Model:** `{executor_model}` (executor + advisor)  ")
    else:
        lines.append(f"**Executor model:** `{executor_model}` | "
                     f"**Advisor model:** `{advisor_model}`  ")
    lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Iterations:** {len(results)}")
    lines.append("")
    lines.append("> Argus-AI is privacy-first: every model call ran on a local "
                 "Ollama backend. No engagement data left the host.")
    lines.append("")

    # Executive summary
    total_conf = sum(r.confirmed_count for r in results)
    total_patched = sum(r.patched_count for r in results)
    total_resolved = sum(r.resolved_count for r in results)
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Confirmed (proof-of-exploit) findings: **{total_conf}**")
    lines.append(f"- Patches applied (human-authorised): **{total_patched}**")
    lines.append(f"- Verified resolved on re-scan: **{total_resolved}**")
    lines.append("")

    for r in results:
        lines.append(f"## Iteration {r.iteration}")
        lines.append("")
        if not r.findings:
            lines.append("_No findings._")
            lines.append("")
            continue
        for f in r.findings:
            badge = {
                ValidationVerdict.CONFIRMED: "✅ CONFIRMED",
                ValidationVerdict.UNCONFIRMED: "❔ UNCONFIRMED (treated as possible hallucination)",
                ValidationVerdict.SKIPPED: "⏭ SKIPPED",
            }[f.verdict]
            lines.append(f"### {f.finding_id} — {f.title}  ")
            lines.append(f"**Severity:** {f.severity.value} | **Phase:** {f.phase} | "
                         f"**Validation:** {badge}")
            lines.append("")
            if f.description:
                lines.append(f.description)
                lines.append("")
            if f.discovery_commands:
                lines.append("**Discovery:**")
                for cmd in f.discovery_commands:
                    lines.append(f"- Command (`{cmd.phase}` phase): `{cmd.command}`")
                    if cmd.stdout.strip():
                        lines.append("  ```")
                        for ln in cmd.stdout[:2000].splitlines():
                            lines.append(f"  {ln}")
                        lines.append("  ```")
                lines.append("")
            if f.verdict != ValidationVerdict.SKIPPED:
                lines.append("**Verification:**")
                lines.append(f"- Command: `{f.verification_command or '(none)'}`")
                if f.proof.strip():
                    lines.append("  ```")
                    for ln in f.proof[:1500].splitlines():
                        lines.append(f"  {ln}")
                    lines.append("  ```")
                lines.append("")
            if f.analysis:
                lines.append("**Detailed analysis:**")
                lines.append("")
                lines.append(f.analysis)
                lines.append("")
            if f.patch_status == PatchStatus.APPLIED:
                lines.append(f"**Patch:** applied (authorised). "
                             f"**Resolved on re-scan:** "
                             f"{'yes' if f.resolved_after_patch else 'NOT yet'}")
            elif f.patch_status == PatchStatus.PROPOSED:
                lines.append("**Patch:** proposed, awaiting authorisation.")
            elif f.patch_status == PatchStatus.REJECTED:
                lines.append("**Patch:** proposed but not authorised.")
            if f.remediation:
                lines.append("")
                lines.append("**Proposed remediation:**")
                lines.append("")
                lines.append(f.remediation)
            lines.append("")
    lines.append("---")
    lines.append("_Generated by Argus-AI — privacy-first continuous assessment agent._")
    return "\n".join(lines)

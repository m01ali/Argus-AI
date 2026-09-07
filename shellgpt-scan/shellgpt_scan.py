#!/usr/bin/env python3
"""
shellgpt_scan.py — one-command, ShellGPT(+Ollama/llama)-driven vuln scanner.

This is the ShellGPT sibling of ../llama-scan/llama_scan.py. The difference is
WHO the analyst is: here every finding and every remediation is written by
`sgpt` (ShellGPT) talking to the LOCAL Ollama llama model — not by a direct
Ollama HTTP call. sgpt is the only brain; the scans just gather evidence.

Because the scanning tools (sqlmap, nc, smbclient, nmap with full internal-net
access) live inside the Kali containers for dvwa/metasploitable, while `sgpt`
is installed on the Windows host, the work is split into two phases:

    --phase scan      Run the fixed recon / proof-of-concept scans for a lab
                      and write the RAW tool output to
                      shellgpt-results/<lab>/NN-<name>.txt .
                      Runs where the tools are: inside the kali container
                      (dvwa/metasploitable) or natively on the host (htb).

    --phase analyze   For every raw .txt, pipe it to `sgpt` (host-side) with a
                      dedicated, evidence-constrained analyst role, writing the
                      findings + remediation to shellgpt-results/<lab>/NN-<name>.md,
                      then an executive shellgpt-results/<lab>/00-SUMMARY.md .
                      Always runs on the host — that is where sgpt + its Ollama
                      config live.

    --phase agentic   sgpt drives EVERYTHING itself: choose a command -> run it
                      -> observe -> repeat -> write the findings report. Same
                      read-only recon allowlist / no-shell safety box as
                      llama_scan.run_agentic. The loop runs on the host; each
                      command executes where the tools are (in the kali
                      container via `--exec docker`, or natively for htb).
                      Output: shellgpt-results/<lab>/agentic/transcript.txt +
                      00-REPORT.md . This is the "LLM does it all" config.

The scan PROFILES are imported verbatim from ../llama-scan/llama_scan.py so the
two engines can never drift apart. This file is stdlib-only.

Normally driven by ../run-shellgpt-scans.ps1 (the single command), but each
phase can be run directly, e.g.:

    # inside the kali container (dvwa):
    python3 shellgpt-scan/shellgpt_scan.py --lab dvwa --phase scan
    # on the host:
    python  shellgpt-scan/shellgpt_scan.py --lab dvwa --phase analyze
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys

# --------------------------------------------------------------------------
# Reuse the scan profiles from the sibling llama engine so the two can't drift.
# The dir has a hyphen (not import-safe as a package), so add it to sys.path
# and import the module by its underscore filename.
# --------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "llama-scan"))

from llama_scan import (  # noqa: E402
    PROFILES, run_step, strip_ansi, _clip,
    AGENTIC_ALLOWED, AGENTIC_SYSTEM, AGENTIC_REPORT_SYSTEM, agentic_reject_reason,
)


# --------------------------------------------------------------------------
# ShellGPT (sgpt) analyst roles. These fully REPLACE sgpt's default
# "programming assistant" persona (which is chatty and, left to its own
# devices, invents CVEs). Written to sgpt's ROLE_STORAGE_PATH on the host so
# `sgpt --role argus-analyst` / `--role argus-summary` pick them up.
# --------------------------------------------------------------------------

ANALYST_ROLE = (
    "You are argus-analyst, a senior penetration tester writing up ONE scan "
    "from an authorised lab assessment. Input (on stdin) is the raw output of a "
    "single security tool. Produce a concise Markdown report with these "
    "sections, in order:\n"
    "1. `## Open Ports / Services` — a Markdown table (Port | Service | Version "
    "| Notes) ONLY when the output contains port/service data; otherwise omit "
    "this section entirely.\n"
    "2. `## Vulnerabilities & Weaknesses` — one `### Finding N: <title>` per "
    "issue, each with **Severity** (Critical/High/Medium/Low/Info), a "
    "**CVE**/identifier ONLY when one clearly and correctly applies, **What it "
    "is**, and **Why it matters**.\n"
    "3. `## Remediation` — concrete, actionable fixes with exact commands or "
    "config snippets in fenced code blocks where useful.\n\n"
    "Hard rules: base EVERY finding only on the provided scan output — never "
    "invent services, ports, versions, or CVEs that are not evidenced there. If "
    "you are not certain a CVE number is correct, describe the weakness by name "
    "instead of guessing an identifier. If the output shows an error or nothing "
    "exploitable, say so plainly. Be specific and technical; no filler, no "
    "preamble, and do NOT wrap the whole answer in a code fence."
)

SUMMARY_ROLE = (
    "You are argus-summary, a senior penetration tester writing the executive "
    "summary of an authorised lab assessment. Input (on stdin) is the set of "
    "per-scan analyses for a single target. Produce Markdown with:\n"
    "1. `## Executive Summary` — 3-5 sentences on overall security posture.\n"
    "2. `## Severity-Ranked Findings` — a Markdown table (Severity | Finding | "
    "Port/Service | Impact) ordered most-severe first, consolidating and "
    "de-duplicating findings across all scans.\n"
    "3. `## Top Remediation Priorities` — a numbered list of the highest-value "
    "fixes.\n\n"
    "Base everything ONLY on the analyses provided; do not invent new findings. "
    "Be concise and concrete, no preamble, and do NOT wrap the answer in a code "
    "fence."
)

# The agentic roles reuse llama_scan's system prompts VERBATIM so the ShellGPT
# agent makes the same decisions (same allowlist, same rules) as the llama agent
# — the results are then directly comparable; only the analyst backend differs.
ROLES = {
    "argus-analyst": ANALYST_ROLE,
    "argus-summary": SUMMARY_ROLE,
    "argus-agent": AGENTIC_SYSTEM,
    "argus-agent-report": AGENTIC_REPORT_SYSTEM,
}

_PREAMBLE = re.compile(
    r"^\s*(here is|here's|below is|sure[,!]?|certainly[,!]?)\b[^\n]*:?\s*\n+",
    re.IGNORECASE,
)


def _strip_preamble(text: str) -> str:
    return _PREAMBLE.sub("", text, count=1).lstrip()


# --------------------------------------------------------------------------
# ShellGPT plumbing (analyze phase — host only).
# --------------------------------------------------------------------------

def _sgptrc_path() -> str:
    return os.path.expanduser(os.path.join("~", ".config", "shell_gpt", ".sgptrc"))


def _sgptrc_value(key: str, default: str) -> str:
    """Read a single KEY=VALUE from the sgpt config, if present."""
    path = _sgptrc_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return default


def resolve_sgpt() -> str:
    """Locate the sgpt executable (host). PATH first, then known fallbacks."""
    found = shutil.which("sgpt")
    if found:
        return found
    candidates = [
        os.path.expandvars(
            r"%LOCALAPPDATA%\Programs\Python\Python310\Scripts\sgpt.exe"),
        os.path.expanduser(
            r"~\AppData\Local\Programs\Python\Python310\Scripts\sgpt.exe"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return "sgpt"  # last resort; will raise a clear error if truly missing


def ensure_roles() -> None:
    """Write/refresh the argus sgpt roles so --role picks them up."""
    role_dir = _sgptrc_value(
        "ROLE_STORAGE_PATH",
        os.path.expanduser(os.path.join("~", ".config", "shell_gpt", "roles")),
    )
    os.makedirs(role_dir, exist_ok=True)
    for name, text in ROLES.items():
        with open(os.path.join(role_dir, f"{name}.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": name, "role": text}, fh)


def _ollama_host() -> str:
    """Where sgpt's Ollama lives (host side), from .sgptrc API_BASE_URL."""
    base = _sgptrc_value("API_BASE_URL", "http://localhost:11434").rstrip("/")
    return base


def _model_tag(model: str | None) -> str:
    """The bare Ollama tag (drop the litellm 'ollama/' prefix sgpt uses)."""
    tag = model or _sgptrc_value("DEFAULT_MODEL", "ollama/llama3:8b")
    return tag.split("/", 1)[1] if tag.startswith("ollama/") else tag


def prewarm(model: str | None) -> None:
    """Load the model into Ollama and pin it resident before the real calls.

    The timeouts we saw were cold-load / model-swap stalls (a 745-byte nmap
    analysis should never take 10 minutes), not big prompts. Loading the model
    once with a long keep_alive means the first real sgpt call hits a warm model
    instead of paying a multi-minute load. Best-effort: never fatal."""
    import urllib.request
    import urllib.error
    host, tag = _ollama_host(), _model_tag(model)
    print(f"[*] pre-warming {tag} at {host} (keep_alive 30m) ...", flush=True)
    payload = json.dumps({
        "model": tag, "prompt": "ok", "stream": False,
        "keep_alive": "30m", "options": {"num_predict": 1},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{host}/api/generate", data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300):
            print("    [+] model warm.", flush=True)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"    [!] pre-warm skipped ({exc}); continuing anyway.", flush=True)


def _md_body(path: str) -> str | None:
    """Return the analysis body of an existing report .md (header stripped), or
    None if the file is missing or was a failed 'unavailable' stub."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        return None
    if "unavailable" in content.lower():
        return None
    # header is "# title\n\n*meta*\n\n<body>"; drop the first two blocks.
    parts = content.split("\n\n", 2)
    return parts[2].strip() if len(parts) >= 3 else content.strip()


class SgptError(RuntimeError):
    pass


def run_sgpt(role: str, stdin_text: str, prompt: str, model: str | None,
             sgpt: str, *, extra_args: tuple[str, ...] = (),
             timeout_s: int = 600) -> str:
    """Call `sgpt --role <role> [--model m] <prompt>` with stdin_text piped in.

    `--no-functions` is always set so sgpt only ever RETURNS text (a report, or
    a proposed command) and never executes anything itself — every command it
    proposes is run by us, through the allowlist safety box.
    """
    cmd = [sgpt, "--no-functions", "--role", role]
    if model:
        cmd += ["--model", model]
    cmd += list(extra_args)
    cmd.append(prompt)
    try:
        proc = subprocess.run(
            cmd, input=stdin_text, capture_output=True, text=True,
            timeout=timeout_s,
        )
    except FileNotFoundError as exc:
        raise SgptError(
            f"could not run sgpt ({sgpt!r}): {exc}. Is ShellGPT installed and on "
            f"PATH? (`pip install \"shell-gpt[litellm]\"`)"
        ) from exc
    except subprocess.TimeoutExpired:
        raise SgptError(f"sgpt timed out after {timeout_s}s.")

    out = (proc.stdout or "").strip()
    # ShellGPT 1.5.1 can emit a prompt_toolkit traceback AFTER printing the real
    # answer on some non-console stdouts; keep the answer, drop the traceback.
    tb = out.find("Traceback (most recent call last)")
    if tb != -1:
        out = out[:tb].strip()
    if not out:
        err = (proc.stderr or "").strip()
        raise SgptError(
            f"sgpt returned no output (exit {proc.returncode}). stderr:\n{err[:800]}"
        )
    return _strip_preamble(out)


# --------------------------------------------------------------------------
# Phase 1 — scan (runs where the tools live: kali container / native host).
# --------------------------------------------------------------------------

def phase_scan(lab: str, target: str, outdir: str) -> int:
    steps = PROFILES[lab][1](target)
    os.makedirs(outdir, exist_ok=True)
    scans: list[dict] = []
    idx = 0
    for step in steps:
        analyze = step.get("analyze", True)
        title = step.get("title", step["name"])
        if analyze:
            idx += 1
        tag = f"{idx:02d}-{step['name']}" if analyze else f"prep-{step['name']}"
        print(f"[*] scan {tag}: {title} ...", flush=True)
        raw = run_step(step)
        if not analyze:
            # prep/side-effect step (e.g. DVWA auth bootstrap) — run, don't emit.
            last = raw.splitlines()[-1] if raw else ""
            print(f"    (prep step) {last}", flush=True)
            continue
        raw_path = os.path.join(outdir, f"{tag}.txt")
        with open(raw_path, "w", encoding="utf-8") as fh:
            fh.write(raw + "\n")
        scans.append({"tag": tag, "name": step["name"], "title": title})
        print(f"    -> {raw_path}", flush=True)

    manifest = {
        "lab": lab,
        "target": target,
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "scans": scans,
    }
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"[+] scan phase done — {len(scans)} raw scans in {outdir}/", flush=True)
    return 0


# --------------------------------------------------------------------------
# Phase 2 — analyze (host only: sgpt is the analyst).
# --------------------------------------------------------------------------

def _load_manifest(outdir: str) -> dict:
    mpath = os.path.join(outdir, "manifest.json")
    if os.path.exists(mpath):
        with open(mpath, "r", encoding="utf-8") as fh:
            return json.load(fh)
    # Fallback: reconstruct from the .txt files on disk.
    scans = []
    for fn in sorted(f for f in os.listdir(outdir) if re.match(r"\d\d-.*\.txt$", f)):
        name = fn[3:-4]
        scans.append({"tag": fn[:-4], "name": name, "title": name})
    return {"lab": os.path.basename(outdir.rstrip("/\\")), "target": "?", "scans": scans}


def phase_analyze(lab: str, outdir: str, model: str | None,
                  only_missing: bool = False) -> int:
    if not os.path.isdir(outdir):
        print(f"[!] no scan output at {outdir}. Run --phase scan first.",
              file=sys.stderr)
        return 4
    sgpt = resolve_sgpt()
    ensure_roles()
    man = _load_manifest(outdir)
    target = man.get("target", "?")
    scans = man.get("scans", [])
    if not scans:
        print(f"[!] no raw scans found in {outdir}.", file=sys.stderr)
        return 4

    print(f"[*] analyze: lab={lab} target={target} via sgpt "
          f"(model={model or 'sgpt default (ollama/llama3:8b)'})"
          f"{' [only-missing]' if only_missing else ''}", flush=True)
    prewarm(model)

    analyses: list[tuple[str, str]] = []
    for s in scans:
        tag, title = s["tag"], s["title"]
        raw_path = os.path.join(outdir, f"{tag}.txt")
        md_path = os.path.join(outdir, f"{tag}.md")
        if not os.path.exists(raw_path):
            print(f"    [skip] {tag}: raw output missing", flush=True)
            continue
        # --only-missing: keep good reports, reuse them for the summary.
        if only_missing:
            body = _md_body(md_path)
            if body is not None:
                print(f"    [keep] {tag}: existing report is good", flush=True)
                analyses.append((title, body))
                continue
        with open(raw_path, "r", encoding="utf-8") as fh:
            raw = fh.read()
        print(f"[*] sgpt analysing {tag}: {title} ...", flush=True)
        prompt = (
            f"Above is the raw output of the security scan '{title}' run against "
            f"the authorised {lab} lab target `{target}`. Write the findings "
            f"report per your role. Keep it concise (aim for under ~350 words)."
        )
        try:
            analysis = run_sgpt("argus-analyst", _clip(raw, 4500), prompt, model,
                                sgpt, timeout_s=900)
        except SgptError as exc:
            print(f"    [!] analysis failed: {exc}", flush=True)
            analysis = (f"> **Analysis unavailable** — sgpt could not produce this "
                        f"section.\n>\n> `{exc}`\n>\n> The raw scan output is "
                        f"preserved in `{tag}.txt`.")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(f"# {lab} — {title}\n\n"
                     f"*Target `{target}` · analysed by ShellGPT (`sgpt`) via local "
                     f"Ollama/llama.*\n\n{analysis}\n")
        analyses.append((title, analysis))
        print(f"    -> {md_path}", flush=True)

    if analyses:
        print("[*] sgpt writing executive summary ...", flush=True)
        joined = "\n\n".join(f"### {t}\n{a}" for t, a in analyses)
        prompt = (
            f"Above are the per-scan analyses for the authorised {lab} lab target "
            f"`{target}`. Write the executive summary per your role. Keep it "
            f"concise (aim for under ~300 words)."
        )
        try:
            summary = run_sgpt("argus-summary", _clip(joined, 8000), prompt, model,
                               sgpt, timeout_s=900)
        except SgptError as exc:
            print(f"    [!] summary failed: {exc}", flush=True)
            summary = (f"> **Summary unavailable** — sgpt could not produce it.\n>\n"
                       f"> `{exc}`")
        stamp = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
        sum_path = os.path.join(outdir, "00-SUMMARY.md")
        with open(sum_path, "w", encoding="utf-8") as fh:
            fh.write(f"# {lab} — Assessment Summary\n\n"
                     f"*Target `{target}` · analyst ShellGPT (`sgpt`) + local "
                     f"Ollama/llama · {stamp} · {len(analyses)} scans.*\n\n{summary}\n")
        print(f"    -> {sum_path}", flush=True)

    print(f"[+] analyze phase done — reports in {outdir}/", flush=True)
    return 0


# --------------------------------------------------------------------------
# Phase 3 — agentic (sgpt drives EVERYTHING: choose -> run -> observe -> report).
# --------------------------------------------------------------------------
#
# Same safety box as llama_scan.run_agentic: proposed commands go through
# shlex.split with NO shell, the first token must be an allowlisted read-only
# recon tool, and shell metacharacters / file-write flags are rejected. sgpt
# only ever PICKS an allowlisted tool + flags; it cannot escape that box.
#
# The loop runs on the HOST (that is where sgpt + its Ollama config live), but
# each recon command is executed WHERE the tools are, via a pluggable executor:
#   * docker labs (dvwa/metasploitable) -> `docker compose exec -T kali <argv>`
#   * htb                               -> run <argv> natively on this host
# Passing prefix + shlex.split(cmd) as argv (shell=False) keeps the no-shell
# guarantee end to end.

def _make_executor(exec_mode: str, compose: str | None, container: str):
    """Return run(argv, timeout) -> CompletedProcess for the chosen transport."""
    if exec_mode == "docker":
        prefix = ["docker", "compose", "-f", compose, "exec", "-T", container]

        def run_docker(argv, timeout):
            return subprocess.run(prefix + argv, capture_output=True, text=True,
                                  timeout=timeout)
        return run_docker

    def run_native(argv, timeout):
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return run_native


def _extract_command(raw: str) -> str:
    """Pull the single command (or DONE) from sgpt's reply, defensively.

    sgpt can be a touch chattier than a raw Ollama call, so rather than blindly
    taking the first line we: strip code fences and common list/prompt markers,
    return "DONE" if any line says so, then prefer the first line whose first
    token is an allowlisted tool — falling back to the first line (which will be
    rejected, prompting the model to try again)."""
    text = re.sub(r"```[a-zA-Z]*", "", raw).replace("```", "")
    lines = []
    for ln in text.splitlines():
        ln = ln.strip()
        ln = re.sub(r"^(?:\$\s+|[-*]\s+|\d+[.)]\s+)", "", ln)  # $ , - , * , 1.
        if ln:
            lines.append(ln)
    if not lines:
        return ""
    for ln in lines:
        if ln.strip(". ").upper() == "DONE":
            return "DONE"
    for ln in lines:
        toks = ln.split()
        if toks and os.path.basename(toks[0]) in AGENTIC_ALLOWED:
            return ln
    return lines[0]


def phase_agentic(lab: str, target: str, outdir: str, model: str | None,
                  sgpt: str, executor, max_steps: int, cmd_timeout: int) -> int:
    import shlex
    ensure_roles()
    agdir = os.path.join(outdir, "agentic")
    os.makedirs(agdir, exist_ok=True)
    print(f"[*] AGENTIC: lab={lab} target={target} — sgpt "
          f"(model={model or 'sgpt default (ollama/llama3:8b)'}) drives everything.",
          flush=True)
    prewarm(model)

    transcript: list[str] = []   # full log written to disk
    history: list[str] = []      # compact context fed back to the model
    seen: set[str] = set()
    step = 0
    while step < max_steps:
        hist = "\n".join(history) if history else "(nothing run yet)"
        stdin = (
            f"Target: {target} (authorised {lab} lab)\n\n"
            f"Commands run so far and what they returned (truncated):\n{hist}"
        )
        prompt = "Output the next single command, or DONE if you have enough."
        try:
            raw = run_sgpt("argus-agent", stdin, prompt, model, sgpt,
                           extra_args=("--no-cache", "--temperature", "0.0"),
                           timeout_s=180)
        except SgptError as exc:
            print(f"    [!] command generation failed, ending loop: {exc}", flush=True)
            transcript.append(f"[command generation failed after {step} steps: {exc}]")
            break

        command = _extract_command(raw)
        if not command or command == "DONE":
            transcript.append(f"[model signalled DONE after {step} steps]")
            break

        reason = agentic_reject_reason(command)
        if reason:
            print(f"    [rejected] {command!r} -> {reason}", flush=True)
            history.append(f"$ {command}\n[rejected: {reason}; choose another tool]")
            transcript.append(f"$ {command}\n[REJECTED: {reason}]\n")
            step += 1
            continue
        if command in seen:
            history.append(f"$ {command}\n[already run; do something different or DONE]")
            step += 1
            continue
        seen.add(command)

        step += 1
        print(f"    [step {step}] $ {command}", flush=True)
        try:
            proc = executor(shlex.split(command), cmd_timeout)
            out = strip_ansi(((proc.stdout or "") + (proc.stderr or "")).strip())
        except FileNotFoundError:
            out = f"[tool not available: {shlex.split(command)[0]}]"
        except subprocess.TimeoutExpired:
            out = f"[timed out after {cmd_timeout}s]"
        out = out or "[no output]"
        transcript.append(f"$ {command}\n{out}\n")
        history.append(f"$ {command}\n{out[:1200]}")

    # Persist the transcript.
    tpath = os.path.join(agdir, "transcript.txt")
    with open(tpath, "w", encoding="utf-8") as fh:
        fh.write(f"# agentic transcript — {lab} — target {target}\n\n"
                 + "\n".join(transcript) + "\n")
    print(f"    -> {tpath}", flush=True)

    if not any(line.startswith("$") for line in transcript):
        print("    [!] agentic mode produced no usable commands; no report written.",
              flush=True)
        return 0

    _write_agentic_report(lab, target, agdir, "\n".join(transcript), len(seen),
                          model, sgpt)
    print(f"[+] agentic phase done — results in {agdir}/", flush=True)
    return 0


def _write_agentic_report(lab: str, target: str, agdir: str, transcript_text: str,
                          ncmds: int, model: str | None, sgpt: str) -> None:
    """Ask sgpt (argus-agent-report role) to write 00-REPORT.md from a transcript."""
    print("[*] sgpt writing agentic findings report ...", flush=True)
    joined = _clip(transcript_text, 8000)
    prompt = (
        f"Target: {target} (authorised {lab} lab). Below (on stdin) is the "
        f"transcript of the commands you ran and their real output. Write the "
        f"findings report per your role. Keep it concise (aim for under ~450 words)."
    )
    try:
        report = run_sgpt("argus-agent-report", joined, prompt, model, sgpt,
                          extra_args=("--no-cache",), timeout_s=900)
    except SgptError as exc:
        print(f"    [!] report generation failed: {exc}", flush=True)
        report = (f"> **Report unavailable** — sgpt could not write the findings.\n>\n"
                  f"> `{exc}`\n>\n> The full command transcript is preserved in "
                  f"`transcript.txt`.")
    stamp = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    rpath = os.path.join(agdir, "00-REPORT.md")
    with open(rpath, "w", encoding="utf-8") as fh:
        fh.write(f"# {lab} — Agentic Assessment (ShellGPT-driven)\n\n"
                 f"*Target `{target}` · ShellGPT (`sgpt`) + local Ollama/llama drove "
                 f"the scanning AND the analysis · {stamp} · {ncmds} commands "
                 f"run.*\n\n{report}\n")
    print(f"    -> {rpath}", flush=True)


def phase_agent_report(lab: str, outdir: str, model: str | None) -> int:
    """Regenerate agentic/00-REPORT.md from an existing transcript.txt — no
    re-scanning, no target needed. Used to recover a report whose generation
    timed out while the transcript itself is intact."""
    agdir = os.path.join(outdir, "agentic")
    tpath = os.path.join(agdir, "transcript.txt")
    if not os.path.exists(tpath):
        print(f"[!] no transcript at {tpath}; run --phase agentic first.",
              file=sys.stderr)
        return 4
    with open(tpath, "r", encoding="utf-8") as fh:
        transcript_text = fh.read()
    cmd_lines = [ln for ln in transcript_text.splitlines() if ln.startswith("$ ")]
    ncmds = sum(1 for ln in transcript_text.splitlines() if "[REJECTED" in ln)
    ncmds = len(cmd_lines) - ncmds
    if not cmd_lines:
        print(f"[!] transcript at {tpath} has no commands; nothing to report.",
              file=sys.stderr)
        return 4
    sgpt = resolve_sgpt()
    ensure_roles()
    target = _load_manifest(outdir).get("target", "?")
    print(f"[*] regenerating agentic report for {lab} from existing transcript "
          f"({ncmds} commands) ...", flush=True)
    prewarm(model)
    _write_agentic_report(lab, target, agdir, transcript_text, ncmds, model, sgpt)
    return 0


# --------------------------------------------------------------------------
# CLI.
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="ShellGPT(+Ollama/llama)-driven scan + vuln advisor.")
    ap.add_argument("--lab", required=True, choices=sorted(PROFILES))
    ap.add_argument("--phase", required=True,
                    choices=["scan", "analyze", "agentic", "agent-report"])
    ap.add_argument("--target", default=None,
                    help="override target host/IP (required for htb)")
    ap.add_argument("--sgpt-model", default=None,
                    help="sgpt model tag, e.g. ollama/llama3:8b "
                         "(analyze/agentic phases; defaults to the .sgptrc default)")
    ap.add_argument("--outdir", default="shellgpt-results")
    ap.add_argument("--only-missing", action="store_true",
                    help="analyze: only (re)generate reports that are missing or "
                         "failed; reuse good existing ones for the summary")
    # agentic-only knobs
    ap.add_argument("--exec", dest="exec_mode", default="native",
                    choices=["native", "docker"],
                    help="agentic: run recon commands natively or inside a "
                         "container via docker compose exec")
    ap.add_argument("--compose", default=None,
                    help="agentic --exec docker: path to the lab docker-compose.yml")
    ap.add_argument("--container", default="kali",
                    help="agentic --exec docker: compose service to exec into")
    ap.add_argument("--max-steps", type=int, default=6,
                    help="agentic: max commands the model may run")
    ap.add_argument("--cmd-timeout", type=int, default=90,
                    help="agentic: per-command timeout (seconds)")
    args = ap.parse_args()

    # htb runs natively on Windows; make sure the default Nmap dir is on PATH so
    # the imported htb profile's `nmap` resolves.
    if sys.platform == "win32":
        nmap_dir = r"C:\Program Files (x86)\Nmap"
        if os.path.isdir(nmap_dir) and nmap_dir.lower() not in os.environ.get("PATH", "").lower():
            os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")

    default_target = PROFILES[args.lab][0]
    target = args.target or default_target
    outdir = os.path.join(args.outdir, args.lab)

    if args.phase == "scan":
        if not target:
            print(f"[!] --lab {args.lab} --phase scan needs an explicit --target "
                  f"(e.g. the HTB machine IP).", file=sys.stderr)
            return 2
        return phase_scan(args.lab, target, outdir)
    elif args.phase == "analyze":
        return phase_analyze(args.lab, outdir, args.sgpt_model, args.only_missing)
    elif args.phase == "agent-report":
        return phase_agent_report(args.lab, outdir, args.sgpt_model)
    else:  # agentic
        if not target:
            print(f"[!] --lab {args.lab} --phase agentic needs an explicit "
                  f"--target (e.g. the HTB machine IP).", file=sys.stderr)
            return 2
        if args.exec_mode == "docker" and not args.compose:
            print("[!] --phase agentic --exec docker needs --compose <path to "
                  "docker-compose.yml>.", file=sys.stderr)
            return 2
        sgpt = resolve_sgpt()
        executor = _make_executor(args.exec_mode, args.compose, args.container)
        return phase_agentic(args.lab, target, outdir, args.sgpt_model, sgpt,
                             executor, args.max_steps, args.cmd_timeout)


if __name__ == "__main__":
    raise SystemExit(main())

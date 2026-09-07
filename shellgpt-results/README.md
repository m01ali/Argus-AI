# shellgpt-results — ShellGPT (+ local Ollama/llama) scan results

Everything in here is produced by **one command** run from the repo root:

```powershell
# DVWA + Metasploitable (Docker labs). HTB is added automatically if a target
# IP is known (see below).
.\run-shellgpt-scans.ps1

# All three, HTB against a specific box over the VPN:
.\run-shellgpt-scans.ps1 -HtbTarget 10.129.109.234
```

The analyst is **ShellGPT (`sgpt`)** talking to the **local Ollama llama**
model — nothing leaves the host. `sgpt` writes every vulnerability finding and
every remediation; the scans only gather the evidence it reasons over.

## Two configs (same as llama)

There are two ways to run this, matching the `llama-results/` set:

| Flag | Config | What sgpt does |
|---|---|---|
| *(default)* | **scripted** | Fixed recon/PoC scans run; sgpt *explains* the results afterwards. |
| `-Agentic` | **agentic** | sgpt *chooses and runs* the commands itself, then writes the findings. Output in `<lab>/agentic/`. |
| `-Both` | both | Runs scripted then agentic for every lab, in one command. |

```powershell
.\run-shellgpt-scans.ps1 -Both       # scripted + agentic, Docker labs
.\run-shellgpt-scans.ps1 -Agentic    # sgpt drives everything, start to finish
```

In **agentic** mode, sgpt is boxed by the *same* read-only recon allowlist and
no-shell safety checks as `llama_scan.run_agentic` (imported verbatim), so the
two agents make comparable decisions — only the backend differs. The loop runs
on the host; each command it picks executes where the tools are (inside the Kali
container via `docker compose exec` for the Docker labs, natively for htb).

## How it works (two phases)

The scanning tools (sqlmap, nc, smbclient, nmap with internal-network access)
and the analyst (`sgpt`) live in different places, so each lab runs in two
phases — both driven by `shellgpt-scan/shellgpt_scan.py`:

1. **scan** — runs the fixed recon / proof-of-concept scans where the tools and
   network access are:
   - `dvwa` / `metasploitable` → **inside their Kali containers**; raw output is
     written to this folder via the mounted repo.
   - `htb` → **natively on the Windows host** over the HTB VPN.
2. **analyze** — always on the **host** (where `sgpt` + its Ollama config are):
   each raw scan is piped to `sgpt` with a dedicated, evidence-constrained
   analyst role.

The scan profiles are imported verbatim from `../llama-scan/llama_scan.py`, so
these results are directly comparable to the `llama-results/` set — the only
difference is the analyst (`sgpt` here vs. a direct Ollama call there).

## Layout

```
shellgpt-results/<lab>/
    manifest.json          what was scanned (lab, target, scans)   [scripted]
    NN-<name>.txt          raw tool output                          [scripted]
    NN-<name>.md           sgpt's findings + remediation per scan   [scripted]
    00-SUMMARY.md          sgpt's executive summary of the lab      [scripted]
    agentic/
        transcript.txt     every command sgpt chose + its output    [agentic]
        00-REPORT.md       sgpt's findings from what it ran         [agentic]
```

`<lab>` is one of `dvwa`, `metasploitable`, `htb`.

## Requirements

- Docker Desktop running (for `dvwa` / `metasploitable`).
- Local Ollama up with the llama model pulled:
  `$env:OLLAMA_HOST="0.0.0.0"; ollama serve` then `ollama pull llama3:8b`.
- ShellGPT on the host: `pip install "shell-gpt[litellm]"`, configured for local
  Ollama (see `~/.config/shell_gpt/.sgptrc`).
- For `htb`: the box spawned and the HTB VPN connected; pass `-HtbTarget <ip>`
  or put the IP in `htb-lab/target.txt`.

## Options

```
-Labs dvwa,metasploitable,htb   which labs to run (default: all three)
-HtbTarget <ip>                 HTB machine IP (also saved to htb-lab/target.txt)
-Model llama3:8b                Ollama tag sgpt uses (as ollama/<tag>)
-Agentic                        sgpt drives everything (vs. scripted default)
-Both                           run scripted + agentic per lab in one command
-Rebuild                        force `docker compose up -d --build`
-SkipUp                         assume the Docker labs are already up
```

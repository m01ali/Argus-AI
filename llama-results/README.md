# llama-results — Llama-driven scans & remediation

Everything in here is produced by **one command** driving a **local Llama**
(`llama3:8b` via Ollama). Nothing is sent to any cloud service.

## Two modes (run side by side)

| Mode | Who runs the scans | Who analyses | Command |
|------|--------------------|--------------|---------|
| **Scripted** (default) | fixed commands we define | Llama | `.\run-llama-scans.ps1` |
| **Agentic** | **Llama** (picks + runs each command) | Llama | `.\run-llama-scans.ps1 -Agentic` |
| **Both** | one run captures both of the above | Llama | `.\run-llama-scans.ps1 -Both` |

- **Scripted**: deterministic, repeatable. The tools are fired by fixed
  commands; Llama only reads the output and writes findings + remediation.
  Output → `llama-results/<lab>/`.
- **Agentic**: Llama decides what to probe, generates each command, reads the
  result, and picks the next step (up to `-MaxSteps`, default 6), then writes
  the report. Commands are allowlist-gated and run with **no shell** (no
  chaining/redirection/file-writes possible). Output → `llama-results/<lab>/agentic/`.

Run both to compare them on the same target.

## The one command

```powershell
# from D:\Argus-AI  (Ollama must be running; the two Docker labs auto-start)
.\run-llama-scans.ps1              # scripted mode
.\run-llama-scans.ps1 -Agentic     # agentic mode (Llama drives)
```

That scans **DVWA** and **Metasploitable** (in their Kali containers) and
**HTB** if you give it the machine IP:

```powershell
.\run-llama-scans.ps1 -HtbTarget 10.129.x.x     # add HTB over the VPN
.\run-llama-scans.ps1 -Labs dvwa                 # just one lab
.\run-llama-scans.ps1 -Model qwen3.5:9b          # sharper (slower) analyst
```

Prerequisites: **Docker Desktop** running (for dvwa/metasploitable) and
**Ollama** serving on `127.0.0.1:11434` with `llama3:8b` pulled. For HTB,
connect the VPN and spawn the box first.

## Layout

```
llama-results/
  dvwa/                        <- scripted mode
    01-nmap.txt  01-nmap.md
    02-web.txt   02-web.md
    03-sqlmap.txt 03-sqlmap.md
    04-cmdi.txt  04-cmdi.md
    00-SUMMARY.md
    agentic/                   <- agentic mode (-Agentic)
      transcript.txt           (commands Llama chose + their output)
      00-REPORT.md             (Llama's findings from that transcript)
  metasploitable/  ...
  htb/  ...
```

- Scripted: `NN-name.txt` raw tool output, `NN-name.md` Llama's analysis of it,
  `00-SUMMARY.md` executive summary of the target.
- Agentic: `agentic/transcript.txt` is the command→output log Llama drove;
  `agentic/00-REPORT.md` is its write-up from that transcript.

## How each lab is scanned

| Lab | Where it runs | Scans Llama analyses |
|-----|---------------|----------------------|
| dvwa | Kali container (`target-w`) | nmap, web fingerprint (whatweb/nikto), authenticated sqlmap, command injection |
| metasploitable | Kali container (`target-m`) | nmap, ingreslock (1524) root shell, Samba usermap RCE (CVE-2007-2447) |
| htb | Windows host over VPN | nmap service/version scan |

The engine is [`llama-scan/llama_scan.py`](../llama-scan/llama_scan.py); the
launcher is [`run-llama-scans.ps1`](../run-llama-scans.ps1).

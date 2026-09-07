# metasploitable — TCP 1524 ingreslock — unauthenticated root shell

*Target `target-m` · analysed by ShellGPT (`sgpt`) via local Ollama/llama.*

## Open Ports / Services

| Port | Service | Version | Notes |
| --- | --- | --- | --- |
| 1524 | ingreslock | - | Unauthenticated root shell |

## Vulnerabilities & Weaknesses

### Finding 1: Unauthenticated Root Shell

**Severity**: Critical
**What it is**: The ingreslock service on port 1524 allows an unauthenticated attacker to gain a root shell.
**Why it matters**: This vulnerability provides a direct path for an attacker to gain elevated privileges, allowing them to execute arbitrary commands and potentially take control of the system.

Note: This finding is based solely on the provided scan output and does not rely on any external information or assumptions.

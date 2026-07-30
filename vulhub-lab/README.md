# Argus-AI Vulhub Lab — Setup & Run Guide

A fully dockerized target range for Argus-AI, built from real [Vulhub](https://github.com/vulhub/vulhub)
environments. This file is written so a new developer can go from a fresh
clone to a working run, and so you (returning after a reboot) can get back
up in a few minutes without re-deriving anything.

**If you only need the cold-start checklist**, skip to [Section 3](#3-cold-start-after-a-reboot-already-set-up-before).
**If this is the first time on this machine**, start at [Section 2](#2-fresh-setup-new-machine--first-time).

---

## 0. What this actually is

Four real Vulhub containers + one Kali-based scanner container, all on one
isolated Docker network. Argus-AI runs *inside* the scanner container and
attacks the other four over that network. Ollama (the LLM backend) runs on
your host machine, not in Docker — the scanner container reaches it via
`http://host.docker.internal:11434`. Both the default models (llama3:8b,
qwen3.5:9b) and RedSage-Qwen3-8B-DPO are just different Ollama tags served
from the same endpoint — select one per-run with `--executor-model`/
`--advisor-model` (see `../how to run.txt`).

```
                    ┌─────────────────────────────────────┐
                    │        pentestlab (bridge net)       │
   host:6379 ───────┼──▶ target-a  (vulhub/redis)          │
   host:8983/5005 ──┼──▶ target-b  (vulhub/solr)           │
   host:8081 ───────┼──▶ target-c  (vulhub/drupal)         │
   host:8082 ───────┼──▶ target-d  (vulhub/struts2)        │
                    │        ▲                              │
                    │        │ nmap/nikto/sqlmap/etc.        │
                    │      kali  (runs argus.cli)           │
                    └────────┼──────────────────────────────┘
                             │ http://host.docker.internal:11434
                             ▼
                    Ollama (llama3:8b, qwen3.5:9b) — on the HOST
```

**Why the targets are named `target-a/b/c/d` and not `redis`/`solr`/etc.:**
a service literally named after its vulnerable software leaks the answer to
the model — Docker's embedded DNS attaches a reverse-DNS record built from
the service name, so even a plain `nmap` scan reveals it unprompted. The
actual mapping (which label is which CVE) lives in
`../report/target-legend-PRIVATE.md` — that file is for *your* bookkeeping
only and must never be read by, or referenced from, anything Argus-AI runs.

---

## 1. Prerequisites (any machine)

- **Docker Desktop** (with the `docker compose` plugin — bundled by default)
- **Ollama**, installed locally: <https://ollama.com>
- ~2GB free disk for the Vulhub images, ~1GB for the Kali scanner image
- Enough VRAM/RAM to run one ~5-7GB local model at a time (this lab was
  built and tested on an 8GB-VRAM / 16GB-RAM machine — see the note in
  Section 5 about why the two models never need to be loaded simultaneously)

---

## 2. Fresh setup (new machine / first time)

### 2.1 Clone the repo and confirm Docker works

```bash
git clone <this-repo-url> Argus-AI
cd Argus-AI
docker ps
```
If `docker ps` errors, start Docker Desktop and wait ~30-60s, then retry.

### 2.2 Install and configure Ollama so containers can reach it

Ollama defaults to binding `127.0.0.1` only, which is invisible to anything
running inside Docker. You must rebind it to `0.0.0.0`:

```powershell
# Windows — pick ONE:

# Option A: persistent (recommended for repeat use)
#   Settings > System > About > Advanced system settings > Environment
#   Variables > New (User variable): OLLAMA_HOST = 0.0.0.0
#   Then just launch Ollama normally (Start Menu) from now on.

# Option B: temporary, for this session only — keep this terminal open:
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve
```

Verify:
```powershell
netstat -an | findstr 11434
```
You must see `0.0.0.0:11434 LISTENING`, not `127.0.0.1:11434`.

### 2.3 Pull both models

```bash
ollama pull llama3:8b
ollama pull qwen3.5:9b
```

### 2.4 Build and start the lab

```bash
cd vulhub-lab
docker compose up -d --build
docker compose ps
```
Expect 5 services `Up`: `target-a`, `target-b`, `target-c`, `target-d`, `kali`.

This step also builds the Kali scanner image (`nmap`, `nikto`, `sqlmap`,
`whatweb`, `gobuster`, `enum4linux`, `smbclient`, `dig`, `whois`, `curl`,
`nbtscan`, `redis-cli`, `searchsploit`, `python3`) — expect several minutes
the first time; subsequent `up -d` calls reuse the built image and are fast.

### 2.5 Verify the scanner container can reach Ollama

```bash
docker compose exec kali curl -s http://host.docker.internal:11434/api/tags
```
Should print JSON listing `llama3:8b` and `qwen3.5:9b`. If it errors or is
empty, go back to 2.2 — do not proceed until this returns real JSON.

### 2.6 Run Argus against a target

```bash
docker compose exec kali bash
```
Then, inside the container:
```bash
python -m argus.cli --target target-a --authorize -v
```
Repeat for `target-b`, `target-c`, `target-d`. Reports land in
`../argus-reports/` (bind-mounted — visible on the host too).

You're set up. For every future session, jump to Section 3.

---

## 3. Cold start after a reboot (already set up before)

Run each step's verification command before moving to the next — don't
assume a step worked.

**1. Docker engine up?**
```powershell
docker ps
```
If it errors, launch Docker Desktop and wait, then retry.

**2. Ollama bound to 0.0.0.0?**
```powershell
netstat -an | findstr 11434
```
- Shows `0.0.0.0:11434 LISTENING` → already good, skip to step 3.
- Shows nothing at all → Ollama isn't running. Start it:
  ```powershell
  $env:OLLAMA_HOST = "0.0.0.0"
  ollama serve
  ```
  (leave that terminal open; use a **new** terminal for everything below)
- Shows only `127.0.0.1:11434` → same fix as above, after quitting the
  existing Ollama process first (tray icon → Quit).

If you set `OLLAMA_HOST` persistently via Environment Variables (2.2 Option
A), Ollama will already bind correctly every time you launch it normally —
you should rarely need the manual `ollama serve` step going forward.

**3. Bring the containers back up**
```bash
cd d:/Argus-AI/vulhub-lab
docker compose up -d
docker compose ps
```
No `--build` needed unless a Dockerfile changed. Confirm all 5 services `Up`.

**4. Verify Ollama reachability from the container**
```bash
docker compose exec kali curl -s http://host.docker.internal:11434/api/tags
```
Must return real JSON. If empty/error, go back to step 2.

**5. Run**
```bash
docker compose exec kali bash
python -m argus.cli --target target-a --authorize -v
```

---

## 4. Running Argus against each target

```bash
python -m argus.cli --target target-a --authorize -v
python -m argus.cli --target target-b --authorize -v
python -m argus.cli --target target-c --authorize -v
python -m argus.cli --target target-d --authorize -v
```

Each run writes a Markdown + JSON report to `argus-reports/`. `-v` gives
INFO-level progress logging; drop it for quiet output. `--dry-run` generates
commands without executing them (useful for prompt-level debugging, but
Discovery will find nothing real since no tool actually runs).

---

## 5. Concurrency / hardware note

Argus-AI's stages are strictly sequential (Discovery → Validation → Patch
Proposal → Re-scan), one blocking model call at a time — the executor
(`llama3:8b`) and advisor (`qwen3.5:9b`) are never loaded and active
simultaneously by design of the code, not by luck. On an 8GB-VRAM host,
Ollama evicts the idle model and cold-loads the other one at each stage
transition; this costs a noticeable pause per switch but stays within VRAM.
`ModelConfig.request_timeout_s` (currently 300s) covers this cold-load time
— if you see a timeout error, it names the model and suggests pre-warming it:
```bash
curl -s http://host.docker.internal:11434/api/generate -d '{"model":"qwen3.5:9b","prompt":"hi","stream":false}' > /dev/null
```

---

## 6. Troubleshooting — issues actually hit while building this lab

| Symptom | Cause | Fix |
|---|---|---|
| Docker build fails ~7 min in, mid-`apt-get install` | `searchsploit -u` chained with `&&`; the apt-installed exploitdb tree isn't a git checkout, so it exits non-zero and kills the whole layer | Already fixed in `kali/Dockerfile` — `searchsploit -u` is its own non-fatal `RUN` |
| `bash: python: command not found` inside the container | `kalilinux/kali-rolling` only ships `python3` | Already fixed — `python-is-python3` is in the Dockerfile |
| `Cannot reach local Ollama at http://localhost:11434` from inside the container | `cli.py` wasn't reading the `ARGUS_OLLAMA_HOST` env var the compose file sets | Already fixed — `cli.py` now calls `ArgusConfig.from_env()` |
| Still can't reach Ollama, `http://host.docker.internal:11434` refused | Ollama bound to `127.0.0.1` only | Set `OLLAMA_HOST=0.0.0.0` on the host, restart Ollama (Section 2.2 / 3 step 2) |
| Discovery always returns 0 findings | Small executor model won't call a bare version banner a "finding" without explicit criteria | Already fixed — `DiscoveryStage._interpret`'s prompt now states generic finding criteria |
| Validation fails with `No such file or directory: 'redis-cli'` | Model chose the right tool, image didn't have it | Already fixed — `redis-tools` added to Dockerfile |
| Validation "verifies" against `localhost` instead of the real target | Model hallucinated a placeholder despite being told the real target | Already fixed — prompt now demands the literal target string |
| `Run failed: timed out` during Patch Proposal | Advisor model cold-loading + generating exceeded the 120s default | Already fixed — timeout raised to 300s, clearer error message added |
| A finding's title/description mentions the target software by name with weak/no evidence | Target hostname (or its Docker rDNS PTR record) leaked the answer | Already fixed — services renamed to opaque `target-a/b/c/d` labels; see `report/target-legend-PRIVATE.md` |
| `docker compose ps` shows nothing after `docker compose up -d --build` | The build likely errored out silently in your terminal, or was still running | Re-run and check the exit code / tail of the output before assuming success |

---

## 7. Resetting a target

Vulhub images ship pre-vulnerable; recreating a container reverts any
runtime config changes made during a patch:

```bash
docker compose stop target-a && docker compose rm -f target-a && docker compose up -d target-a
```

Full reset:
```bash
docker compose down -v
docker compose up -d --build
```

## 8. A note on Re-scan and "actually patching" a container

`Argus.run()`'s default `patch_applier` is `None` — authorising a patch in
the interactive prompt records the human's decision but does not mutate the
running container. Re-scan will then legitimately still find the same
issue, since nothing changed. To see a finding genuinely flip to
`resolved_after_patch=True`, wire a `patch_applier` callback that carries out
the advisor's remediation against the real container (e.g. `docker compose
exec target-a redis-cli CONFIG SET requirepass '<password>'` for the config-
fix target; the three package-upgrade targets require swapping the image tag
in `docker-compose.yml` and recreating the container, since there's no
in-place package manager fix inside a frozen Vulhub image).

Separately, `RescanStage` currently matches "is this finding still present"
by exact lowercased title string — since the executor model's phrasing isn't
perfectly deterministic run-to-run, this comparison is fragile even with a
real `patch_applier` wired up. Treat any "resolved" verdict with that caveat
until a more robust re-identification method is in place.

## 9. Scope reminder

These are intentionally vulnerable containers, isolated on their own bridge
network with ports bound to `127.0.0.1` only. Do not expose this compose
stack on a shared network or the internet. Argus-AI's own scope-
authorisation gate (`--authorize`) still applies — you are authorising
yourself, as the owner of this lab, to test these containers.

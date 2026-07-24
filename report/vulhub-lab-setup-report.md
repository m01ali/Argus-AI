# Argus-AI × Vulhub Lab — Session Report

**Date:** 2026-07-23
**Goal:** Replace the Metasploitable2 target with a dockerized Vulhub lab covering 3-4 vulnerabilities that the Patch Proposal (advisor) model has a realistic shot at remediating correctly, and validate the full Discovery → Validation → Patch Proposal → Re-scan loop against it.

---

## 1. Model change — dropped Gemma3:12B

| Stage | Before | After |
|---|---|---|
| Discovery / Validation (executor) | `llama3:8b` | `llama3:8b` (unchanged) |
| Patch Proposal (advisor) | `gemma3:12b` | `qwen3.5:9b` |

Files updated: `argus/config.py`, `argus/stages.py`, `README.md`, `argus-ai-README.md`, `argus-flow-diagram.html` (both the root copy and `docs/` copy), `requirements.txt`.

---

## 2. Vulhub targets selected

Four real [Vulhub](https://github.com/vulhub/vulhub) environments, chosen because each has a signal Argus's existing tool allowlist (`nmap`, `nikto`, `sqlmap`, `searchsploit`, `whatweb`, `gobuster`, `dig`, `whois`, `curl`, `nbtscan`, `enum4linux`, `smbclient`) can actually detect, and a single well-documented remediation path (config change or version/package upgrade):

| Target service | Vulnerability | Fix category |
|---|---|---|
| `redis` | Unauthenticated Redis access (`vulhub/redis:4.0.14`) | Configuration |
| `solr` | Log4Shell — CVE-2021-44228 (`vulhub/solr:8.11.0`) | Package upgrade |
| `drupal` | Drupalgeddon2 — CVE-2018-7600 (`vulhub/drupal:8.5.0`) | Package upgrade |
| `struts2` | S2-045 — CVE-2017-5638 (`vulhub/struts2:2.3.30`) | Package/config upgrade |

---

## 3. Infrastructure built

```
vulhub-lab/
  docker-compose.yml   4 target containers + a Kali scanner container, one bridge network
  kali/Dockerfile       nmap, nikto, sqlmap, whatweb, gobuster, enum4linux, smbclient,
                        dig, whois, curl, nbtscan, redis-cli, searchsploit, python3
  README.md             full setup/usage/reset instructions
```

- All 4 vulnerable containers + a `kali` scanner container sit on one isolated bridge network (`pentestlab`); host ports are bound to `127.0.0.1` only.
- The `kali` container mounts the whole repo at `/opt/argus-ai`, so `python -m argus.cli` runs directly against the other containers by Docker DNS service name (`redis`, `solr`, `drupal`, `struts2`) — no separate Kali VM needed.
- Ollama itself runs on the Windows host (not in Docker); the `kali` container reaches it via `http://host.docker.internal:11434`.

---

## 4. Bugs found and fixed

These were all real defects surfaced by actually running the stack, not hypothetical — each blocked the loop from working until fixed.

1. **Docker build failure — `searchsploit -u` chained with `&&`.**
   The apt-installed `exploitdb` tree isn't a git checkout, so `searchsploit -u` exits non-zero, killing the entire `RUN` layer after ~7 minutes of otherwise-successful package installs.
   **Fix:** moved to its own `RUN searchsploit -u || true`, non-fatal, in `vulhub-lab/kali/Dockerfile`.

2. **`python: command not found` inside the Kali container.**
   `kalilinux/kali-rolling` only ships `python3`, not a `python` symlink.
   **Fix:** added `python-is-python3` to the Dockerfile package list.

3. **Ollama connection refused from inside the container.**
   `cli.py` built a bare `ArgusConfig()` instead of `ArgusConfig.from_env()`, so the `ARGUS_OLLAMA_HOST` / `ARGUS_EXECUTOR_MODEL` / `ARGUS_ADVISOR_MODEL` environment variables set in `docker-compose.yml` were silently ignored — it kept trying the hardcoded default `http://localhost:11434`, unreachable from inside a container.
   **Fix:** changed `cfg = ArgusConfig()` to `cfg = ArgusConfig.from_env()` in `argus/cli.py` (CLI flags still override env vars afterward, unchanged).

4. **Ollama unreachable from Docker Desktop even after the above.**
   Ollama binds to `127.0.0.1` by default on Windows, invisible to anything outside the host's own loopback — including containers.
   **Fix:** set `OLLAMA_HOST=0.0.0.0` as a user environment variable and restarted Ollama (confirmed via `netstat -an | findstr 11434` showing `0.0.0.0:11434`).

5. **Discovery never flagged anything — small-model interpretation gap.**
   `llama3:8b`, given a plain nmap version banner (`Redis 4.0.14`, port open), returned `{}` every time — it wasn't reasoning "unauthenticated" or "known-vulnerable version" from a bare banner alone.
   **Fix:** added an explicit, generic finding-criteria rubric to `DiscoveryStage._interpret`'s prompt (exposed service with no evidence of auth; old/named software version; verbose version banner; default/blank credentials; info disclosure). Deliberately CVE/target-agnostic — applies identically regardless of which service is being scanned.

6. **Discovery hallucinated CLI flags.**
   The `vuln-id` phase command came back as `searchsploit --no-update -m redis`, then later `searchsploit --no-exact -w 0-9.99 redis` — both invalid/nonsensical flag usage. Execution failed safely (sandboxed subprocess error, not a fabricated finding), but wasted the vuln-id phase.
   **Partial fix:** added a generic instruction to `DiscoveryStage.SYSTEM`: "Only use flags and options you are certain exist for that exact tool; if you are not certain, invoke the tool with no extra flags rather than guessing one." Reduced but did not fully eliminate the behavior — worth tracking as an open executor-model limitation.

7. **Validation chose the right tool, but it wasn't installed.**
   The model correctly decided to verify Redis with `redis-cli`, but the Kali image had no Redis client, so verification failed with `No such file or directory: 'redis-cli'`.
   **Fix:** added `redis-tools` to the Dockerfile. (Note: `ValidationStage` is not restricted to Discovery's `ALLOWED_TOOLS` allowlist — worth documenting as an intentional or accidental asymmetry between the two stages.)

8. **Validation hallucinated the target itself.**
   Given an explicit `Target: redis` in the prompt, the model generated a verification `nmap` command against `localhost` instead — closed inside the Kali container, so it correctly failed to confirm. This is the hallucination-defense gate working as designed (bad command → no evidence → UNCONFIRMED, not a false positive) — but it meant a real, exploitable finding didn't get a chance to reach Patch Proposal.
   **Fix:** `ValidationStage._verify`'s prompt now explicitly states the command "MUST run against the literal target string ... — never substitute localhost, 127.0.0.1, or any other placeholder."

9. **Patch Proposal timed out (`Run failed: timed out`).**
   `qwen3.5:9b` (9.7B params, 6.59GB @ Q4_K_M) cold-loading into memory — after Ollama evicted the idle `llama3:8b` to make room on an 8GB-VRAM host — plus generating a full 3-section remediation, exceeded the default 120s request timeout.
   **Fix:** raised `ModelConfig.request_timeout_s` from 120 to 300 in `argus/config.py`, and added explicit `socket.timeout`/`TimeoutError` handling in `argus/llm.py` so a future timeout gives an actionable message instead of a bare `"timed out"`.

### Known limitation — NOT fixed, flagged for awareness

**Re-scan's "resolved" determination is fragile.** `RescanStage` matches prior confirmed findings against a fresh scan **by exact lowercased title string** (`f.title.lower() not in still_present`). Two problems:
- No `patch_applier` was wired up for this session's runs (`Argus(cfg, authorizer=...)` was called without one), so authorizing a patch never actually mutated the Redis container — `patch_status` went to `APPLIED` purely from human sign-off (`orchestrator.py`: `applied = self.patch_applier(f) if self.patch_applier else True`).
- Despite nothing being mutated, the live run's second iteration reported one finding as `resolved_after_patch=True`. The most likely explanation is that `llama3:8b`'s non-deterministic interpretation step produced slightly different finding titles/counts across repeated scans of the *same, unchanged* target — which the exact-string match reads as "no longer present" (resolved), when really nothing changed.
- **Recommendation before trusting any "verified resolved" claim in a report:** wire up a real `patch_applier` per target (see `vulhub-lab/README.md`'s notes on this), and consider replacing exact-title matching with a more robust re-identification method (e.g., match on a stable finding category/fingerprint rather than the LLM's free-text title).

---

## 5. Full command reference

### One-time host setup

```bash
# Ollama must be reachable from Docker containers, not just 127.0.0.1
# Quit Ollama fully (tray icon -> Quit), then either:

# Option A - temporary, in a terminal you leave open:
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve

# Option B - persistent:
#   Windows Settings > System > About > Advanced system settings >
#   Environment Variables > New (User) > OLLAMA_HOST = 0.0.0.0
#   then relaunch Ollama from the Start Menu

# Verify it bound correctly:
netstat -an | findstr 11434   # want 0.0.0.0:11434, not 127.0.0.1:11434

# Pull both models
ollama pull llama3:8b
ollama pull qwen3.5:9b
```

### Bring up the lab

```bash
cd d:/Argus-AI/vulhub-lab
docker compose up -d --build
docker compose ps                 # expect 5 services: redis, solr, drupal, struts2, kali
```

### Verify connectivity

```bash
docker compose exec kali curl -s http://host.docker.internal:11434/api/tags
# should list your pulled models, not error
```

### Run Argus against each target

```bash
docker compose exec kali bash

# inside the container:
python -m argus.cli --target redis   --authorize -v
python -m argus.cli --target solr    --authorize -v
python -m argus.cli --target drupal  --authorize -v
python -m argus.cli --target struts2 --authorize -v
```

Reports land in `argus-reports/` (bind-mounted, visible on the host too).

### Reset a target (undo runtime config changes)

```bash
docker compose stop redis && docker compose rm -f redis && docker compose up -d redis
```

### Full reset

```bash
docker compose down -v
docker compose up -d --build
```

---

## 6. First live result (Redis target)

- **Discovery:** 2 candidate findings — "Redis Service Exposed with Old Version" and "Redis Service Exposed" (unauthenticated), both from real `nmap -sV -p 6379 redis` output.
- **Validation:** both confirmed (2/2) using a model-chosen `redis-cli` verification command against the real container.
- **Patch Proposal (`qwen3.5:9b`):** produced detailed, entirely self-generated three-part remediation for each finding (`requirepass`, `bind`, `protected-mode`, ACLs, `rename-command` for dangerous commands, version-upgrade guidance, secure-client-connection code guidance) — no remediation content was written or suggested by the operator.
- **Human-in-the-loop:** both patches authorised (`y`).
- **Re-scan (iteration 2):** 1 of 2 confirmed findings reported as resolved — see the "Known limitation" note above before treating this as a genuine remediation verification.

---

## 7. On research integrity — what was and wasn't hinted to the models

Every prompt change made this session is quoted in Section 4 above. None of them name a target, a CVE, or a vulnerability class — they are all generic (tool-usage discipline, a finding-judgment rubric, and "use the literal target string"), and would apply identically regardless of which service Argus is pointed at. The one infrastructure change directly triggered by a specific run was adding `redis-cli` to the Kali image, after the model *independently chose* to use it and found it missing — the tool choice was the model's own; only the missing binary was supplied. Before running the remaining three targets (Solr, Drupal, Struts2 — still untouched as of this report), the same discipline should hold: fix generically, disclose in methodology, never hardcode target-specific content.

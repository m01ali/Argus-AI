# Argus-AI × Vulhub — Empirical Results: Hinted vs. Blind Target Naming

**Compiled:** 2026-07-24
**Source data:** every claim below is sourced directly from files in `argus-reports/` (the raw JSON/Markdown output written by `argus.report.write_reports()`) or from manually-run diagnostic probes explicitly labeled as such. File names are cited so every claim can be independently re-verified against the raw artifact. Nothing in this document is inferred, estimated, or reconstructed from memory — where the underlying data does not answer a question, that is stated explicitly rather than filled in.

---

## 1. What "hinted" vs "blind" means here

- **Hinted runs**: Docker Compose services were named after the software they run (`redis`, `solr`, `drupal`, `struts2`), and `argus.cli --target <name>` was invoked with that literal name. Docker's embedded DNS also attaches a reverse-DNS (PTR) record built from the compose service name, so this name is visible to `nmap` and any DNS-resolving tool regardless of whether `--target` uses the name or the container's IP.
- **Blind runs**: services were renamed to opaque labels (`target-a` = Redis, `target-b` = Solr, `target-c` = Drupal, `target-d` = Struts2) in `vulhub-lab/docker-compose.yml`, removing both the forward-DNS name and the rDNS PTR leak. The mapping is kept in `report/target-legend-PRIVATE.md`, outside anything Argus-AI can read.
- The rename was made **after** the hinted runs had already been executed, specifically because a hinted run against `struts2` produced a finding with no supporting evidence (documented in §5). All four targets were then re-run under blind names to get a comparable dataset.

---

## 2. Data inventory (all files this report draws from)

| File (in `argus-reports/`) | Target string used | Confirmed / Patched / Resolved (final) | Iterations |
|---|---|---|---|
| `argus-redis-20260723-113815.json` | `redis` | 0 / 0 / 0 (empty findings list) | 1 |
| `argus-redis-20260723-113847.json` | `redis` | 0 / 0 / 0 (empty findings list) | 1 |
| `argus-redis-20260723-114749.json` | `redis` | 0 / 0 / 0 | 1 |
| `argus-redis-20260723-121551.json` | `redis` | iter1: 2/2/0, iter2: 1/1/1 | 2 |
| `argus-redis-20260723-152305.json` | `redis` | iter1: 1/1/0, iter2: 0/0/0 | 2 |
| `argus-solr-20260723-152355.json` | `solr` | 0 / 0 / 0 | 1 |
| `argus-drupal-20260723-154356.json` | `drupal` | iter1: 2/2/0, iter2: 2/2/0, iter3: 2/2/0 | 3 |
| `argus-struts2-20260723-154705.json` | `struts2` | 0 / 0 / 0 | 1 |
| `argus-target-a-20260723-190211.json` | `target-a` (Redis, blind) | 0 / 0 / 0 | 1 |
| `argus-target-b-20260723-195732.json` | `target-b` (Solr, blind) | iter1: 1/0/0, iter2: 1/1/0, iter3: 2/2/0 | 3 |
| `argus-target-c-20260723-200050.json` | `target-c` (Drupal, blind) | 0 / 0 / 0 | 1 |
| `argus-target-d-20260723-200251.json` | `target-d` (Struts2, blind) | 0 / 0 / 0 | 1 |
| `argus-target-d-20260723-200447.json` | `target-d` (Struts2, blind, repeat) | 0 / 0 / 0 | 1 |

`argus-192-168-56-101-20260719-200722.json` is a pre-existing report from before this session's work (a different target, `192.168.56.101`, run 2026-07-19) and is out of scope for this comparison.

**Instrumentation limitation, disclosed up front:** the `Finding` data model (`argus/models.py`) does not persist the exact shell command `ValidationStage` generated to verify a finding — only the resulting `proof` (stdout) is stored. Where the validation command itself matters to the analysis below, it is inferred from the *format* of the proof text (e.g., nmap NSE script output has a distinctive `| scriptname:` prefix) and is labeled as inferred, not confirmed.

---

## 3. Redis (Vulhub `redis/4-unacc`, real issue: unauthenticated access)

### 3a. Hinted (`--target redis`)

**Run 1 & 2 — `argus-redis-20260723-113815.json`, `argus-redis-20260723-113847.json`** (before the `_interpret` rubric fix): both report `"findings": []` — Discovery produced zero candidate findings. No commands are recorded in these files because the data model only attaches `discovery_commands` to a `Finding` object, and none was created.

**Diagnostic probe (manual, not a CLI run)** — to understand the above, the exact `DiscoveryStage._interpret` prompt was manually replicated via a direct call to Ollama's `/api/generate` with `llama3:8b`, using real `nmap -sV -p 6379 redis` output as input. The real nmap output was:
```
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.14
```
The model's response to the (pre-fix) interpretation prompt was:
```
{}
(Note: There are no security findings in this output, so the JSON object is empty.)
```
This is consistent with, and explains, the two empty-findings runs above. This probe was run outside the orchestrator and is not itself a CLI execution record.

**Run 3 — `argus-redis-20260723-114749.json`** (after the `_interpret` rubric fix, before the `redis-tools`/target-fidelity fixes): 2 candidate findings, 0 confirmed.
- `F-64588`, phase `recon`, command `nmap -sV -p 6379 redis`, title "Redis Service Exposed with Old Version". Verdict `unconfirmed`. `proof`: `"verification failed: [Errno 2] No such file or directory: 'redis-cli'"` — the model chose to verify with `redis-cli`, which was not installed in the Kali image at that point.
- `F-67338`, phase `scan`, command `nmap -p 6379 redis`, title "Redis Service Exposed". Verdict `unconfirmed`. `proof`: `"Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-23 11:47 +0000\nNmap scan report for localhost (127.0.0.1)\nHost is up (0.000057s latency)...\n6379/tcp closed redis..."` — the verification command scanned `localhost` (closed) instead of the target `redis`.

**Run 4 — `argus-redis-20260723-121551.json`** (after `redis-tools` added to the Kali image and the "use the literal target string" fix to `ValidationStage`): iteration 1: 2 confirmed, 2 patched.
- `F-26776`, command `nmap -p 6379 redis`, title "Redis Service Exposed". Verdict `confirmed`. `proof`: a plain nmap port-scan (`6379/tcp open redis`) with **no additional evidence beyond the port being open** — no version, no auth-check, no NSE script output. The judge step (`ValidationStage._judge`) answered YES to "does this confirm the finding" on this evidence alone.
- `F-28996`, command `nmap -p 6379 redis`, title "Redis Service Exposed". Verdict `confirmed`. `proof` includes nmap's `redis-info` NSE script output:
  ```
  | redis-info:
  |   Version: 4.0.14
  |   ...
  |   Bind addresses:
  |     0.0.0.0
  |   Client connections:
  |_    172.18.0.6
  ```
  This is materially stronger evidence (server bound to `0.0.0.0`, an active client connection, `INFO` succeeding with no credentials).

**Important correction to an earlier statement made mid-session:** at the time, this assistant told the user "the model correctly chose redis-cli to verify" Redis in this successful run. That is not accurate — the `proof` text format above (`| redis-info:` prefix) is nmap's own `redis-info` NSE script output, not raw `redis-cli` output. **It cannot be confirmed from this data that the earlier `redis-tools` fix was causally necessary for this success** — the successful run's evidence does not show `redis-cli` being invoked at all; the model used a different nmap NSE script instead. This is now corrected in this report.

Iteration 2 of this same run (`resolved_after_patch` field): `F-11960` (re-discovered "Redis Service Exposed" finding) is recorded as `"resolved_after_patch": true`. No `patch_applier` was configured for this run (`Argus(cfg, authorizer=_interactive_authorizer)` in `cli.py` never passes one), meaning authorizing a patch never mutates the running container (`orchestrator.py`: `applied = self.patch_applier(f) if self.patch_applier else True`). The container's actual configuration was not changed between iterations 1 and 2. A `resolved_after_patch: true` verdict on an unmodified target is only explainable by `RescanStage`'s exact-lowercased-title matching (`f.title.lower() not in still_present`) failing to find the same title string on the fresh scan — i.e., **this specific "resolved" result does not reflect a genuine fix** and should not be cited as evidence of successful remediation-verification.

**Run 5 — `argus-redis-20260723-152305.json`**: iteration 1: 1 confirmed (`nmap -p 6379 redis`, "Redis Service Exposed", proof is plain port-scan output only, no NSE script, no redis-cli), 1 patched. Iteration 2: 0 confirmed, 0 patched — both findings in iteration 2 (`F-79167`, `F-81760`) came back `unconfirmed` with plain nmap port-scan proof (no additional signal). This run demonstrates the same finding, run close in time to the successful run above, receiving inconsistent judge verdicts on similarly weak evidence — in run 4 a plain-port-scan proof was judged `confirmed`; in this run, plain-port-scan proof was judged `unconfirmed` for both remaining findings.

### 3b. Blind (`--target target-a`)

**`argus-target-a-20260723-190211.json`**: 1 candidate finding, 0 confirmed.
- `F-29239`, command `nmap -sV -p- target-a` (a full 65535-port version-detection scan — broader than any command used in the hinted runs), title "Redis Service Exposed with No Authentication". `discovery_commands[0].stdout` shows genuine, tool-derived identification:
  ```
  PORT     STATE SERVICE VERSION
  6379/tcp open  redis   Redis key-value store 4.0.14
  ```
  This is the Redis wire protocol self-announcing its identity to nmap's service-detection probe — the finding is not attributable to the target hostname, since `target-a` carries no semantic content. Verdict: `unconfirmed`. `proof`: `"Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-23 19:02 +0000\n"` — the verification step's real output was, per the stored proof, only the nmap startup banner with no port/service table following it.

### 3c. Redis summary of directly observed facts
- Discovery correctly and repeatedly identified the real Redis service from its own protocol banner, both hinted and blind — this identification is not attributable to the hostname.
- Validation's judge step accepted a bare "port open" proof as sufficient confirmation in one case (`F-26776`) and rejected functionally similar bare "port open" proof as insufficient in another (the two `unconfirmed` findings in run 5's iteration 2, and the blind run's `F-29239`). The data does not support a claim that Validation's strictness is consistent.
- One "resolved" verdict (`F-11960`) is not attributable to any real fix, since no `patch_applier` was ever configured in this session's runs.

---

## 4. Apache Solr / Log4Shell (Vulhub `log4j/CVE-2021-44228`, real issue: CVE-2021-44228)

### 4a. Hinted (`--target solr`)

**`argus-solr-20260723-152355.json`**: 2 candidate findings, 0 confirmed.
- `F-29250`, command `nmap -p 8983 solr` (no `-sV`), title "Solr Port 8983 Exposed". `stdout` shows `8983/tcp open  unknown` — service was not identified by name in this scan. Verdict `unconfirmed`; `proof` is a repeat plain nmap scan, same "unknown" service.
- `F-31917`, command `nmap -p 8983 solr`, title "Solr Service Exposed". Verdict `unconfirmed`; `proof` truncated to `"Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-23 15:23 +0000\n"` with nothing further recorded.

Neither finding, nor any command recorded in this file, mentions Log4j, Log4Shell, or CVE-2021-44228.

### 4b. Blind (`--target target-b`)

**`argus-target-b-20260723-195732.json`**: 3 iterations, cumulative 4 confirmed findings across the run (1 in iter1, 1 in iter2, 2 in iter3), all titled "Apache Solr Default Credentials".

- Discovery command in every iteration: `nmap -sV -p- target-b`. Real output:
  ```
  5005/tcp open  jdwp    Java Debug Wire Protocol (Reference Implementation) version 1.8 1.8.0_102
  8983/tcp open  http    Apache Solr
  ```
  "Apache Solr" is identified here from the HTTP service banner nmap's version-detection probe retrieved — again a real protocol disclosure, not a hostname artifact.
- Validation evidence was substantive in this run:
  - Iterations 1–2 (`F-37700`, `F-71709`): `proof` is a real, well-formed JSON response from Solr's own status API (`responseHeader`, `status.demo.instanceDir`, `index.numDocs`, etc.) — i.e., a real unauthenticated API call succeeded.
  - Iteration 3 (`F-09907`, `F-23722`): `proof` is the raw HTML of Solr's Admin UI login-free landing page (`<title>Solr Admin</title>`, embedded Angular app markup) — again real, unauthenticated access to a live admin interface.
- **No finding, in any of the 3 iterations, named Log4j, Log4Shell, or CVE-2021-44228.** The vulnerability this Vulhub image specifically demonstrates was not discovered; a different, genuine issue (no authentication on the Solr instance) was found and repeatedly confirmed with strong evidence instead.
- Notable data quality issue: `F-09907` (iteration 3) has `"remediation": ""` — the advisor model (`qwen3.5:9b`) returned an empty completion for that finding, yet `patch_status` is `"applied"`. `PatchProposalStage.run()` does not check for an empty/failed generation before setting `patch_status = PROPOSED`, and the CLI's interactive authorizer does not block on empty remediation content.
- All `resolved_after_patch` values across all 3 iterations are `false` — consistent with no `patch_applier` being configured; nothing was ever expected to resolve.

### 4c. Solr summary of directly observed facts
- Both hinted and blind runs identified an open port; only the blind run's discovery command (`-sV -p-`, a fuller scan) actually retrieved the "Apache Solr" service string. The hinted run's narrower `-p 8983` (no version flag) scan did not.
- The blind run produced strong, real, repeatable proof of a genuine vulnerability (fully unauthenticated Solr admin access) — this is not the CVE the lab targets, but it is a real, correctly-verified finding.
- In neither condition did Discovery or Validation ever reference Log4j/Log4Shell/CVE-2021-44228 by name, run a JNDI-related payload, or otherwise attempt to detect or trigger the specific vulnerability this Vulhub environment is built around.

---

## 5. Drupal / Drupalgeddon2 (Vulhub `drupal/CVE-2018-7600`, real issue: CVE-2018-7600)

### 5a. Hinted (`--target drupal`)

**`argus-drupal-20260723-154356.json`**: 3 iterations, 2 confirmed findings per iteration (6 total across the run), all titled "Drupal Installation Page Exposed", description in every instance: *"The Drupal installation page is exposed at /core/install.php, which may indicate a misconfigured or unpatched installation."*

- Discovery command, every iteration: `nmap -p 80,443 --script "http-title,http-robots.txt" drupal` (iteration 1's recon-phase command additionally used `--script=http-title,http-robots.txt` with an `=` rather than a space — a minor syntactic variant, functionally equivalent). Real output every time included:
  ```
  | http-title: Choose language | Drupal
  |_Requested resource was /core/install.php
  ```
  "Drupal" appears here because nmap's `http-title` script retrieved the page's actual HTML `<title>` tag — real content returned by the server, not sourced from the hostname.
- Validation evidence in every instance: a real HTTP response with `Server: Apache/2.4.25 (Debian)` and `X-Powered-By: PHP/7.2.3` headers, `200 OK`. All 6 findings were judged `confirmed`.
- All 6 were authorized and `patch_status: "applied"`; all 6 show `"resolved_after_patch": false`.
- **No finding, in any of the 3 iterations, named Drupalgeddon2 or CVE-2018-7600.** The real, specific vulnerability (a REST/AJAX-triggered PHP object-injection RCE) was not discovered; the genuinely-present but distinct issue of an exposed, unblocked installer page was found and repeatedly confirmed instead.
- The remediation text proposed across the 6 findings is entirely about blocking `/core/install.php` at the web-server level, upgrading PHP 7.2.3 (EOL), and upgrading Drupal core generally — sound advice for the issue actually found, not remediation specific to CVE-2018-7600.

### 5b. Blind (`--target target-c`)

**`argus-target-c-20260723-200050.json`**: 2 candidate findings, 0 confirmed.
- `F-07416`, command `nmap -sV -p- target-c`, title "Apache HTTP Server Default Version Exposed", description: *"The Apache HTTP Server version 2.4.25 is exposed, which may be vulnerable to known exploits."* Real nmap output: `80/tcp open  http    Apache httpd 2.4.25 ((Debian))`. Verdict `unconfirmed`. **However, the recorded `proof` is not weak — it contains a real HTTP response with an explicit redirect:**
  ```
  HTTP/1.1 302 Found
  Server: Apache/2.4.25 (Debian)
  X-Powered-By: PHP/7.2.3
  Location: /core/install.php
  ```
  The verification step independently and correctly located the `/core/install.php` redirect — the same real signal the hinted run's Discovery step keyed on — despite the target being an opaque, non-suggestive name. The judge nonetheless returned `unconfirmed`, which is only explainable by the judge evaluating the evidence against the finding's own stated claim ("Apache version exposed") rather than the (more specific and arguably more significant) installer-redirect fact the evidence actually contains. `PatchProposalStage` was never reached since the finding was not confirmed, so `remediation` is empty.
- `F-17189`, same command, same title, description near-identical (minor wording variant). `proof` again shows the same `302 Found` / `Location: /core/install.php` response. Verdict `unconfirmed`, same reasoning gap as above.

### 5c. Drupal summary of directly observed facts
- Under the hinted name, Discovery's own command (`--script http-title`) surfaced the phrase "Drupal" from a real HTTP title tag — a genuine signal, not fabricated from the hostname `drupal`.
- Under the blind name, Discovery did not use a script that would surface "Drupal" by name (its command was a generic `-sV -p-` scan), so its finding was framed generically ("Apache HTTP Server..."). Independently, Validation's own probe (not Discovery's) still discovered the specific `/core/install.php` redirect purely by actively requesting it — real, target-derived evidence, entirely independent of the hostname.
- In the blind condition, this genuine and specific evidence was judged `unconfirmed`, apparently because it did not literally match the wording of the original (generic) finding — a data point about a rigidity/mismatch in the interpret→verify→judge pipeline, not about the model's ability to find real evidence.
- Neither condition ever named Drupalgeddon2 / CVE-2018-7600, nor did Discovery or Validation attempt the specific unauthenticated REST/AJAX request that constitutes the actual exploit for this CVE.
- The hinted run confirmed and "patched" (authorization-only, no real mutation) 6 times across 3 iterations without ever resolving anything, for the reasons given in §3 (no `patch_applier`, fragile title-matching).

---

## 6. Struts2 / S2-045 (Vulhub `struts2/s2-045`, real issue: CVE-2017-5638)

### 6a. Hinted (`--target struts2`)

**`argus-struts2-20260723-154705.json`**: 1 candidate finding, 0 confirmed.
- `F-13718`, command `nmap -p 80,443 --script=http-title,http-robots.txt,struts-stomp-detect struts2`, title "Struts2 Detection", description: *"The target host is running Struts2, which is a known vulnerable framework."*
  - **The command's own recorded `stdout` is: `"Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-23 15:46 +0000\n"` — nothing else.** The command's recorded `stderr` shows the scan failed outright:
    ```
    NSE: failed to initialize the script engine:
    /usr/share/nmap/nse_main.lua:829: 'struts-stomp-detect' did not match a category, filename, or directory
    ...
    QUITTING!
    ```
    `exit_code: 1`. The scan also targeted ports 80/443 — the Vulhub Struts2 container listens on 8080, so even a successful scan of those ports would not have reached the service.
  - `DiscoveryStage._interpret` only receives `cmd.stdout` (not `stderr`), so the model that produced the "Struts2 Detection" finding was given only the single startup-banner line above — no port table, no service name, no HTTP response, nothing that could name "Struts2." **The finding's title and description have no traceable source in the tool output provided to the model.** The only remaining candidate source for the word "Struts2" in the finding is the literal target string `struts2` passed to the model as part of the interpretation/discovery prompt context.
  - Verdict: `unconfirmed`; `proof`: `""` (empty string) — Validation could not produce any confirming evidence either, which is why this did not propagate as a false positive to Patch Proposal.

This is the single finding that prompted the decision to rename all four Vulhub services to opaque labels, since it is the clearest directly-evidenced instance in this dataset of a finding's content being explainable only by the target's name rather than by any tool output.

### 6b. Blind (`--target target-d`, run twice)

**`argus-target-d-20260723-200251.json`** and **`argus-target-d-20260723-200447.json`** (identical structure, run consecutively): 2 candidate findings each, 0 confirmed in both runs.
- Both findings in both runs are titled "Jetty Server Exposed with No Authentication", description: *"The Jetty server on port 8080 is exposed without any evidence of authentication being required or enabled."*
- Command in all four instances: `nmap -sV -p- target-d`. Real output: `8080/tcp open  http    Jetty 9.2.11.v20150529` — the Vulhub Struts2 image's actual underlying servlet container (Jetty), correctly identified by version.
- **"Struts2" does not appear anywhere in either blind run's findings, commands, or output.** Only the real underlying server component (Jetty) that nmap could actually detect was named.
- Verdict `unconfirmed` in all 4 findings (2 findings × 2 runs); `proof` in all 4 cases is limited to `"Starting Nmap 7.99 ( https://nmap.org ) at [timestamp]\n"` with nothing further — i.e., Validation's own check produced no additional evidence beyond the startup banner in every instance, and the two repeat runs produced byte-for-byte identical outcomes.

### 6c. Struts2 summary of directly observed facts
- The hinted run's fabricated "Struts2 Detection" finding is the clearest, most directly documented instance in this entire dataset of a finding attributable to the target's name rather than to tool-derived evidence: the recorded stdout given to the interpretation step contains no information about Struts2, and the scan that was supposed to produce that information failed before producing any.
- Removing the hint (rebuilding the same target as `target-d`) eliminated the fabrication entirely, across two independent runs: the model reported only what it could actually detect (Jetty, not Struts2), and — critically — did not fabricate a "Jetty is vulnerable" claim either, despite Jetty also being a real, name-bearing piece of software it could have latched onto the same way.
- Validation never produced strong evidence for this target in either condition; 0 findings were ever confirmed for Struts2/`target-d` in this dataset.
- No run, hinted or blind, ever referenced S2-045, CVE-2017-5638, the Jakarta Multipart parser, or attempted the actual exploit (a crafted `Content-Type` header) this Vulhub image demonstrates.

---

## 7. Cross-cutting observations (directly evidenced across all four targets)

1. **The hostname-leak fabrication was demonstrated exactly once, for Struts2, and did not recur for the other three targets' hinted runs.** Redis, Solr, and Drupal's hinted findings were all traceable to real tool output (a version banner, an HTTP title, robots.txt content) that happened to also match the hostname — meaning the hostname and the genuine evidence were confounded in those three cases, not that fabrication was proven for them. Struts2 is the only case in this dataset where the tool output was independently confirmed to contain no relevant information, isolating the hostname as the only remaining source.
2. **In every one of the four vulnerabilities, both hinted and blind, the model never discovered or attempted the specific CVE the Vulhub image is built to demonstrate** (Log4Shell, Drupalgeddon2, S2-045) or the specific unauthenticated-access exploit path for Redis beyond noting the port was open. In all cases it instead found a real but different/shallower issue: an open port, a missing-auth admin panel, an exposed installer page, or a version banner.
3. **Validation's judge step (`ValidationStage._judge`) does not apply a consistent evidence bar.** Within the same dataset: a bare "port open" proof was judged sufficient to confirm a Redis finding in one run (`F-26776`) and insufficient in another (Redis run 5, iteration 2; the blind Redis run); a genuine, specific installer-redirect proof was judged insufficient for a Drupal finding whose original claim was more generic (`target-c`, both findings).
4. **No `patch_applier` was configured for any run in this session.** Every `patch_status: "applied"` in every report reflects only that a human answered "y" to the interactive authorization prompt — no configuration file, package, or setting was ever actually changed on any of the four containers.
5. **`RescanStage` matches prior findings to fresh-scan findings by exact lowercased title string.** The one `resolved_after_patch: true` result in this entire dataset (`F-11960`, Redis, hinted run 4, iteration 2) occurred with no `patch_applier` configured, meaning nothing on the container could have changed — this result is attributable to title-matching behavior on a non-deterministic model output, not to genuine remediation.
6. **`PatchProposalStage` does not guard against an empty advisor response.** One instance (`F-09907`, Solr blind run, iteration 3) shows `remediation: ""` while still reaching `patch_status: "applied"`.
7. **The exact command `ValidationStage` used to produce a given `proof` is not persisted in the data model** — only the resulting stdout is. Any claim in this report or elsewhere about *which tool* produced a given piece of verification evidence is inferred from the proof text's format (e.g., nmap NSE script output's `| scriptname:` prefix) and should be treated as inferred, not directly recorded.

---

## 8. What this data does not support

To avoid overstatement in any downstream write-up:
- This dataset does not establish that hostname hinting caused every hinted-run finding — only the Struts2 case has direct evidence (an empty/failed tool output) ruling out any other source. For Redis, Solr, and Drupal, the hinted runs' findings had genuine corroborating tool output that was independent of (if coincidentally identical to) the hostname.
- This dataset does not establish a general rate of hallucination for `llama3:8b` or `qwen3.5:9b` — sample sizes per condition are small (1–3 runs per target per condition) and were not run with controlled repetition beyond the two Struts2 (blind) and two Redis (hinted) repeats noted above.
- This dataset does not demonstrate successful automated remediation-verification (the "Re-scan" half of Argus-AI's four-stage loop) under any condition, for the structural reason given in observation 4 above (no `patch_applier` was ever wired up).

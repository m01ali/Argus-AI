# Argus-AI DVWA Lab — Setup & Run Guide

A fully dockerised target built from **DVWA** (Damn Vulnerable Web Application,
`vulnerables/web-dvwa`), set up the same way as the sibling
[`vulhub-lab/`](../vulhub-lab/README.md) and
[`metasploitable-lab/`](../metasploitable-lab/README.md): one isolated Docker
network, one Kali scanner/attacker container, and the LLM backend (Ollama)
running on your host. Drive it with Argus-AI, or shell into the Kali box and
point gemini-cli / `sgpt` / `sqlmap` / `nikto` at the target by hand.

**Cold-start checklist only?** Jump to [Section 3](#3-cold-start-after-a-reboot-already-set-up-before).
**First time on this machine?** Start at [Section 2](#2-fresh-setup-new-machine--first-time).

---

## 0. What this actually is

One DVWA container (`target-w`) + one Kali scanner container (`kali`), on one
isolated bridge network (`pentestlab`). The scanner attacks the target over that
network by service name. Ollama runs on your host (not in Docker); the scanner
reaches it at `http://host.docker.internal:11434`.

```
                    +-------------------------------------+
                    |        pentestlab (bridge net)      |
   host:8084 -------+--> target-w  (vulnerables/web-dvwa) |
                    |      PHP/MySQL web app on :80        |
                    |        ^                            |
                    |        | sqlmap/nikto/hydra/curl    |
                    |      kali  (runs argus.cli / by hand)
                    +--------+----------------------------+
                             | http://host.docker.internal:11434
                             v
                    Ollama (llama3:8b, qwen3.5:9b) - on the HOST
```

### How this differs from the other labs

| | Vulhub | Metasploitable | This lab |
|---|---|---|---|
| Target | 4 boxes, 1 CVE each | 1 box, dozens of network vulns | 1 web app |
| Name | `target-a..d` | `target-m` | `target-w` |
| Surface | network services | network services | **web, behind a login** |
| Gotcha | — | some services don't start in Docker | needs DB init + auth + level cookie |

**The important difference:** almost nothing in DVWA is exploitable until you
(a) initialise its database once, (b) log in (`admin` / `password`), and (c) set
a *security level* (`low` -> `impossible`). A blind network scanner sees only a
login page. So this lab is best driven by tooling that can authenticate and hold
a session — sqlmap with a cookie, hydra against the login, or an LLM agent you
give the credentials to. See [Section 5](#5-attacking-dvwa-auth-level-and-tools).

**Why the target is `target-w`, not `dvwa`:** a service named after itself leaks
the answer — Docker's reverse-DNS record (built from the service name) shows up
in scans. The real mapping and module list live in
[`../report/dvwa-legend-PRIVATE.md`](../report/dvwa-legend-PRIVATE.md) — that
file is for *your* bookkeeping only and must never be read by, or referenced
from, anything the scanner runs. (DVWA's own page titles still say "DVWA", so a
scanner reading page content can still fingerprint it — that banner leak is
inherent to the app; the opaque name only removes the free rDNS giveaway.)

---

## 1. Prerequisites (any machine)

- **Docker Desktop** (with the `docker compose` plugin — bundled by default)
- **Ollama**, installed locally: <https://ollama.com> (only if you drive it with
  Argus-AI or a local model)
- ~1.5GB free disk for the DVWA image, ~1.5GB for the Kali scanner image (the
  Kali image is cache-shared with the other labs, so it builds in seconds if you
  already built one of them)

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

(Skip if you only drive DVWA by hand with sqlmap/nikto.) Ollama binds
`127.0.0.1` only by default. On Docker Desktop, `host.docker.internal` still
reaches it through Docker's host proxy, but the more robust setup is to rebind
to `0.0.0.0`:

```powershell
# Windows — persistent (recommended):
#   Settings > System > About > Advanced system settings > Environment
#   Variables > New (User variable): OLLAMA_HOST = 0.0.0.0
#   Then launch Ollama normally from the Start Menu.
# Or temporary, this session only (keep the terminal open):
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve
```
Verify it is up before running (avoids the startup race that looks like a
"connection refused" / "timed out"):
```powershell
netstat -an | findstr 11434
```

### 2.3 Pull the models (only if using Argus-AI)

```bash
ollama pull llama3:8b
ollama pull qwen3.5:9b
```

### 2.4 Build and start the lab

```bash
cd dvwa-lab
docker compose up -d --build
docker compose ps
```
Expect 2 services `Up`: `target-w` and `kali`.

### 2.5 Initialise the DVWA database (one time)

The `vulnerables/web-dvwa` image ships without its database created — you have
to run *Create / Reset Database* once. Do it headless from the kali container:

```bash
docker compose exec kali bash -c '
  # wait for Apache to answer
  until curl -s -o /dev/null http://target-w/login.php; do sleep 2; done
  # grab the CSRF user_token setup.php expects, then POST the DB-create
  jar=$(mktemp)
  tok=$(curl -s -c "$jar" http://target-w/setup.php | grep -oP "user_token'"'"' value='"'"'\K[0-9a-f]+")
  curl -s -b "$jar" -c "$jar" -d "create_db=Create+/+Reset+Database&user_token=${tok}" \
       http://target-w/setup.php -o /dev/null -w "setup.php HTTP %{http_code}\n"
'
```
(If the token grep comes back empty on your image build, the create still works
without it — DVWA only enforces the token on some versions.) You can also just
browse <http://127.0.0.1:8084/setup.php> from the host and click the button.

### 2.6 Confirm the app is up and the DB is initialised

```bash
docker compose exec kali curl -s -o /dev/null -w "login.php -> HTTP %{http_code}\n" http://target-w/login.php
```
`HTTP 200` means Apache/PHP/MySQL are all up. Then log in at
<http://127.0.0.1:8084/> with `admin` / `password`.

### 2.7 (If using Argus-AI) verify the scanner can reach Ollama

```bash
docker compose exec kali curl -s http://host.docker.internal:11434/api/tags
```
Should print JSON listing your pulled models.

### 2.8 Run against the target

```bash
docker compose exec kali bash
# Argus (network-level recon — it will mostly see the login page):
python -m argus.cli --target target-w --authorize -v
# or drive the web vulns by hand — see Section 5.
```

You're set up. For every future session, jump to Section 3.

---

## 3. Cold start after a reboot (already set up before)

**1. Docker engine up?** `docker ps` (else start Docker Desktop, wait, retry).

**2. (Argus only) Ollama up and reachable?**
```powershell
netstat -an | findstr 11434
```
If nothing, start it (`$env:OLLAMA_HOST="0.0.0.0"; ollama serve`) and wait until
it answers before running — a run fired during Ollama's ~10s startup shows as
"connection refused" then "timed out".

**3. Bring the containers back up**
```bash
cd d:/Argus-AI/dvwa-lab
docker compose up -d
docker compose ps
```
The DB survives restarts (named volume `dvwa-db`), so you normally skip the
setup.php step. If login.php errors on the DB, re-run step 2.5.

**4. Confirm app + (Argus only) Ollama**
```bash
docker compose exec kali curl -s -o /dev/null -w "%{http_code}\n" http://target-w/login.php
docker compose exec kali curl -s http://host.docker.internal:11434/api/tags
```

**5. Run**
```bash
docker compose exec kali bash
python -m argus.cli --target target-w --authorize -v
```

---

## 4. Running Argus against the target

```bash
python -m argus.cli --target target-w --authorize -v
```
Argus's Discovery is network/recon-oriented (nmap/whatweb/nikto), so against
DVWA it will fingerprint the web server and surface the login page and any
obvious web-server issues, but it will **not** log in and walk the authenticated
SQLi/XSS/upload modules — those need a session. Treat Argus here as the
web-server recon pass; use the hands-on tooling in Section 5 for the app-layer
vulns. To run one local model end to end, pass both flags:
```bash
python -m argus.cli --target target-w --authorize -v \
  --executor-model qwen3.5:9b --advisor-model qwen3.5:9b
```

---

## 5. Attacking DVWA: auth, level, and tools

Everything below runs from inside the kali container (`docker compose exec kali
bash`) against hostname `target-w`. Default creds: `admin` / `password`.

**Get a real, logged-in session id into `$sid` (paste this whole block at the
kali container prompt — it substitutes the cookie for you, so there is nothing
to fill in by hand):**
```bash
jar=$(mktemp)
tok=$(curl -s -c "$jar" http://target-w/login.php | grep -oP "user_token' value='\K[0-9a-f]+")
curl -s -b "$jar" -c "$jar" \
     --data-urlencode username=admin --data-urlencode password=password \
     --data-urlencode "user_token=$tok" --data-urlencode Login=Login \
     http://target-w/login.php -o /dev/null
sid=$(grep -oP 'PHPSESSID\t\K\S+' "$jar")
echo "authenticated PHPSESSID=$sid"
```

> **Do not** copy a `PHPSESSID=<id>` literally from any example — an unauthenticated
> cookie makes DVWA 302-redirect every request to `login.php`, and the tool then
> reports "not injectable". Always use the real `$sid` captured above (or a
> PHPSESSID you copied from your logged-in browser's dev tools).

**Then, in the same shell (so `$sid` is set), for example:**

| Tool | Example against DVWA |
|---|---|
| `sqlmap` | `sqlmap -u "http://target-w/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=$sid; security=low" --batch --flush-session --dbs` |
| `hydra` | `hydra -l admin -P /usr/share/wordlists/rockyou.txt target-w http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"` |
| `nikto` | `nikto -h http://target-w/` |
| `whatweb` | `whatweb http://target-w/` |
| `gobuster` | `gobuster dir -u http://target-w/ -w /usr/share/wordlists/dirb/common.txt` |
| `curl` | command-injection / XSS probes against `/vulnerabilities/exec/`, `/vulnerabilities/xss_r/`, etc. |

The Kali image already carries `sqlmap`, `nikto`, `whatweb`, `gobuster`,
`hydra`, `curl`, and `mysql` (to query the DB you reach through a SQLi). Point
your own LLM-driven tooling (gemini-cli, sgpt) at `http://target-w/` with the
cookie above.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `login.php` returns 200 but every module says "database error" | DB never created | Run the setup.php create (Section 2.5), or browse `/setup.php` and click the button |
| setup.php create seems to do nothing | CSRF `user_token` required on this build and wasn't sent | Use the token-grabbing one-liner in 2.5, or do it in a browser |
| SQLi/XSS pages redirect to `login.php` | no session / not logged in | Get an authenticated cookie first (Section 5) and pass it to the tool |
| A module still isn't vulnerable | `security` level too high | Set it to `low` via `/security.php` or the `security=low` cookie |
| `Cannot reach Ollama at host.docker.internal:11434` | Ollama not up yet, or bound `127.0.0.1` and proxy still warming | Start Ollama, wait until `/api/tags` answers, then run |
| Host port 8084 already in use | another service owns it | Change the left side of the `ports:` mapping in `docker-compose.yml` |

---

## 7. Resetting the target

Undo any runtime changes / get a clean database:
```bash
docker compose down -v      # -v drops the dvwa-db volume too
docker compose up -d
# then re-run the setup.php create (Section 2.5)
```
Restart without wiping the DB:
```bash
docker compose restart target-w
```

---

## 8. Scope reminder

DVWA is intentionally vulnerable and isolated on its own bridge network with the
host port bound to `127.0.0.1` only. **Do not** expose this stack on a shared
network or the internet. Argus-AI's `--authorize` gate still applies: you are
authorising yourself, as the owner of this lab, to test this container.

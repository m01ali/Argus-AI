# Argus-AI Metasploitable Lab — Setup & Run Guide

A fully dockerised target range built from the classic **Metasploitable 2**
box (`tleemcjr/metasploitable2`), set up the same way as the sibling
[`vulhub-lab/`](../vulhub-lab/README.md): one isolated Docker network, one
Kali scanner/attacker container, and the LLM backend (Ollama) running on your
host. You can drive it with Argus-AI, or shell into the Kali box and point
gemini-cli / `sgpt` / `msfconsole` at the target by hand.

**Cold-start checklist only?** Jump to [Section 3](#3-cold-start-after-a-reboot-already-set-up-before).
**First time on this machine?** Start at [Section 2](#2-fresh-setup-new-machine--first-time).

---

## 0. What this actually is

One Metasploitable 2 container (`target-m`) + one Kali scanner container
(`kali`), on one isolated bridge network (`pentestlab`). The scanner attacks
the target over that network by service name. Ollama runs on your host (not in
Docker); the scanner reaches it at `http://host.docker.internal:11434`.

```
                    +-------------------------------------+
                    |        pentestlab (bridge net)      |
  host:2221/2/3 ----+--> target-m  (tleemcjr/metasploitable2)
  host:8083/8180 ---+-->   one box, dozens of vulns
  host:13306/15432 -+-->   (vsftpd/samba/tomcat/mysql/...)
                    |        ^                            |
                    |        | nmap/nikto/hydra/msf/etc.  |
                    |      kali  (runs argus.cli / by hand)
                    +--------+----------------------------+
                             | http://host.docker.internal:11434
                             v
                    Ollama (llama3:8b, qwen3.5:9b) - on the HOST
```

### How this differs from the Vulhub lab

| | Vulhub lab | This lab |
|---|---|---|
| Targets | 4 containers, **1 CVE each** | 1 container, **dozens of vulns** |
| Names | `target-a` ... `target-d` | `target-m` |
| Remediation | clean per-CVE fix | mostly "the whole box is EOL" |
| Good for | testing a clean Discover->Patch->Re-scan loop | broad Discovery / recon breadth |

**Why the target is `target-m`, not `metasploitable`:** a service literally
named after itself leaks the answer to the model — Docker's embedded DNS
attaches a reverse-DNS record built from the service name, and `nmap` prints it
unprompted. The real mapping (and the port-by-port vuln list) lives in
[`../report/metasploitable-legend-PRIVATE.md`](../report/metasploitable-legend-PRIVATE.md)
— that file is for *your* bookkeeping only and must never be read by, or
referenced from, anything the scanner runs.

---

## 1. Prerequisites (any machine)

- **Docker Desktop** (with the `docker compose` plugin — bundled by default)
- **Ollama**, installed locally: <https://ollama.com> (only if you drive it with
  Argus-AI or a local model; not needed for a hand-driven msfconsole session)
- ~3GB free disk for the Metasploitable image, ~1.5GB for the Kali scanner image
- Enough VRAM/RAM to run one ~5-7GB local model at a time (same envelope as the
  Vulhub lab)

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

(Skip if you only plan to drive the box by hand with msfconsole.) Ollama binds
`127.0.0.1` only by default, invisible to Docker. Rebind it to `0.0.0.0`:

```powershell
# Windows — pick ONE:

# Option A: persistent (recommended)
#   Settings > System > About > Advanced system settings > Environment
#   Variables > New (User variable): OLLAMA_HOST = 0.0.0.0
#   Then launch Ollama normally from the Start Menu.

# Option B: temporary, this session only — keep this terminal open:
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve
```
Verify:
```powershell
netstat -an | findstr 11434
```
You must see `0.0.0.0:11434 LISTENING`, not `127.0.0.1:11434`.

### 2.3 Pull the models (only if using Argus-AI)

```bash
ollama pull llama3:8b
ollama pull qwen3.5:9b
```

### 2.4 Build and start the lab

```bash
cd metasploitable-lab
docker compose up -d --build
docker compose ps
```
Expect 2 services `Up`: `target-m` and `kali`. The Metasploitable image is
large (~3GB) so the first `up` pulls for a while; the Kali image build takes a
few minutes the first time, then is cached.

### 2.5 Confirm the target's services actually came up

The Metasploitable image does **not** auto-start its services — the compose
`command` runs `/bin/services.sh` for you. Confirm the classic ports answer:

```bash
docker compose exec kali nmap -sV -Pn -p21,22,23,80,139,445,3306,6667,8180 target-m
```
You should see vsftpd, OpenSSH, telnet, Apache, Samba, MySQL, UnrealIRCd,
Tomcat, etc. If ports are closed, give the container another ~15s (services.sh
is still starting) and re-scan; a full restart is `docker compose restart
target-m`.

### 2.6 (If using Argus-AI) verify the scanner can reach Ollama

```bash
docker compose exec kali curl -s http://host.docker.internal:11434/api/tags
```
Should print JSON listing your pulled models. If it errors or is empty, go back
to 2.2 — don't proceed until this returns real JSON.

### 2.7 Run against the target

**With Argus-AI:**
```bash
docker compose exec kali bash
python -m argus.cli --target target-m --authorize -v
```

**By hand (gemini-cli / sgpt / msfconsole / raw tools):**
```bash
docker compose exec kali bash
# then, inside the container, e.g.:
nmap -sV -Pn target-m
hydra -l msfadmin -p msfadmin target-m ftp
# or point your own LLM-driven tooling at the hostname "target-m"
```
Reports from Argus land in `../argus-reports/` (bind-mounted — visible on the
host too).

You're set up. For every future session, jump to Section 3.

---

## 3. Cold start after a reboot (already set up before)

Run each step's verification before moving on — don't assume a step worked.

**1. Docker engine up?**
```powershell
docker ps
```
If it errors, launch Docker Desktop, wait, retry.

**2. (Argus only) Ollama bound to 0.0.0.0?**
```powershell
netstat -an | findstr 11434
```
- `0.0.0.0:11434 LISTENING` -> good, skip to step 3.
- Nothing -> Ollama isn't running:
  ```powershell
  $env:OLLAMA_HOST = "0.0.0.0"
  ollama serve
  ```
  (leave that terminal open; use a **new** terminal below)
- Only `127.0.0.1:11434` -> quit Ollama (tray -> Quit), then apply the fix above.

**3. Bring the containers back up**
```bash
cd d:/Argus-AI/metasploitable-lab
docker compose up -d
docker compose ps
```
No `--build` needed unless the Dockerfile changed. Confirm both services `Up`.

**4. Confirm target services are live**
```bash
docker compose exec kali nmap -sV -Pn -p21,80,445,3306,6667 target-m
```

**5. (Argus only) verify Ollama reachability**
```bash
docker compose exec kali curl -s http://host.docker.internal:11434/api/tags
```

**6. Run**
```bash
docker compose exec kali bash
python -m argus.cli --target target-m --authorize -v
```

---

## 4. Running against the target

Argus-AI takes a single `--target`; point it at `target-m`:
```bash
python -m argus.cli --target target-m --authorize -v
```
`-v` gives INFO-level progress logging; drop it for quiet output. `--dry-run`
generates commands without executing them. To run a specific local model end to
end (both roles), pass both flags — see the models section in
[`../how to run.txt`](../how%20to%20run.txt):
```bash
python -m argus.cli --target target-m --authorize -v \
  --executor-model qwen3.5:9b --advisor-model qwen3.5:9b
```

Because Metasploitable is one host with many independent services, a single
Discovery run surfaces a long list — treat the box as a breadth target rather
than the clean single-CVE loop the Vulhub lab gives you.

---

## 5. Handy attack surface (for hand-driven sessions)

The Kali scanner ships the protocol clients you need for the classic
Metasploitable services (all reachable at hostname `target-m`):

| Tool | Use against |
|---|---|
| `nmap` | full service/version sweep |
| `ftp` | vsftpd 2.3.4 backdoor probe |
| `smbclient`, `enum4linux` | Samba shares / `usermap_script` |
| `rpcinfo -p target-m`, `showmount -e target-m` | RPC / NFS exports |
| `mysql -h target-m -u root` | blank-root MySQL |
| `psql -h target-m -U postgres` | PostgreSQL |
| `snmpwalk`, `finger`, `telnet` | info leaks / cleartext services |
| `hydra` | credential testing (e.g. `msfadmin:msfadmin`) |
| `nikto`, `sqlmap`, `whatweb`, `gobuster` | the web apps on :80 (DVWA, Mutillidae, phpMyAdmin) |

Want the full Metasploit console in the box? It's not installed by default to
keep the image lean. Add `metasploit-framework` to `kali/Dockerfile`'s package
list and rebuild, or install it ad-hoc inside the running container.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `target-m` up but all ports closed | services.sh hadn't finished, or didn't run | Wait ~15s and re-scan; else `docker compose restart target-m`, or check `docker compose logs target-m` |
| Container `target-m` keeps exiting | the image's default CMD drops to a shell that exits without a TTY | Already handled — compose `command` runs services then `tail -f /dev/null` to hold it open |
| Host port bind fails on 139/445 | Windows already owns SMB/NetBIOS on the host | Already handled — those are remapped to `127.0.0.1:1139`/`1445`; the scanner uses the internal net regardless |
| Kali build fails mid `apt-get` on `searchsploit -u` | the apt exploitdb tree isn't a git checkout | Already handled — `searchsploit -u` is its own non-fatal `RUN` |
| `bash: python: command not found` in the container | `kali-rolling` ships only `python3` | Already handled — `python-is-python3` is in the Dockerfile |
| `Cannot reach Ollama at host.docker.internal:11434` | Ollama bound to `127.0.0.1` only | Set `OLLAMA_HOST=0.0.0.0` on the host, restart Ollama (Section 2.2 / 3) |
| Scan mentions "metasploitable" with weak evidence | rDNS/hostname leaked the answer | Keep the opaque `target-m` name; never rename the service after the box it runs |

---

## 7. Resetting the target

Metasploitable ships pre-vulnerable; recreating the container reverts any
runtime changes made during testing:

```bash
docker compose stop target-m && docker compose rm -f target-m && docker compose up -d target-m
```

Full reset (containers + network):
```bash
docker compose down -v
docker compose up -d --build
```

---

## 8. Scope reminder

This is an intentionally-vulnerable host, isolated on its own bridge network
with host ports bound to `127.0.0.1` only. **Do not** expose this compose stack
on a shared network or the internet — Metasploitable is trivially, remotely
rootable by design. Argus-AI's own `--authorize` gate still applies: you are
authorising yourself, as the owner of this lab, to test this container.

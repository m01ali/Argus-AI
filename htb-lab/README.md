# Argus-AI HTB Lab — MonitorsFour (Windows-native, no Docker)

Unlike the other three labs, this one has **no target container**. HackTheBox
hosts the machine; you reach it over their VPN. So the whole "host the
vulnerable target in Docker" half disappears — you only need a network path to
the box plus your tooling. Everything here runs **natively on Windows**: your
ollama / sgpt / Gemini CLI stay exactly where they are.

```
   Windows host
   ┌───────────────────────────────────────────────┐
   │  ollama (127.0.0.1:11434)  ← sgpt, argus       │
   │  Gemini CLI (cloud, needs Google auth)         │
   │  attack tools: curl, nmap, sqlmap              │
   │                     │                          │
   │            OpenVPN Connect  (tun to HTB)        │
   └─────────────────────┼──────────────────────────┘
                         │  10.10.x.x / 10.129.x.x  (split tunnel)
                         ▼
                MonitorsFour  (hosted on HackTheBox)
```

MonitorsFour is a **retired, easy Windows** Seasons machine (released
2025-12-06). Retired boxes need an **HTB VIP / VIP+** subscription to spawn.

---

## 0. The one gotcha you already hit: Windows Defender eats sqlmap

Defender flags offensive tools as malware. On this machine it quarantined
`sqlmap.py` as `HackTool:Python/SqlMap!AMTB` seconds after each download. Your
LLM tooling (ollama, sgpt, Gemini CLI) is **not** affected — only attack tools,
and sqlmap is the main one (nmap and curl are normally allowlisted).

**Fix — add a scoped Defender exclusion for the tools folder (one time, needs
admin).** Open **PowerShell as Administrator** and run:

```powershell
Add-MpPreference -ExclusionPath "D:\Argus-AI\tools"
```

That excludes only the dedicated tools directory, nothing else. If you would
rather not exclude anything, run the offensive tools in **WSL2** instead (Kali
or Ubuntu) — Defender doesn't scan inside the WSL2 disk, and everything below
works the same there. This guide assumes the exclusion route since you chose
Windows-native.

---

## 1. What's already set up on this machine

Done during setup — you don't need to redo these:

| Piece | State |
|---|---|
| ollama + models (llama3:8b, qwen3.5:9b, redsage-8b-dpo) | installed, running on `127.0.0.1:11434` |
| sgpt (ShellGPT 1.5.1) wired to local ollama | installed in `.venv`, config at `C:\Users\user\.config\shell_gpt\.sgptrc` |
| Gemini CLI (`@google/gemini-cli`) | installed globally via npm (needs Google auth, step 2.4) |
| curl | native to Windows |

Still to install: **nmap**, **OpenVPN Connect**, and **sqlmap** (after the
Defender exclusion). See step 2.

---

## 2. One-time installs

### 2.1 Defender exclusion (admin) — do this first, or sqlmap keeps vanishing
```powershell
Add-MpPreference -ExclusionPath "D:\Argus-AI\tools"
```

### 2.2 nmap + OpenVPN Connect (winget; each pops a UAC / driver prompt)
```powershell
winget install --id Insecure.Nmap -e
winget install --id OpenVPNTechnologies.OpenVPNConnect -e
```
nmap pulls in the Npcap driver; accept its prompt. Open a **new** terminal
afterward so `nmap` is on PATH.

### 2.3 sqlmap (official git clone — the PyPI package is broken on Windows)
Run **after** the exclusion in 2.1, or Defender will delete `sqlmap.py`:
```powershell
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git D:\Argus-AI\tools\sqlmap
D:\Argus-AI\.venv\Scripts\python.exe D:\Argus-AI\tools\sqlmap\sqlmap.py --version
```
For convenience, add a function to your PowerShell profile
(`notepad $PROFILE`):
```powershell
function sqlmap { & "D:\Argus-AI\.venv\Scripts\python.exe" "D:\Argus-AI\tools\sqlmap\sqlmap.py" @args }
```

### 2.4 Gemini CLI auth (cloud — works alongside the VPN, split tunnel)
```powershell
gemini
```
On first run it walks you through Google sign-in (or set `GEMINI_API_KEY`). The
HTB VPN is split-tunnel (only routes `10.x.x.x`), so Gemini's cloud calls keep
working while you're connected.

---

## 3. Connect to the HTB VPN (detailed)

Two things must BOTH be true to reach the box: you're connected to a **VIP**
VPN server, and the machine is **spawned**. Retired machines only live on VIP
infrastructure — a **Free** server will not reach MonitorsFour even with the
right IP.

### 3A. Download your VPN config (`.ovpn`)
1. Log in at <https://www.hackthebox.com> (you land on the dashboard at
   app.hackthebox.com).
2. Top-right, next to your avatar, click **Connect to HTB**.
3. Choose the **Machines** / **Labs** product (regular retired machines live
   here — not Starting Point, not Pro Labs).
4. In the server dropdown pick a **VIP** (or VIP+) server near you. **Not** a
   Free server.
5. Click **Download VPN** / **Download Connection Pack** → you get
   `lab_<username>.ovpn`.
6. Move that file into `D:\Argus-AI\htb-lab\vpn\` (gitignored, so your key is
   never committed).

### 3B. Import + connect in OpenVPN Connect
1. Open **OpenVPN Connect**.
2. **+** / **Import Profile** → the **UPLOAD FILE** tab (not URL).
3. Browse to `D:\Argus-AI\htb-lab\vpn\lab_<username>.ovpn` → **Add**.
4. Toggle the profile **on**. If it warns about compression or an unused
   option, accept — HTB profiles still connect.
5. Connected = status shows **Connected** (CLI equivalent: "Initialization
   Sequence Completed").

### 3C. Spawn MonitorsFour and get its IP
1. On the HTB site: **Machines** → search **MonitorsFour** → open it.
2. **Spawn Machine** / **Start Machine** (needs VIP). After ~30-60s it shows the
   machine **IP**, e.g. `10.10.11.xx`.

### 3D. Verify reachability (PowerShell, no nmap needed yet)
```powershell
$t = "10.10.11.XX"          # the IP HTB showed
Test-NetConnection $t -Port 80
```
`TcpTestSucceeded : True` = tunnel + machine are live. Plain `ping` often fails
on Windows targets (they drop ICMP), so a failed ping does not mean you're
disconnected. If every port fails, check the tunnel got a 10.x address:
```powershell
ipconfig | findstr /i "10.10 10.129"
```
No 10.x adapter → the VPN didn't connect; re-check you picked a **VIP** server.

---

## 4. Get the target IP and confirm reachability

The machine's IP is on its HTB page (e.g. `10.10.11.xx` or `10.129.x.x`). Set
it once for the session:
```powershell
$t = "10.10.11.XX"   # <-- MonitorsFour's IP from HTB
ping $t
nmap -sV -Pn -T4 $t
```
Windows machines often drop ICMP; `-Pn` tells nmap to scan anyway. Expect HTTP
and typical Windows service ports.

---

## 5. Attack it — with your LLM tooling advising

Keep the actual commands pointed at the **IP**, and give the models the IP, not
the machine name — the name "MonitorsFour" is itself a hint (it telegraphs the
Cacti/monitoring theme), so feeding it to the model taints a blind run. This is
the same discipline as the opaque `target-a/m/w` names in the other labs.

**Ask a local model (via sgpt → ollama) what to do next:**
```powershell
sgpt "I scanned $t and found an Apache server exposing a REST API under /api. What are the first three enumeration steps? Keep it to commands."
# deeper reasoning model:
sgpt --model ollama/qwen3.5:9b "Given a Cacti instance behind a login, outline how to enumerate its version from HTTP responses."
```

**Ask Gemini (cloud) for the same, as a second opinion:**
```powershell
gemini -p "Outline an enumeration plan for a web host at $t exposing an API and a Cacti login. Commands only."
```

**Run what they suggest:**

| Tool | Example (point at `$t`) |
|---|---|
| `curl` | `curl -sk https://$t/ -i` — headers, redirects, API probing (does most of the work on this box) |
| `nmap` | `nmap -sV -Pn -T4 --top-ports 2000 $t` |
| `sqlmap` | `sqlmap -u "http://$t/<endpoint>?id=1" --batch --level 2 --risk 2` |
| browser | drive the web app / API and Cacti UI directly at `http://$t/` |

MonitorsFour is HTTP/API-centric, so `curl` plus a browser carries most of it;
sqlmap and nmap fill in. Argus can also run against it:
```powershell
D:\Argus-AI\.venv\Scripts\python.exe -m argus.cli --target $t --authorize -v
```
(Argus is network-recon oriented — it fingerprints the box; the app-layer work
is the hands-on tooling above.)

---

## 6. Teardown

Just disconnect in OpenVPN Connect, and stop the machine on the HTB page when
you're done (frees your spawn slot). Nothing runs locally to tear down.

---

## 7. Why there's no docker-compose here

There is nothing to containerise: the target is HackTheBox's, reached over VPN.
The previous labs used Docker to *host* a local vulnerable target; here HTB does
that. The only "environment" on your side is the VPN tunnel plus the tools in
section 1-2, all of which run natively. If you later want the isolation of a
container for the attack tools (to sidestep Defender without an exclusion), the
`metasploitable-lab/kali` image already has the full toolbox — run it with
`--cap-add=NET_ADMIN --device /dev/net/tun` and connect the `.ovpn` inside it.

---

## 8. Scope reminder

You are authorised to attack MonitorsFour because you spawned it on your own HTB
account — that is the platform's purpose. Keep the VPN and this tooling pointed
only at your spawned HTB targets. Don't point these tools at hosts you don't own
or aren't explicitly authorised to test.

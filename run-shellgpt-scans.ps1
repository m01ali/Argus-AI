<#
.SYNOPSIS
  One command: ShellGPT (sgpt) + local Ollama/llama scan DVWA, Metasploitable
  and HTB, find vulnerabilities, and write remediation advice into
  shellgpt-results/.

.DESCRIPTION
  Same idea as run-llama-scans.ps1, but the ANALYST is ShellGPT (`sgpt`) — every
  finding and every fix is written by sgpt talking to the LOCAL Ollama llama
  model. Nothing leaves the host.

  Because the scanning tools and the analyst live in different places, each lab
  runs in two phases (both handled by shellgpt-scan/shellgpt_scan.py):

    1. SCAN    — runs the fixed recon / proof-of-concept scans where the tools
                 and network access actually are:
                   * dvwa / metasploitable -> inside their Kali containers
                     (sqlmap, nc, smbclient, internal-net access). Raw output
                     lands in shellgpt-results/<lab>/ via the mounted repo.
                   * htb -> natively on this Windows host over the HTB VPN.
    2. ANALYZE — always on THIS host, where sgpt + its Ollama config live: each
                 raw scan is piped to `sgpt` with a dedicated, evidence-
                 constrained analyst role, producing NN-<name>.md findings and a
                 00-SUMMARY.md per lab.

  Results: shellgpt-results/<lab>/  (NN-<name>.txt raw + NN-<name>.md analysis +
  00-SUMMARY.md + manifest.json).

.EXAMPLE
  .\run-shellgpt-scans.ps1
      Run the Docker labs (dvwa, metasploitable). HTB is skipped unless a
      target IP is known (via -HtbTarget or htb-lab/target.txt).

  Two configs, mirroring run-llama-scans.ps1:
    (default)   scripted — fixed scans, then sgpt explains the results.
    -Agentic    sgpt chooses AND runs the commands itself, then writes findings
                (results in shellgpt-results/<lab>/agentic/).
    -Both       run scripted THEN agentic for every lab, in one invocation.

.EXAMPLE
  .\run-shellgpt-scans.ps1 -HtbTarget 10.129.109.234
      Run all three (scripted), HTB against that machine over the VPN.

.EXAMPLE
  .\run-shellgpt-scans.ps1 -Both
      Run both configs (scripted + agentic) for the Docker labs.

.EXAMPLE
  .\run-shellgpt-scans.ps1 -Agentic
      Agentic only — sgpt drives everything, start to finish.
#>
[CmdletBinding()]
param(
    [string[]] $Labs = @('dvwa', 'metasploitable', 'htb'),
    [string]   $HtbTarget = '',
    [string]   $Model = 'llama3:8b',            # Ollama tag; sgpt uses ollama/<tag>
    [string]   $OllamaHost = 'http://127.0.0.1:11434',
    [switch]   $Rebuild,        # force `docker compose up -d --build`
    [switch]   $SkipUp,         # assume the Docker labs are already up
    [switch]   $Agentic,        # let sgpt choose+run the commands (vs scripted)
    [switch]   $Both            # capture BOTH configs per lab in one run
)

# NOT 'Stop': docker/compose write normal progress to stderr, and under 'Stop'
# PowerShell 5.1 turns each such line into a fatal NativeCommandError. We gate
# every native call on $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'
$Root = $PSScriptRoot
Set-Location $Root
$Engine    = 'shellgpt-scan/shellgpt_scan.py'   # repo-relative; mounted in kali
$SgptModel = "ollama/$Model"

# Which config(s) to run this invocation. -Both runs scripted then agentic for
# every lab; otherwise it's one or the other.
#   scripted = fixed scans, sgpt explains the results afterwards
#   agentic  = sgpt chooses + runs the commands itself, then writes findings
if     ($Both)    { $Modes = @('scripted', 'agentic') }
elseif ($Agentic) { $Modes = @('agentic') }
else              { $Modes = @('scripted') }
$ModeBanner = ($Modes | ForEach-Object {
    if ($_ -eq 'scripted') { 'scripted scans + sgpt analyst' } else { 'AGENTIC (sgpt drives)' }
}) -join '  +  '

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red }

# Normalise -Labs: accept both -Labs a,b (array) and a single "a,b" string.
$Labs = @($Labs | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# --- Preflight: local Ollama up (the model lives here) ----------------------
Info "Checking local Ollama at $OllamaHost ..."
try {
    $tags = Invoke-RestMethod -Uri "$OllamaHost/api/tags" -TimeoutSec 5 -ErrorAction Stop
    $have = @($tags.models | ForEach-Object { $_.name })
    Ok ("Ollama up. Models: " + ($have -join ', '))
    if (($have -notcontains $Model) -and ($have -notcontains ($Model + ':latest'))) {
        Warn ("Model '" + $Model + "' not pulled. Run:  ollama pull " + $Model)
    }
} catch {
    Fail "Ollama not reachable at $OllamaHost."
    Warn 'Start it (new terminal):  $env:OLLAMA_HOST="0.0.0.0"; ollama serve'
    exit 1
}

# --- Preflight: sgpt available on this host (the analyst) -------------------
$sgptCmd = Get-Command sgpt -ErrorAction SilentlyContinue
if (-not $sgptCmd) {
    Fail "ShellGPT (sgpt) is not on PATH on this host."
    Warn 'Install it:  pip install "shell-gpt[litellm]"   (then re-run)'
    exit 1
}
Ok ("sgpt found: " + $sgptCmd.Source)
Info "Config: $ModeBanner"

$ResultsDir = Join-Path $Root 'shellgpt-results'
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
$ran = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]

# Analyze phase — always on THIS host, where sgpt + its config live.
function Invoke-Analyze($lab) {
    Info "${lab}: analysing raw scans with sgpt (model $SgptModel) ..."
    & python -u $Engine --lab $lab --phase analyze --sgpt-model $SgptModel
    if ($LASTEXITCODE -ne 0) { Fail "${lab}: sgpt analyze phase failed."; return $false }
    return $true
}

# --- Docker labs (dvwa / metasploitable): scan INSIDE the kali container ----
function Invoke-DockerLab($lab, $composeDir, $target, [scriptblock]$readyCheck) {
    $compose = Join-Path $Root ($composeDir + '/docker-compose.yml')
    if (-not (Test-Path $compose)) { Warn "${lab}: no compose file at $compose - skipping."; return $false }

    if (-not $SkipUp) {
        $buildArg = @(); if ($Rebuild) { $buildArg = @('--build') }
        Info "${lab}: bringing the lab up (docker compose up -d) - first run builds Kali, be patient ..."
        & docker compose -f $compose up -d @buildArg 2>&1 | ForEach-Object { Write-Host "    $_" }
        if ($LASTEXITCODE -ne 0) { Fail "${lab}: 'docker compose up' failed - is Docker Desktop running?"; return $false }
    }

    Info "${lab}: waiting for $target to answer ..."
    $up = $false
    for ($i = 0; $i -lt 45; $i++) {
        if (& $readyCheck $compose) { $up = $true; break }
        Start-Sleep -Seconds 3
    }
    if (-not $up) { Warn "${lab}: $target did not come up in time - skipping."; return $false }
    Ok "${lab}: $target is up."

    $anyOk = $false
    foreach ($mode in $Modes) {
        if ($mode -eq 'scripted') {
            # Scan inside kali (tools + internal-net access live there); raw output
            # is written to the mounted repo -> shows up in shellgpt-results/.
            Info "${lab}: [scripted] running scans inside the Kali container ..."
            & docker compose -f $compose exec -T kali python3 -u ("/opt/argus-ai/" + $Engine) --lab $lab --phase scan
            if ($LASTEXITCODE -ne 0) { Fail "${lab}: scan phase failed inside the container."; continue }
            # Analyze on the host with sgpt.
            if (Invoke-Analyze $lab) { $anyOk = $true }
        }
        else {
            # Agentic: sgpt drives from the host; each recon command runs INSIDE
            # the kali container via docker compose exec (tools + internal net).
            Info "${lab}: [AGENTIC] sgpt drives; commands run inside Kali via docker exec ..."
            & python -u $Engine --lab $lab --phase agentic --exec docker --compose $compose --container kali --sgpt-model $SgptModel
            if ($LASTEXITCODE -eq 0) { $anyOk = $true } else { Fail "${lab}: agentic phase failed." }
        }
    }
    return $anyOk
}

foreach ($lab in $Labs) {
    switch ($lab) {
        'dvwa' {
            $ready = {
                param($c)
                $code = (& docker compose -f $c exec -T kali curl -s -o /dev/null -w '%{http_code}' http://target-w/ 2>$null)
                return ($code -and ($code -ne '000'))
            }
            if (Invoke-DockerLab 'dvwa' 'dvwa-lab' 'target-w' $ready) { $ran.Add('dvwa') } else { $skipped.Add('dvwa') }
        }
        'metasploitable' {
            $ready = {
                param($c)
                & docker compose -f $c exec -T kali bash -c 'nc -w2 -z target-m 445' 2>$null | Out-Null
                return ($LASTEXITCODE -eq 0)
            }
            if (Invoke-DockerLab 'metasploitable' 'metasploitable-lab' 'target-m' $ready) { $ran.Add('metasploitable') } else { $skipped.Add('metasploitable') }
        }
        'htb' {
            $ip = $HtbTarget
            $tf = Join-Path $Root 'htb-lab/target.txt'
            if ((-not $ip) -and (Test-Path $tf)) { $ip = (Get-Content $tf -Raw).Trim() }
            if (-not $ip) {
                Warn "htb: no target IP. Spawn the box + connect the VPN, then rerun with -HtbTarget <ip> (or put the IP in htb-lab/target.txt). Skipping."
                $skipped.Add('htb'); continue
            }
            if ($HtbTarget) { Set-Content -Path $tf -Value $HtbTarget -Encoding utf8 }
            # HTB runs natively on this host over the VPN. No ICMP gate (nmap -Pn).
            $anyOk = $false
            foreach ($mode in $Modes) {
                if ($mode -eq 'scripted') {
                    Info "htb: [scripted] running scans natively against $ip over the VPN ..."
                    & python -u $Engine --lab htb --phase scan --target $ip
                    if ($LASTEXITCODE -ne 0) { Fail "htb: scan phase failed (VPN up? box spawned?)."; continue }
                    if (Invoke-Analyze 'htb') { $anyOk = $true }
                }
                else {
                    Info "htb: [AGENTIC] sgpt drives natively against $ip over the VPN ..."
                    & python -u $Engine --lab htb --phase agentic --target $ip --exec native --sgpt-model $SgptModel
                    if ($LASTEXITCODE -eq 0) { $anyOk = $true } else { Fail "htb: agentic phase failed." }
                }
            }
            if ($anyOk) { $ran.Add('htb') } else { $skipped.Add('htb') }
        }
        default { Warn ("unknown lab '" + $lab + "' - skipping."); $skipped.Add($lab) }
    }
}

# --- Wrap up ----------------------------------------------------------------
Write-Host ''
$scannedMsg = if ($ran.Count) { $ran -join ', ' } else { '(none)' }
Ok ("Scanned + analysed by sgpt: " + $scannedMsg)
if ($skipped.Count) { Warn ("Skipped: " + ($skipped -join ', ')) }
Info "Results are in: $ResultsDir"
Get-ChildItem $ResultsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $md = @(Get-ChildItem $_.FullName -Filter *.md -ErrorAction SilentlyContinue).Count
    $ag = if (Test-Path (Join-Path $_.FullName 'agentic')) { ' + agentic/' } else { '' }
    Write-Host ("    shellgpt-results/" + $_.Name + "/  (" + $md + " reports$ag)")
}

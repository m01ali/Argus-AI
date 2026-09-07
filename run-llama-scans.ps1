<#
.SYNOPSIS
  One command: Llama scans DVWA, Metasploitable and HTB, finds vulnerabilities,
  and writes remediation advice into llama-results/.

.DESCRIPTION
  Each lab runs in the context that actually works:
    * dvwa / metasploitable  -> inside their Kali containers (sqlmap, nc,
      smbclient, and full internal-network access live there). The container
      reaches Ollama at host.docker.internal:11434.
    * htb                    -> natively on this Windows host over the HTB VPN.
      Reaches Ollama at 127.0.0.1:11434. Needs the machine IP (dynamic per
      spawn) via -HtbTarget or htb-lab/target.txt; skipped if absent.

  All three call the same engine (llama-scan/llama_scan.py). Llama (llama3:8b by
  default) is the only analyst; nothing leaves the host. Results land in
  llama-results/<lab>/ as raw .txt scans + .md analyses + a 00-SUMMARY.md.

.EXAMPLE
  .\run-llama-scans.ps1
      Run the Docker labs (dvwa, metasploitable). HTB is skipped unless a
      target IP is known.

.EXAMPLE
  .\run-llama-scans.ps1 -HtbTarget 10.129.109.234
      Run all three, HTB against that machine over the VPN.
#>
[CmdletBinding()]
param(
    [string[]] $Labs = @('dvwa', 'metasploitable', 'htb'),
    [string]   $HtbTarget = '',
    [string]   $Model = 'llama3:8b',
    [string]   $OllamaHost = 'http://127.0.0.1:11434',
    [switch]   $Rebuild,      # force `docker compose up -d --build`
    [switch]   $SkipUp,       # assume the Docker labs are already up
    [switch]   $Agentic,      # let Llama choose+run the commands (vs scripted)
    [switch]   $Both          # capture BOTH modes per lab in one run
)

# NOT 'Stop': docker/compose write normal progress to stderr, and under 'Stop'
# PowerShell 5.1 turns each such line into a fatal NativeCommandError. We gate
# every native call on $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'
$Root = $PSScriptRoot
Set-Location $Root
$Engine = 'llama-scan/llama_scan.py'   # repo-relative; mounted at /opt/argus-ai in kali

# Which mode(s) to run this invocation. -Both runs scripted then agentic for
# every lab; otherwise it's one or the other.
$scripted = @{ Args = @();            Label = 'scripted scans + Llama analyst' }
$agent    = @{ Args = @('--agentic'); Label = 'AGENTIC (Llama drives)' }
if     ($Both)    { $Modes = @($scripted, $agent) }
elseif ($Agentic) { $Modes = @($agent) }
else              { $Modes = @($scripted) }
$ModeBanner = ($Modes | ForEach-Object { $_.Label }) -join '  +  '

# Normalise -Labs: accept both -Labs a,b (array) and a single "a,b" string
# (the latter is what `powershell -File ... -Labs a,b` passes).
$Labs = @($Labs | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red }

# --- Preflight: local Ollama must be up (the analyst lives here) ------------
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

Info "Mode: $ModeBanner"
$ResultsDir = Join-Path $Root 'llama-results'
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
$ran = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]

# --- Docker labs ------------------------------------------------------------
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
    foreach ($m in $Modes) {
        Info "${lab}: running inside the Kali container [$($m.Label)] ..."
        $ma = @($m.Args)
        & docker compose -f $compose exec -T `
            -e "LLAMA_SCAN_OLLAMA_HOST=http://host.docker.internal:11434" `
            kali python3 -u ("/opt/argus-ai/" + $Engine) --lab $lab --model $Model @ma
        if ($LASTEXITCODE -eq 0) { $anyOk = $true } else { Fail "${lab}: engine error in [$($m.Label)]." }
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
            # No ICMP gate: HTB boxes usually block ping, and nmap runs with -Pn.
            $env:LLAMA_SCAN_OLLAMA_HOST = $OllamaHost
            $anyOk = $false
            foreach ($m in $Modes) {
                Info "htb: running natively against $ip over the VPN [$($m.Label)] ..."
                $ma = @($m.Args)
                & python -u $Engine --lab htb --target $ip --model $Model --ollama-host $OllamaHost @ma
                if ($LASTEXITCODE -eq 0) { $anyOk = $true } else { Fail "htb: engine error in [$($m.Label)] (VPN up? box spawned?)." }
            }
            if ($anyOk) { $ran.Add('htb') } else { $skipped.Add('htb') }
        }
        default { Warn ("unknown lab '" + $lab + "' - skipping."); $skipped.Add($lab) }
    }
}

# --- Wrap up ----------------------------------------------------------------
Write-Host ''
$scannedMsg = if ($ran.Count) { $ran -join ', ' } else { '(none)' }
Ok ("Scanned: " + $scannedMsg)
if ($skipped.Count) { Warn ("Skipped: " + ($skipped -join ', ')) }
Info "Results are in: $ResultsDir"
Get-ChildItem $ResultsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $md = @(Get-ChildItem $_.FullName -Filter *.md -ErrorAction SilentlyContinue).Count
    $ag = if (Test-Path (Join-Path $_.FullName 'agentic')) { ' + agentic/' } else { '' }
    Write-Host ("    llama-results/" + $_.Name + "/  (" + $md + " reports$ag)")
}

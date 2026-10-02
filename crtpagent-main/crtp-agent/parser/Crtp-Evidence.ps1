<#
    Crtp-Evidence.ps1  --  evidence capture discipline for an AUTHORIZED CRTP exam/lab.

    Purpose: make every privilege/host transition self-documenting so the report
    writes itself from FACTS (your commands + their output). It records what YOU
    do; it does NOT write report prose (exam rule: report body must be yours).

    Load it on each shell you work from:
        . .\Crtp-Evidence.ps1

    Core idea: before/after any attack step, drop a CONTEXT banner that proves
    who you are, where you are, and what privileges you hold. Screenshot THAT
    window — the banner + the command + its output all in one shot.

    Functions:
        Start-CrtpSession -Target <n> [-Host <name>]   # begin transcript for a target
        Show-CrtpContext  [-Note "..."]                # the whoami/hostname/priv banner
        Add-CrtpStep -Title "..." [-Why "..."]         # label a step in the transcript
        Save-CrtpFlag -Path <flagfile>                 # read + stamp the final flag
        Stop-CrtpSession                               # end transcript
#>

$script:CrtpBase = Join-Path ([Environment]::GetFolderPath('Desktop')) 'crtp-evidence'
$script:CrtpStep = 0
$script:CrtpTarget = '?'

function Start-CrtpSession {
    param([Parameter(Mandatory)][int]$Target, [string]$HostLabel = $env:COMPUTERNAME)
    $script:CrtpTarget = $Target
    $script:CrtpStep = 0
    if (-not (Test-Path $script:CrtpBase)) { New-Item -ItemType Directory -Path $script:CrtpBase -Force | Out-Null }
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $log = Join-Path $script:CrtpBase "target$Target`_$HostLabel`_$ts.txt"
    Start-Transcript -Path $log -Append | Out-Null
    Write-Host ""
    Write-Host "==================== CRTP TARGET #$Target  ($HostLabel) ====================" -ForegroundColor Cyan
    Write-Host "transcript -> $log" -ForegroundColor DarkGray
    Show-CrtpContext -Note "session start"
}

function Show-CrtpContext {
    param([string]$Note = '')
    $script:CrtpStep++
    Write-Host ""
    Write-Host "----- [T$script:CrtpTarget.$script:CrtpStep] CONTEXT  $(Get-Date -Format u)  $Note -----" -ForegroundColor Yellow
    Write-Host "## hostname";        hostname
    Write-Host "## whoami";          whoami
    Write-Host "## whoami /groups";  whoami /groups
    Write-Host "## whoami /priv";    whoami /priv
    Write-Host "## ipv4";            (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                                       Where-Object {$_.IPAddress -notlike '127.*'} |
                                       Select-Object -Expand IPAddress) -join ', '
    Write-Host "----- END CONTEXT [T$script:CrtpTarget.$script:CrtpStep] -----" -ForegroundColor Yellow
    Write-Host ">> [SHOT] SCREENSHOT this window now (label: T$script:CrtpTarget.$script:CrtpStep)" -ForegroundColor Green
    Write-Host ""
}

function Add-CrtpStep {
    param([Parameter(Mandatory)][string]$Title, [string]$Why = '')
    $script:CrtpStep++
    Write-Host ""
    Write-Host "########## [T$script:CrtpTarget.$script:CrtpStep] $Title ##########" -ForegroundColor Magenta
    if ($Why) { Write-Host "# intent: $Why" -ForegroundColor DarkGray }
    Write-Host "# (run your attack command below; output is captured in the transcript)" -ForegroundColor DarkGray
    Write-Host ">> [SHOT] after output appears, screenshot (label: T$script:CrtpTarget.$script:CrtpStep)" -ForegroundColor Green
}

function Save-CrtpFlag {
    param([string]$Path = 'C:\Users\finadmin\Desktop\finalflag.txt')
    Write-Host ""
    Write-Host "########## FINAL FLAG CAPTURE ##########" -ForegroundColor Red
    Write-Host "## proving context before reading flag:" -ForegroundColor DarkGray
    hostname; whoami
    Write-Host "## flag contents ($Path):" -ForegroundColor DarkGray
    try { Get-Content -Path $Path -ErrorAction Stop }
    catch { Write-Host "!! could not read $Path : $_" -ForegroundColor Red }
    Write-Host ">> [SHOT] SCREENSHOT: must show hostname + whoami + flag together" -ForegroundColor Green
}

function Stop-CrtpSession {
    Write-Host "==================== END TARGET #$script:CrtpTarget ====================" -ForegroundColor Cyan
    try { Stop-Transcript | Out-Null } catch {}
}

Write-Host "[Crtp-Evidence] loaded. Start with:  Start-CrtpSession -Target 1 -HostLabel <host>" -ForegroundColor Cyan

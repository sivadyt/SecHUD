<#
    SecHUD live test
    ----------------
    Does two harmless things an attacker would do, so you can watch SecHUD catch them,
    then undoes both. Nothing is left behind.

      Test 1  adds a Run key entry (persistence, ATT&CK T1547.001). No admin needed.
      Test 2  creates a disabled local account (ATT&CK T1136.001). Needs an admin window.

    Start it with live-test.cmd. For Test 2, right-click live-test.cmd and choose
    "Run as administrator".
#>
$ErrorActionPreference = 'Stop'

$runKey    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$valueName = 'SecHUD-LiveTest'
$userName  = 'sechud-livetest'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin  = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Wait-ForYou([string]$text) {
    Write-Host ''
    Write-Host $text -ForegroundColor Cyan
    Read-Host 'Press Enter when you have looked' | Out-Null
}

Write-Host 'SecHUD live test' -ForegroundColor Red
Write-Host 'Keep the SecHUD window open next to this one.'

try {
    # ---- Test 1: persistence ----
    Write-Host ''
    Write-Host 'TEST 1: a new startup entry (T1547.001)' -ForegroundColor Yellow
    New-ItemProperty -Path $runKey -Name $valueName -Value 'notepad.exe' -PropertyType String -Force | Out-Null
    Wait-ForYou @'
A Run key entry named SecHUD-LiveTest was added.
Do not press anything. Within a few seconds the live watch should show:
  - AUTORUNS shows 1 NEW and the status goes to ELEVATED
  - the Autoruns tab lists HKCU\SecHUD-LiveTest at the top, flagged NEW
  - the Events tab has a line tagged T1547.001
  - a Discord message, if you set that up
(If live watch is switched off in Settings, press SCAN NOW instead.)
'@

    # ---- Test 2: account creation ----
    Write-Host ''
    Write-Host 'TEST 2: a new local account (T1136.001)' -ForegroundColor Yellow
    if (-not $isAdmin) {
        Write-Host 'Skipped: this window is not running as administrator.' -ForegroundColor DarkGray
        Write-Host 'To include it, close this, right-click live-test.cmd and choose Run as administrator.' -ForegroundColor DarkGray
    }
    else {
        $bytes = New-Object byte[] 24
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $password = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
        New-LocalUser -Name $userName -Password $password -Description 'SecHUD live test. Safe to delete.' | Out-Null
        Disable-LocalUser -Name $userName
        Wait-ForYou @'
A disabled local account named sechud-livetest was created (random password, cannot log in).
Do not press anything. Within a few seconds the live watch should show:
  - DETECTIONS shows 1 OPEN (it may also say PARTIAL, which is fine here)
  - the Events tab has a new-account line for SECHUD-LIVETEST tagged T1136.001, with a DISMISS button
  - a Discord message, if you set that up
SecHUD catches this by comparing the account list, so it works even without access to the Security log.
'@
    }
}
finally {
    # ---- Clean up, whatever happened above ----
    Write-Host ''
    Write-Host 'Cleaning up...' -ForegroundColor Yellow
    if (Get-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue
        Write-Host '  removed the Run key entry'
    }
    if ($isAdmin -and (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) {
        Remove-LocalUser -Name $userName -ErrorAction SilentlyContinue
        Write-Host '  removed the test account'
    }
}

Write-Host ''
Write-Host 'Done. The autorun flag clears by itself within a few seconds.' -ForegroundColor Cyan
Write-Host 'Press DISMISS on the account detection in the Events tab to bring the status back to NOMINAL.' -ForegroundColor Cyan
Read-Host 'Press Enter to close' | Out-Null

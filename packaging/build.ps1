<#
  Builds Shield for Windows: the program folder, a self-test of it, and the installer.

      powershell -ExecutionPolicy Bypass -File packaging\build.ps1

  Needs: Python 3.12+ (3.14 is fine) and Inno Setup 6   ( winget install JRSoftware.InnoSetup )
  Optional: set SHIELD_SIGN_ARGS to your signtool arguments to code-sign Shield.exe and the installer, e.g.
      $env:SHIELD_SIGN_ARGS = '/fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a'
#>
param(
    [switch]$SkipInstaller,   # stop after the program folder + self-test
    [switch]$NoUpgrade        # don't pull newer PyQt6 / WebEngine first (not recommended: engine patches are security fixes)
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Step($t) { Write-Host ""; Write-Host "== $t" -ForegroundColor Cyan }
function Fail($t) { Write-Host ""; Write-Host "FAILED: $t" -ForegroundColor Red; exit 1 }

# ---- version (single source of truth: shield_core.py) -------------------------------------------------------
$m = Select-String -Path "shield_core.py" -Pattern '^VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $m) { Fail "Couldn't read VERSION from shield_core.py" }
$Version = $m.Matches[0].Groups[1].Value
$parts = @($Version -split '[^0-9]+' | Where-Object { $_ -ne "" })
while ($parts.Count -lt 4) { $parts += "0" }
$Version4 = ($parts[0..3]) -join "."
Write-Host "Building Shield $Version"

# ---- python environment -------------------------------------------------------------------------------------
Step "Python environment"
$venv = Join-Path $Root ".venv-build"
if (-not (Test-Path "$venv\Scripts\python.exe")) {
    $made = $false
    foreach ($cand in @(@("py", "-3.14"), @("py", "-3"), @("python"))) {
        try {
            $exe = $cand[0]; $rest = @(); if ($cand.Count -gt 1) { $rest = $cand[1..($cand.Count - 1)] }
            & $exe @rest -m venv $venv 2>$null
            if ($LASTEXITCODE -eq 0 -and (Test-Path "$venv\Scripts\python.exe")) { $made = $true; break }
        } catch { }
    }
    if (-not $made) { Fail "Couldn't create a virtual environment. Is Python installed and on PATH?" }
}
$py = "$venv\Scripts\python.exe"
& $py --version
$upgrade = @(); if (-not $NoUpgrade) { $upgrade = @("--upgrade") }
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet @upgrade -r requirements.txt pyinstaller
if ($LASTEXITCODE -ne 0) { Fail "pip couldn't install the requirements" }
$engine = (& $py -c "from importlib.metadata import version; print(version('PyQt6-WebEngine'))").Trim()
$chromium = (& $py -c "from PyQt6.QtWebEngineCore import qWebEngineChromiumVersion as v; print(v())").Trim()
Write-Host "Web engine: PyQt6-WebEngine $engine (Chromium $chromium)"
try {
    $latest = (Invoke-RestMethod "https://pypi.org/pypi/PyQt6-WebEngine/json" -TimeoutSec 15).info.version
    if ([version]$latest -gt [version]$engine) { Write-Host "NOTE: PyQt6-WebEngine $latest exists but $engine was installed. Check your Python version supports it." -ForegroundColor Yellow }
} catch { }

# ---- icon ---------------------------------------------------------------------------------------------------
if (-not (Test-Path "packaging\shield.ico")) {
    Step "Icon"
    & $py packaging\make_icon.py
    if ($LASTEXITCODE -ne 0) { Fail "Couldn't create the icon" }
}

# ---- Tor for this system --------------------------------------------------------------------------------------
# Each installer carries only its own system's Tor (tor\tor_win here). get_tor.py fetches it, checked against packaging\tor_lock.json.
Step "Tor (the private connection's program)"
& $py packaging\get_tor.py
if ($LASTEXITCODE -ne 0) { Fail "Couldn't get Tor. If packaging\tor_lock.json doesn't exist yet, run once:  python packaging\get_tor.py --update" }

# ---- program folder -----------------------------------------------------------------------------------------
Step "Packing the program (PyInstaller)"
Remove-Item -Recurse -Force dist, build -ErrorAction SilentlyContinue
& $py -m PyInstaller packaging\shield.spec --noconfirm --clean --distpath dist --workpath build
if ($LASTEXITCODE -ne 0) { Fail "PyInstaller failed" }
$exe = Join-Path $Root "dist\Shield\Shield.exe"
if (-not (Test-Path $exe)) { Fail "dist\Shield\Shield.exe wasn't produced" }
$size = [math]::Round((Get-ChildItem dist\Shield -Recurse | Measure-Object Length -Sum).Sum / 1MB)
Write-Host "Program folder: $size MB"

# ---- self-test of the packed program ------------------------------------------------------------------------
Step "Self-test of the packed program"
$report = Join-Path $Root "build\selftest.json"
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $exe -ArgumentList @("--selftest", "`"$report`"") -Wait -PassThru
$sw.Stop()
if (-not (Test-Path $report)) { Fail "The packed Shield.exe didn't write a self-test report (exit code $($p.ExitCode)). Check %USERPROFILE%\.shieldbrowser\shield.log" }
$r = Get-Content $report -Raw | ConvertFrom-Json
foreach ($c in $r.checks.PSObject.Properties) {
    $ok = $c.Value.ok
    $mark = "ok  "; $col = "Green"; if (-not $ok) { $mark = "FAIL"; $col = "Red" }
    Write-Host ("  [{0}] {1}: {2}" -f $mark, $c.Name, $c.Value.detail) -ForegroundColor $col
}
if (-not $r.ok) { Fail "The packed program is missing something (see above). Don't ship this build." }
Write-Host ("Self-test passed in {0:N1}s (this includes starting the web engine and loading a page)." -f $sw.Elapsed.TotalSeconds)

# ---- optional signing ---------------------------------------------------------------------------------------
function Find-SignTool {
    $c = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    if (Test-Path $kits) {
        $f = Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "x64" } | Sort-Object FullName -Descending | Select-Object -First 1
        if ($f) { return $f.FullName }
    }
    return $null
}
function Sign($file) {
    if (-not $env:SHIELD_SIGN_ARGS) { return }
    $st = Find-SignTool
    if (-not $st) { Fail "SHIELD_SIGN_ARGS is set but signtool.exe wasn't found (install the Windows SDK)" }
    & $st sign @($env:SHIELD_SIGN_ARGS -split '\s+') $file
    if ($LASTEXITCODE -ne 0) { Fail "Signing $file failed" }
}
if ($env:SHIELD_SIGN_ARGS) { Step "Signing Shield.exe"; Sign $exe }
else { Write-Host ""; Write-Host "Not code-signing (SHIELD_SIGN_ARGS not set). Windows SmartScreen will warn people who download the installer." -ForegroundColor Yellow }

if ($SkipInstaller) { Write-Host ""; Write-Host "Done (program folder only): dist\Shield"; exit 0 }

# ---- installer ----------------------------------------------------------------------------------------------
Step "Building the installer (Inno Setup)"
$iscc = $null
$cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($cmd) { $iscc = $cmd.Source }
foreach ($d in @("$env:LOCALAPPDATA\Programs\Inno Setup 6", "${env:ProgramFiles(x86)}\Inno Setup 6", "$env:ProgramFiles\Inno Setup 6", "$env:LOCALAPPDATA\Programs\Inno Setup 7", "$env:ProgramFiles\Inno Setup 7")) {
    if (-not $iscc -and (Test-Path "$d\ISCC.exe")) { $iscc = "$d\ISCC.exe" }
}
if (-not $iscc) { Fail "Inno Setup wasn't found. Install it with:  winget install JRSoftware.InnoSetup" }
New-Item -ItemType Directory -Force release | Out-Null
& $iscc "/DAppVersion=$Version" "/DAppVersion4=$Version4" packaging\shield.iss
if ($LASTEXITCODE -ne 0) { Fail "Inno Setup failed" }
$setup = Join-Path $Root "release\Shield-Setup-$Version.exe"
if (-not (Test-Path $setup)) { Fail "The installer wasn't produced" }
if ($env:SHIELD_SIGN_ARGS) { Step "Signing the installer"; Sign $setup }

$mb = [math]::Round((Get-Item $setup).Length / 1MB, 1)
Write-Host ""
Write-Host "Built: release\Shield-Setup-$Version.exe ($mb MB)" -ForegroundColor Green
Write-Host "Next:  python packaging\release.py     (makes the signed update manifest for this installer)"

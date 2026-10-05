# Shared helpers for the release scripts (1-push.ps1, 2-build.ps1, 3-release.ps1, ship.ps1). Not run by itself.
# Native programs (git, gh, python) report failure through $LASTEXITCODE, so errors are checked explicitly.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Workflow = "Build installers"          # the name of your GitHub workflow (the title shown in the Actions tab)

function Step($m) { Write-Host ""; Write-Host "== $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "   $m" }
function Warn($m) { Write-Host "   $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host ""; Write-Host "STOPPED: $m" -ForegroundColor Red; exit 1 }

function Need($cmd, $hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Fail "$cmd was not found. $hint" }
}

function Get-ShieldVersion {
    $m = Select-String -Path (Join-Path $Root "shield_core.py") -Pattern '^VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $m) { Fail "Could not read VERSION from shield_core.py" }
    return $m.Matches[0].Groups[1].Value
}

function Test-GitHubLogin {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    gh auth status *> $null
    $ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $old
    return $ok
}

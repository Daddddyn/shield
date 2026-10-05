# Step 3: download the finished installers, make and sign the update manifest, and leave the 6 files to upload in
# release\upload\ (4 installers + manifest.json + manifest.json.sig). Then it opens that folder.
#
#     powershell -ExecutionPolicy Bypass -File packaging\3-release.ps1
#     powershell -ExecutionPolicy Bypass -File packaging\3-release.ps1 -Notes "What changed, in one sentence."
#
# Optional: -MinChromium N (otherwise worked out from the build's own self-test), -Days 45, -RunId <id>.
param([string]$Notes, [int]$MinChromium = 0, [int]$Days = 45, [string]$RunId)
. "$PSScriptRoot\_common.ps1"

Need gh "Install the GitHub CLI (winget install GitHub.cli), then run: gh auth login"
Need python "Python must be on your PATH (the same one you used for release.py before)."
if (-not (Test-GitHubLogin)) { Fail "You are not signed in to GitHub. Run: gh auth login" }

$version = Get-ShieldVersion
Step "Shield $version"

if (-not $RunId) {
    $idFile = Join-Path $Root "build\last-run-id.txt"
    if (-not (Test-Path $idFile)) { Fail "No build run recorded. Run packaging\2-build.ps1 first (or pass -RunId)." }
    $RunId = (Get-Content $idFile -Raw).Trim()
}
Info "Using build run $RunId"

if (-not $Notes) { $Notes = Read-Host "One sentence for 'what changed' (shown to people in Settings > Updates)" }
if (-not $Notes) { $Notes = "Update $version" }
$Notes = $Notes -replace '"', ''

Step "Clearing out older files in release\"
$release = Join-Path $Root "release"
New-Item -ItemType Directory -Force -Path $release | Out-Null
Get-ChildItem -LiteralPath $release -Force | Where-Object {
    $_.Name -like "installer-*" -or $_.Name -eq "upload" -or $_.Name -like "Shield-*"
} | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop }
Info "Done."

Step "Downloading the installers from GitHub"
gh run download $RunId --dir $release
if ($LASTEXITCODE -ne 0) { Fail "Download failed. Is run $RunId finished and still available?" }

$expected = @(
    "Shield-Setup-$version.exe",
    "Shield-$version-macos-arm64.dmg",
    "Shield-$version-macos-x64.dmg",
    "Shield-$version-linux-x64.tar.gz"
)
$missing = @()
foreach ($name in $expected) {
    $hit = Get-ChildItem -LiteralPath $release -Recurse -File -Filter $name | Select-Object -First 1
    if ($hit) { Info ("{0}  ({1} MB)" -f $name, [math]::Round($hit.Length / 1MB)) } else { $missing += $name }
}
if ($missing.Count) {
    Fail ("These are missing from the build: " + ($missing -join ", ") +
          "`nUsually this means VERSION in shield_core.py was changed after the build, or the build ran on an older commit. Push, build again, and retry.")
}

Step "Working out the web-engine floor"
if ($MinChromium -le 0) {
    $log = (gh run view $RunId --log) -join "`n"
    $found = @([regex]::Matches($log, 'security-patch major (\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
    if ($found.Count -eq 0) {
        Fail "Could not read the engine version from the build log. Run again with  -MinChromium N  (the number the build printed, minus 1)."
    }
    $lowest = ($found | Measure-Object -Minimum).Minimum
    $MinChromium = $lowest - 1
    Info "The builds ship Chromium security-patch major $lowest, so the floor is $MinChromium."
} else {
    Info "Using the floor you gave: $MinChromium."
}

Step "Making and signing the update manifest"
python packaging\release.py --notes $Notes --min-chromium $MinChromium --days $Days
if ($LASTEXITCODE -ne 0) { Fail "release.py failed (see its message above)." }

$upload = Join-Path $release "upload"
$out = @(Get-ChildItem -LiteralPath $upload -File)
Step "Ready to upload: $($out.Count) files"
$out | ForEach-Object { Info ("{0}  ({1:N1} MB)" -f $_.Name, ($_.Length / 1MB)) }
if ($out.Count -ne 6) { Warn "Expected 6 files (4 installers + manifest.json + manifest.json.sig) but found $($out.Count). Check the list above." }

try {
    $m = Get-Content (Join-Path $upload "manifest.json") -Raw | ConvertFrom-Json
    $expires = [DateTimeOffset]::FromUnixTimeSeconds([int64]$m.expires).LocalDateTime
    Write-Host ""
    Write-Host ("The manifest expires on {0:yyyy-MM-dd}. Run this script again (same version is fine) before then," -f $expires) -ForegroundColor Yellow
    Write-Host "and upload only manifest.json and manifest.json.sig." -ForegroundColor Yellow
} catch { }

Write-Host ""
Write-Host "To publish them automatically run: packaging\4-upload.ps1" -ForegroundColor Green
Write-Host "Or upload them by hand to the GitHub release named 'shield':" -ForegroundColor Green
Write-Host "  https://github.com/Daddddyn/shield/releases/tag/shield   (Edit the release, drag the files in)"
Write-Host "  Upload the 4 installers first and manifest.json + manifest.json.sig LAST. Replace the older files with the same names."
Start-Process explorer.exe -ArgumentList "`"$upload`""
exit 0

# Step 4 (optional): put the six files from release\upload onto the GitHub release, then remove the old ones.
#
#     powershell -ExecutionPolicy Bypass -File packaging\4-upload.ps1
#     powershell -ExecutionPolicy Bypass -File packaging\4-upload.ps1 -Yes      (don't ask before deleting old files)
#
# The order is chosen so nobody ever sees a broken update:
#   1. new installers go up first (they have new names, so the live manifest still points at the old, working ones),
#   2. the manifest and its signature go up last (this is the moment people are offered the update),
#   3. only then are installers from older versions deleted, because nothing refers to them any more.
# Installers already on the release with the same content are not uploaded again, so a manifest-only refresh is quick.
param([switch]$Yes)
. "$PSScriptRoot\_common.ps1"

Need gh "Install the GitHub CLI (winget install GitHub.cli), then run: gh auth login"
if (-not (Test-GitHubLogin)) { Fail "You are not signed in to GitHub. Run: gh auth login" }

$version = Get-ShieldVersion
Step "Shield $version"

# ---- check what is about to be uploaded -----------------------------------------------------------------
$upload = Join-Path $Root "release\upload"
$manifestPath = Join-Path $upload "manifest.json"
$sigPath = Join-Path $upload "manifest.json.sig"
foreach ($p in @($manifestPath, $sigPath)) {
    if (-not (Test-Path -LiteralPath $p)) { Fail "$p is missing. Run packaging\3-release.ps1 first." }
}
$m = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($m.version -ne $version) {
    Fail "The files in release\upload are for version $($m.version), but shield_core.py says $version. Run packaging\3-release.ps1 again."
}
if ($m.expires) {
    $exp = [DateTimeOffset]::FromUnixTimeSeconds([int64]$m.expires)
    if ($exp -lt [DateTimeOffset]::UtcNow) { Fail "The manifest has already expired. Run packaging\3-release.ps1 again." }
}
$installers = @(Get-ChildItem -LiteralPath $upload -File | Where-Object { $_.Name -notlike "manifest.json*" })
if ($installers.Count -eq 0) { Fail "There are no installers in release\upload." }
foreach ($key in $m.platforms.PSObject.Properties.Name) {
    $leaf = ($m.platforms.$key.url -split "/")[-1]
    if (-not ($installers | Where-Object { $_.Name -eq $leaf })) {
        Fail "The manifest offers $leaf for $key, but that file is not in release\upload."
    }
}

# ---- find the release this build updates from -------------------------------------------------------------
$line = Select-String -Path (Join-Path $Root "shield_update.py") -Pattern '^UPDATE_URL\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $line) { Fail "Could not find UPDATE_URL in shield_update.py" }
$updateUrl = $line.Matches[0].Groups[1].Value
if ($updateUrl -match '^https://github\.com/([^/]+/[^/]+)/releases/download/([^/]+)/manifest\.json$') {
    $repo = $Matches[1]
    $tag = $Matches[2]
} else {
    Fail "UPDATE_URL is not a GitHub release address, so this script can't upload to it. Upload the files by hand."
}
Info "Release '$tag' in $repo"

gh release view $tag --repo $repo --json assets *> $null
if ($LASTEXITCODE -ne 0) {
    Step "Creating the release '$tag' (it did not exist yet)"
    gh release create $tag --repo $repo --title "Shield downloads" --notes "Latest Shield installers and update information."
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the release." }
}

function Get-Assets {
    $j = gh release view $tag --repo $repo --json assets
    if ($LASTEXITCODE -ne 0 -or -not $j) { Fail "Could not read the release's files from GitHub." }
    return @(($j | ConvertFrom-Json).assets)
}

# ---- 1. installers ----------------------------------------------------------------------------------------
Step "Uploading installers"
$assets = Get-Assets
foreach ($f in $installers) {
    $remote = $assets | Where-Object { $_.name -eq $f.Name } | Select-Object -First 1
    $same = $false
    if ($remote -and $remote.size -eq $f.Length) {
        if ($remote.PSObject.Properties.Name -contains "digest" -and $remote.digest) {
            $local = "sha256:" + (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
            $same = ($remote.digest.ToLower() -eq $local)
        } else {
            $same = $true       # older GitHub CLI: same name and same size is the best check available
        }
    }
    if ($same) { Info ("{0}: already there, unchanged" -f $f.Name); continue }
    Info ("{0}: uploading {1:N0} MB (this can take a few minutes)" -f $f.Name, ($f.Length / 1MB))
    gh release upload $tag $f.FullName --repo $repo --clobber
    if ($LASTEXITCODE -ne 0) { Fail "Uploading $($f.Name) failed. Nothing has been announced yet; run this script again to retry." }
}

# ---- 2. manifest and signature, last ---------------------------------------------------------------------
Step "Uploading the manifest and signature (this is what announces the update)"
gh release upload $tag $sigPath $manifestPath --repo $repo --clobber
if ($LASTEXITCODE -ne 0) { Fail "Uploading the manifest failed. Run this script again." }

# ---- 3. remove installers from older versions ------------------------------------------------------------
Step "Removing old files"
$keep = @($installers | ForEach-Object { $_.Name }) + @("manifest.json", "manifest.json.sig")
$stale = @(Get-Assets | Where-Object { $keep -notcontains $_.name -and $_.name -like "Shield-*" })
if ($stale.Count -eq 0) {
    Info "Nothing old to remove."
} else {
    $stale | ForEach-Object { Info ("old: {0}" -f $_.name) }
    $go = $Yes
    if (-not $go) { $go = ((Read-Host "Delete these $($stale.Count) old file(s) from the release? (y/N)") -match '^(y|yes)$') }
    if ($go) {
        foreach ($a in $stale) {
            gh release delete-asset $tag $a.name --repo $repo --yes
            if ($LASTEXITCODE -ne 0) { Warn "Could not delete $($a.name)" }
        }
    } else {
        Info "Left them in place."
    }
}

# ---- check from the outside, the way Shield will see it ---------------------------------------------------
Step "Checking the live files"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("shield-verify-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$verified = $false
for ($i = 0; $i -lt 8 -and -not $verified; $i++) {
    if ($i -gt 0) { Info "GitHub may still be updating its cache, trying again..."; Start-Sleep -Seconds 6 }
    try {
        Invoke-WebRequest -Uri $updateUrl -OutFile (Join-Path $tmp "manifest.json") -UseBasicParsing -ErrorAction Stop
        Invoke-WebRequest -Uri ($updateUrl + ".sig") -OutFile (Join-Path $tmp "manifest.json.sig") -UseBasicParsing -ErrorAction Stop
    } catch { continue }
    $a = (Get-FileHash (Join-Path $tmp "manifest.json") -Algorithm SHA256).Hash
    $b = (Get-FileHash $manifestPath -Algorithm SHA256).Hash
    $c = (Get-FileHash (Join-Path $tmp "manifest.json.sig") -Algorithm SHA256).Hash
    $d = (Get-FileHash $sigPath -Algorithm SHA256).Hash
    $verified = ($a -eq $b -and $c -eq $d)
}
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if (-not $verified) { Fail "The manifest at $updateUrl does not match the one you uploaded. Wait a minute and run this script again." }
Info "The live manifest and signature match."

$names = @(Get-Assets | ForEach-Object { $_.name })
$gone = @()
foreach ($key in $m.platforms.PSObject.Properties.Name) {
    $leaf = ($m.platforms.$key.url -split "/")[-1]
    if ($names -notcontains $leaf) { $gone += $leaf }
}
if ($gone.Count) { Fail ("The manifest offers files that are not on the release: " + ($gone -join ", ")) }
Info "Every installer the manifest offers is on the release."

Write-Host ""
Write-Host "Done. Shield $version is live: people will be offered it the next time they check for updates." -ForegroundColor Green
Write-Host "https://github.com/$repo/releases/tag/$tag"
exit 0

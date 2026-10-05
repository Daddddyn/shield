# Step 2: start the "Build installers" workflow on GitHub and wait for it to finish (about 7 minutes).
#
#     powershell -ExecutionPolicy Bypass -File packaging\2-build.ps1
#
# It builds the exact commit you pushed in step 1, and stops with a clear message if anything is red.
. "$PSScriptRoot\_common.ps1"

Need git "Install Git for Windows."
Need gh "Install the GitHub CLI (winget install GitHub.cli), then run: gh auth login"
if (-not (Test-GitHubLogin)) { Fail "You are not signed in to GitHub. Run: gh auth login" }

$version = Get-ShieldVersion
$branch = (git rev-parse --abbrev-ref HEAD).Trim()
Step "Shield $version, branch '$branch'"

if (git status --porcelain) { Fail "You have changes that are not committed yet. Run packaging\1-push.ps1 first." }
git fetch origin $branch *> $null
$local = (git rev-parse HEAD).Trim()
$remote = (git rev-parse "origin/$branch").Trim()
if ($local -ne $remote) { Fail "Your latest commit is not on GitHub yet. Run packaging\1-push.ps1 first." }

Step "Starting the build on GitHub"
$startedUtc = (Get-Date).ToUniversalTime()
gh workflow run $Workflow --ref $branch
if ($LASTEXITCODE -ne 0) {
    Fail "Could not start the workflow named '$Workflow'. Check its name in the Actions tab (set `$Workflow in packaging\_common.ps1), and that it has 'workflow_dispatch' in its triggers."
}

Step "Waiting for GitHub to pick it up"
$run = $null
for ($i = 0; $i -lt 40 -and -not $run; $i++) {
    Start-Sleep -Seconds 4
    $json = gh run list --workflow $Workflow --branch $branch --limit 10 --json databaseId,headSha,event,createdAt
    if ($LASTEXITCODE -ne 0 -or -not $json) { continue }
    $runs = $json | ConvertFrom-Json
    # Only the run started just now, on exactly this commit (never an older run of the same commit).
    $run = $runs | Where-Object {
        $_.headSha -eq $local -and $_.event -eq "workflow_dispatch" -and
        ([datetime]$_.createdAt).ToUniversalTime() -gt $startedUtc.AddSeconds(-45)
    } | Select-Object -First 1
}
if (-not $run) { Fail "The run did not show up. Open the Actions tab on GitHub to see whether it started." }
$id = $run.databaseId
Info "Run $id started."

New-Item -ItemType Directory -Force -Path (Join-Path $Root "build") | Out-Null
Set-Content -Path (Join-Path $Root "build\last-run-id.txt") -Value $id -Encoding ascii

Step "Building on Windows, macOS and Linux (about 7 minutes). You can leave this window open."
gh run watch $id --exit-status --interval 10
if ($LASTEXITCODE -ne 0) {
    Fail "The build failed, so nothing was released. See why with:  gh run view $id --log-failed   (or: gh run view $id --web)"
}

Write-Host ""
Write-Host "Build finished and every self-test passed. Next: packaging\3-release.ps1" -ForegroundColor Green
exit 0

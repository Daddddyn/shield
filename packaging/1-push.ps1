# Step 1: commit everything and push it to GitHub.
#
#     powershell -ExecutionPolicy Bypass -File packaging\1-push.ps1
#     powershell -ExecutionPolicy Bypass -File packaging\1-push.ps1 -Message "what I changed"
#
# Refuses to go ahead if a key or certificate file is about to be committed.
param([string]$Message)
. "$PSScriptRoot\_common.ps1"

Need git "Install Git for Windows from https://git-scm.com"
$version = Get-ShieldVersion
$branch = (git rev-parse --abbrev-ref HEAD).Trim()
Step "Shield $version, branch '$branch'"

Step "Checking that no secret is about to be uploaded"
$files = @(git ls-files) + @(git ls-files --others --exclude-standard)
$bad = $files | Where-Object { $_ -match '\.(key|pfx|p12|pem)$' -or $_ -match '(^|/)\.env$' }
if ($bad) {
    Fail ("These look like secrets and would be uploaded to GitHub:`n   " + ($bad -join "`n   ") +
          "`nMove them out of the project folder, add them to .gitignore, and run: git rm --cached <file>")
}
Info "Nothing secret-looking found."

Step "Committing"
$changes = git status --porcelain
if ($changes) {
    git add -A
    if ($LASTEXITCODE -ne 0) { Fail "git add failed" }
    if (-not $Message) { $Message = "Release $version" }
    git commit -m $Message
    if ($LASTEXITCODE -ne 0) { Fail "git commit failed" }
} else {
    Info "No new changes to commit."
}

Step "Pushing to GitHub"
git push origin $branch
if ($LASTEXITCODE -ne 0) { Fail "git push failed. If it asks you to sign in, do that, then run this again." }

Write-Host ""
Write-Host "Pushed. Next: packaging\2-build.ps1" -ForegroundColor Green
exit 0

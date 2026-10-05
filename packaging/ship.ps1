# All the steps in one go: commit and push, build on GitHub, download and prepare the files, and (with -Upload) publish them.
#
#     powershell -ExecutionPolicy Bypass -File packaging\ship.ps1 -Notes "What changed, in one sentence."
#     powershell -ExecutionPolicy Bypass -File packaging\ship.ps1 -Notes "..." -Upload
#
# Without -Upload it stops after step 3, with the six files ready in release\upload for you to look over.
param([string]$Notes, [string]$Message, [switch]$Upload, [switch]$Yes)
$here = $PSScriptRoot
& "$here\1-push.ps1" -Message $Message
if ($LASTEXITCODE -ne 0) { exit 1 }
& "$here\2-build.ps1"
if ($LASTEXITCODE -ne 0) { exit 1 }
& "$here\3-release.ps1" -Notes $Notes
if ($LASTEXITCODE -ne 0) { exit 1 }
if ($Upload) {
    if ($Yes) { & "$here\4-upload.ps1" -Yes } else { & "$here\4-upload.ps1" }
    exit $LASTEXITCODE
}
Write-Host ""
Write-Host "Nothing was published. To publish: packaging\4-upload.ps1" -ForegroundColor Yellow
exit 0

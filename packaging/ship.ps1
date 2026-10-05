# All three steps in one go: commit and push, build on GitHub, then download and prepare the 6 files.
#
#     powershell -ExecutionPolicy Bypass -File packaging\ship.ps1 -Notes "What changed, in one sentence."
param([string]$Notes, [string]$Message)
$here = $PSScriptRoot
& "$here\1-push.ps1" -Message $Message
if ($LASTEXITCODE -ne 0) { exit 1 }
& "$here\2-build.ps1"
if ($LASTEXITCODE -ne 0) { exit 1 }
& "$here\3-release.ps1" -Notes $Notes
exit $LASTEXITCODE

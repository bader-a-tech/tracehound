param([Parameter(Mandatory)][string]$Installer,[Parameter(Mandatory)][string]$SmokeExecutable,[Parameter(Mandatory)][string]$Version,[Parameter(Mandatory)][string]$WorkDirectory)
$ErrorActionPreference='Stop'
$installer=(Resolve-Path -LiteralPath $Installer).Path
$smoke=(Resolve-Path -LiteralPath $SmokeExecutable).Path
New-Item -ItemType Directory -Path $WorkDirectory | Out-Null
$work=(Resolve-Path -LiteralPath $WorkDirectory).Path
function Invoke-Msi([string]$Operation) {
  $log=Join-Path $work "$Operation.log"
  $process=Start-Process -FilePath msiexec.exe -ArgumentList @("/$Operation",('"'+$installer+'"'),'/qn','/norestart','/l*v',('"'+$log+'"')) -WindowStyle Hidden -Wait -PassThru
  if ($process.ExitCode -notin @(0,3010)) { throw "MSI $Operation failed: $($process.ExitCode); see $log" }
}
$installed=Join-Path $env:LOCALAPPDATA 'Programs/Tracehound'
if (Test-Path -LiteralPath $installed) { throw 'Smoke check requires a clean disposable runner, not an existing installation' }
try {
  Invoke-Msi 'i'
  & $smoke $installed "v$Version" (Join-Path $work 'backend verification')
  if ($LASTEXITCODE -ne 0) { throw 'Installed backend verification failed' }
  & (Join-Path $installed 'tracehound-desktop.exe') --smoke-test
  if ($LASTEXITCODE -ne 0) { throw 'Installed native GUI initialization failed' }
  if (-not(Test-Path -LiteralPath (Join-Path $installed 'licenses/catalog.json'))) { throw 'Installed dependency notices are missing' }
} finally {
  if (Test-Path -LiteralPath $installed) { Invoke-Msi 'x' }
}
if (Test-Path -LiteralPath (Join-Path $installed 'tracehound-desktop.exe')) { throw 'Uninstall left an application executable behind' }

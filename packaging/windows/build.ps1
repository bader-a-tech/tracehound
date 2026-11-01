param(
  [Parameter(Mandatory)][string]$StageDirectory,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [Parameter(Mandatory)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')][string]$Version
)
$ErrorActionPreference = 'Stop'
$stage = (Resolve-Path -LiteralPath $StageDirectory).Path
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path
$work = Join-Path ([IO.Path]::GetDirectoryName($output)) ('windows-package-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
function Invoke-Checked([string]$Executable, [string[]]$Arguments) {
  & $Executable @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($Executable)) failed with exit code $LASTEXITCODE" }
}
function Find-Wix([string]$Name) {
  $command = Get-Command "$Name.exe" -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  $candidates = @()
  if ($env:WIX) { $candidates += Join-Path $env:WIX "bin/$Name.exe" }
  $candidates += Get-ChildItem -LiteralPath ${env:ProgramFiles(x86)} -Directory -Filter 'WiX Toolset v3*' | ForEach-Object { Join-Path $_.FullName "bin/$Name.exe" }
  $found = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $found) { throw "WiX3 $Name.exe is required; the native Windows hosted runner provides it. No tools are installed by this script." }
  return $found
}
function Set-HarvestedFileIdentities([string]$Path) {
  # Per-user file components use an HKCU registry keypath. WiX cannot generate
  # a GUID for that combination, so derive both identities from the installed
  # relative path, independent of the checkout directory and heat's element IDs.
  $document = [Xml.XmlDocument]::new()
  $document.PreserveWhitespace = $true
  $document.Load($Path)
  $namespaces = [Xml.XmlNamespaceManager]::new($document.NameTable)
  $namespaces.AddNamespace('wix', 'http://schemas.microsoft.com/wix/2006/wi')
  $components = @($document.SelectNodes('//wix:Component[wix:File]', $namespaces))
  if ($components.Count -eq 0) { throw 'The harvested package contains no file components' }
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $prefix = '$(var.StageDir)\'
  foreach ($component in $components) {
    $files = @($component.SelectNodes('wix:File', $namespaces))
    if ($files.Count -ne 1) { throw 'Each harvested file must have its own component' }
    $source = $files[0].GetAttribute('Source').Replace('/', '\')
    if (-not $source.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'A harvested file source is outside the staged relative prefix'
    }
    $relative = $source.Substring($prefix.Length).ToLowerInvariant()
    if ($relative.Split('\') | Where-Object { $_ -in @('', '.', '..') }) {
      throw 'A harvested file source has an invalid relative path'
    }
    if (-not $seen.Add($relative)) { throw 'Duplicate harvested file path' }
    $digest = [Security.Cryptography.SHA256]::HashData(
      [Text.Encoding]::UTF8.GetBytes('Tracehound per-user file component v1:' + $relative))
    $component.SetAttribute('Guid', ([Guid]::new([byte[]]$digest[0..15])).ToString('D'))
    $keys = @($component.SelectNodes("wix:RegistryValue[@Root='HKCU' and @Key='Software\Tracehound\Components' and @KeyPath='yes']", $namespaces))
    if ($keys.Count -ne 1) { throw 'A harvested file component lacks its private HKCU keypath' }
    $keys[0].SetAttribute('Name', 'file_' + [Convert]::ToHexString($digest).ToLowerInvariant())
  }
  # Directory cleanup components contain only registry values and keep WiX's
  # supported automatic GUID generation.
  $document.Save($Path)
}
$certificate = $null
$certificateWasPresent = $false
$pfx = $null
$signed = $false
try {
  if ($env:WINDOWS_CERTIFICATE_PFX_BASE64) {
    if (-not $env:WINDOWS_CERTIFICATE_PASSWORD) { throw 'A certificate was supplied without WINDOWS_CERTIFICATE_PASSWORD' }
    $pfx = Join-Path $work 'signing.pfx'
    $bytes = [Convert]::FromBase64String($env:WINDOWS_CERTIFICATE_PFX_BASE64)
    [IO.File]::WriteAllBytes($pfx, $bytes)
    $inspection = [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes, $env:WINDOWS_CERTIFICATE_PASSWORD, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    $thumbprint = $inspection.Thumbprint
    $inspection.Dispose()
    $certificateWasPresent = Test-Path -LiteralPath "Cert:/CurrentUser/My/$thumbprint"
    $password = ConvertTo-SecureString $env:WINDOWS_CERTIFICATE_PASSWORD -AsPlainText -Force
    Import-PfxCertificate -FilePath $pfx -Password $password -CertStoreLocation Cert:/CurrentUser/My | Out-Null
    $certificate = Get-Item -LiteralPath "Cert:/CurrentUser/My/$thumbprint"
    $signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1
    if (-not $signTool) {
      $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
      $signTool = Get-ChildItem -LiteralPath $sdk -Directory | Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'x64/signtool.exe' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if (-not $signTool) { throw 'The Windows SDK signing tool is unavailable' }
    $timestamp = if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { 'https://timestamp.digicert.com' }
    if (([Uri]$timestamp).Scheme -ne 'https') { throw 'Timestamp URL must use HTTPS' }
    foreach ($name in @('tracehound.exe', 'tracehound-eval.exe', 'tracehound-desktop.exe')) {
      Invoke-Checked $signTool @('sign', '/sha1', $thumbprint, '/s', 'My', '/fd', 'SHA256', '/tr', $timestamp, '/td', 'SHA256', (Join-Path $stage $name))
      Invoke-Checked $signTool @('verify', '/pa', (Join-Path $stage $name))
    }
    $signed = $true
  }
  $state = if ($signed) { 'signed' } else { 'unsigned' }
  $package = Join-Path $output "tracehound-v$Version-windows-amd64-installer-$state.msi"
  if (Test-Path -LiteralPath $package) { throw 'Installer output already exists' }
  $license = Get-Content -LiteralPath (Join-Path $stage 'LICENSE') -Raw
  $escaped = $license.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}').Replace("`r", '').Replace("`n", '\par ')
  $rtf = Join-Path $work 'license.rtf'
  ('{\rtf1\ansi\deff0{\fonttbl{\f0 Segoe UI;}}\f0\fs20 ' + $escaped + '}') | Set-Content -LiteralPath $rtf -Encoding ascii
  $heat = Find-Wix 'heat'; $candle = Find-Wix 'candle'; $light = Find-Wix 'light'
  $harvest = Join-Path $work 'Files.wxs'
  Invoke-Checked $heat @('dir', $stage, '-nologo', '-ag', '-sfrag', '-srd', '-sreg', '-scom', '-cg', 'AppFiles', '-dr', 'INSTALLFOLDER', '-var', 'var.StageDir', '-t', (Join-Path $PSScriptRoot 'PerUserComponents.xsl'), '-out', $harvest)
  Set-HarvestedFileIdentities $harvest
  $product = Join-Path $PSScriptRoot 'Product.wxs'
  $packageVersion = $Version.Split('-')[0]
  Invoke-Checked $candle @('-nologo', '-arch', 'x64', "-dStageDir=$stage", "-dPackageVersion=$packageVersion", "-dLicenseFile=$rtf", '-out', ($work + [IO.Path]::DirectorySeparatorChar), $product, $harvest)
  Invoke-Checked $light @('-nologo', '-ext', 'WixUIExtension', '-pdbout', (Join-Path $work 'Product.wixpdb'), '-out', $package, (Join-Path $work 'Product.wixobj'), (Join-Path $work 'Files.wixobj'))
  if ($signed) {
    Invoke-Checked $signTool @('sign', '/sha1', $thumbprint, '/s', 'My', '/fd', 'SHA256', '/tr', $timestamp, '/td', 'SHA256', $package)
    Invoke-Checked $signTool @('verify', '/pa', $package)
  }
  [PSCustomObject]@{ schema_version=1; platform='windows'; architecture='amd64'; application_binaries_signed=$signed; package_signed=$signed; notarized=$false; installer=[IO.Path]::GetFileName($package) } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output "tracehound-v$Version-windows-amd64-signing.json") -Encoding utf8NoBOM
  Write-Output "Built $state per-user MSI: $([IO.Path]::GetFileName($package))"
} finally {
  if ($certificate -and -not $certificateWasPresent) { Remove-Item -LiteralPath "Cert:/CurrentUser/My/$($certificate.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue }
  if ($pfx -and (Test-Path -LiteralPath $pfx)) { Remove-Item -LiteralPath $pfx }
}

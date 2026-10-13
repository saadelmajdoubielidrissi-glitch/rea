$ErrorActionPreference = "Stop"

$jobSource = Join-Path $PSScriptRoot "..\windows-gui\launcher\LauncherJobObject.cs"
$jobSource = [System.IO.Path]::GetFullPath($jobSource)
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
  "rea-gui-launcher-job-" + [guid]::NewGuid().ToString("N")
)
$ownerScriptPath = Join-Path $temporaryRoot "owner.ps1"
$middlePidPath = Join-Path $temporaryRoot "middle.pid"
$childPidPath = Join-Path $temporaryRoot "child.pid"
$ownerOutputPath = Join-Path $temporaryRoot "owner.stdout"
$ownerErrorPath = Join-Path $temporaryRoot "owner.stderr"
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)

$nestedScript = @"
`$ErrorActionPreference = 'Stop'
Add-Type -Path '$($jobSource.Replace("'", "''"))'
`$nestedJob = [Rea.WindowsGui.Launcher.LauncherJobObject]::AssignCurrentProcess()
`$child = Start-Process -FilePath (Join-Path `$env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoLogo', '-NoProfile', '-Command', 'Start-Sleep -Seconds 120') -PassThru
[System.IO.File]::WriteAllText('$($childPidPath.Replace("'", "''"))', `$child.Id.ToString())
Start-Sleep -Seconds 120
"@
$nestedEncoded = [Convert]::ToBase64String(
  [System.Text.Encoding]::Unicode.GetBytes($nestedScript)
)
$ownerScript = @"
`$ErrorActionPreference = 'Stop'
Add-Type -Path '$($jobSource.Replace("'", "''"))'
`$job = [Rea.WindowsGui.Launcher.LauncherJobObject]::AssignCurrentProcess()
`$middle = Start-Process -FilePath (Join-Path `$env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoLogo', '-NoProfile', '-EncodedCommand', '$nestedEncoded') -PassThru
[System.IO.File]::WriteAllText('$($middlePidPath.Replace("'", "''"))', `$middle.Id.ToString())
Start-Sleep -Seconds 120
"@
[System.IO.File]::WriteAllText($ownerScriptPath, $ownerScript)

$encodedScript = [Convert]::ToBase64String(
  [System.Text.Encoding]::Unicode.GetBytes(
    "& '$($ownerScriptPath.Replace("'", "''"))'"
  )
)
$owner = $null
$middle = $null
$child = $null
try {
  $owner = Start-Process `
    -FilePath (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe") `
    -ArgumentList @("-NoLogo", "-NoProfile", "-EncodedCommand", $encodedScript) `
    -RedirectStandardOutput $ownerOutputPath `
    -RedirectStandardError $ownerErrorPath `
    -PassThru
  $deadline = [DateTime]::UtcNow.AddSeconds(15)
  while (-not [System.IO.File]::Exists($childPidPath) -and [DateTime]::UtcNow -lt $deadline) {
    if ($owner.HasExited) {
      throw "The launcher-job fixture exited before it started its child: $(Get-Content -Raw $ownerErrorPath)"
    }
    Start-Sleep -Milliseconds 25
  }
  if (-not [System.IO.File]::Exists($childPidPath)) {
    throw "The launcher-job fixture did not report its child process."
  }

  $middlePid = [int][System.IO.File]::ReadAllText($middlePidPath)
  $childPid = [int][System.IO.File]::ReadAllText($childPidPath)
  $middle = [System.Diagnostics.Process]::GetProcessById($middlePid)
  $child = [System.Diagnostics.Process]::GetProcessById($childPid)
  if ($middle.HasExited -or $child.HasExited) {
    throw "A nested child process exited before the launcher owner was stopped."
  }

  Stop-Process -Id $owner.Id -Force
  if (-not $owner.WaitForExit(15000)) {
    throw "The launcher-job owner did not exit."
  }
  if (-not $child.WaitForExit(15000)) {
    throw "The launcher's child process survived owner termination."
  }
  if (-not $middle.WaitForExit(15000)) {
    throw "The launcher's nested GUI process survived owner termination."
  }

  Write-Output "Windows GUI launcher Job Object test passed."
}
finally {
  if ($null -ne $owner -and -not $owner.HasExited) {
    Stop-Process -Id $owner.Id -Force
  }
  if ($null -ne $child) {
    $child.Dispose()
  }
  if ($null -ne $middle) {
    $middle.Dispose()
  }
  if ($null -ne $owner) {
    $owner.Dispose()
  }
  if ([System.IO.Directory]::Exists($temporaryRoot)) {
    [System.IO.Directory]::Delete($temporaryRoot, $true)
  }
}

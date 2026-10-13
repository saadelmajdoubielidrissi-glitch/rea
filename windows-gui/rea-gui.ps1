param(
  [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

$script:GuiCommands = @(
  [pscustomobject]@{
    Id = "analyze"
    Label = "일반 개요 분석"
    Description = "네이티브 대상은 선택한 REA 분석 엔진으로 분석합니다. JavaScript 앱 디렉터리와 ASAR는 정적 분석 경로로 처리합니다."
    AllowsDirectory = $true
    UsesProvider = $true
  },
  [pscustomobject]@{
    Id = "analyze-javascript-application"
    Label = "JavaScript / Electron 앱 정적 분석"
    Description = "앱 디렉터리 또는 ASAR를 정적으로 분석합니다. Electron 앱 자체를 실행하지 않습니다."
    AllowsDirectory = $true
    UsesProvider = $false
  },
  [pscustomobject]@{
    Id = "inspect-go-binary"
    Label = "Go 바이너리 메타데이터"
    Description = "ELF, PE 또는 thin Mach-O 파일에서 Go 빌드 정보를 읽습니다. 대상 코드를 실행하지 않습니다."
    AllowsDirectory = $false
    UsesProvider = $false
  },
  [pscustomobject]@{
    Id = "inspect-managed-artifact"
    Label = ".NET 어셈블리 메타데이터"
    Description = "PE/CLI 어셈블리의 식별 정보를 읽습니다. 대상 코드를 로드하거나 실행하지 않습니다."
    AllowsDirectory = $false
    UsesProvider = $false
  },
  [pscustomobject]@{
    Id = "inspect-sqlite-database"
    Label = "SQLite 데이터베이스"
    Description = "로컬 SQLite 스냅샷의 스키마를 검사합니다. 표본 행 조회는 CLI에서 별도로 지정할 수 있습니다."
    AllowsDirectory = $false
    UsesProvider = $false
  }
)

function Get-ReaArguments {
  param(
    [Parameter(Mandatory)]
    [string]$CommandId,
    [Parameter(Mandatory)]
    [string]$TargetPath,
    [string]$Provider = "auto",
    [switch]$IsJavaScriptTarget
  )

  switch ($CommandId) {
    "analyze" {
      if ($Provider -notin @("auto", "ghidra", "ida")) {
        throw "지원하지 않는 분석 제공자입니다: $Provider"
      }
      $arguments = @("analyze", $TargetPath)
      if (-not $IsJavaScriptTarget -and $Provider -ne "auto") {
        $arguments += @("--provider", $Provider)
      }
      $arguments += "--json"
      return $arguments
    }
    "analyze-javascript-application" {
      return @("analyze-javascript-application", $TargetPath, "--json")
    }
    "inspect-go-binary" {
      return @("inspect-go-binary", $TargetPath, "--json")
    }
    "inspect-managed-artifact" {
      return @("inspect-managed-artifact", $TargetPath, "--json")
    }
    "inspect-sqlite-database" {
      return @("inspect-sqlite-database", $TargetPath, "--json")
    }
    default {
      throw "REA GUI에서 지원하지 않는 작업입니다: $CommandId"
    }
  }
}

function ConvertTo-WindowsArgument {
  param(
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Argument
  )

  $builder = New-Object System.Text.StringBuilder
  [void]$builder.Append([char]34)
  $backslashes = 0
  foreach ($character in $Argument.ToCharArray()) {
    if ($character -eq [char]92) {
      $backslashes++
      continue
    }
    if ($character -eq [char]34) {
      for ($index = 0; $index -lt (2 * $backslashes + 1); $index++) {
        [void]$builder.Append([char]92)
      }
      [void]$builder.Append([char]34)
    }
    else {
      for ($index = 0; $index -lt $backslashes; $index++) {
        [void]$builder.Append([char]92)
      }
      [void]$builder.Append($character)
    }
    $backslashes = 0
  }
  for ($index = 0; $index -lt (2 * $backslashes); $index++) {
    [void]$builder.Append([char]92)
  }
  [void]$builder.Append([char]34)
  return $builder.ToString()
}

function Test-ReaJavaScriptTarget {
  param(
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$TargetPath
  )

  if ([System.IO.Path]::GetExtension($TargetPath) -ieq ".asar") {
    return $true
  }
  return [System.IO.Path]::GetExtension($TargetPath) -ine ".app" -and
    [System.IO.Directory]::Exists($TargetPath)
}

function Test-ReaGuiCommands {
  $target = "C:\테스트 폴더\100% & sample.exe"
  $commandIds = @($script:GuiCommands | ForEach-Object { $_.Id })
  $expectedIds = @(
    "analyze",
    "analyze-javascript-application",
    "inspect-go-binary",
    "inspect-managed-artifact",
    "inspect-sqlite-database"
  )
  if (($commandIds -join "`0") -cne ($expectedIds -join "`0")) {
    throw "GUI 명령 선택 목록이 예상과 다릅니다."
  }
  $cases = @(
    @{
      Id = "analyze"
      Provider = "auto"
      Expected = @("analyze", $target, "--json")
    },
    @{
      Id = "analyze"
      Provider = "ghidra"
      Expected = @("analyze", $target, "--provider", "ghidra", "--json")
    },
    @{
      Id = "analyze"
      Provider = "ida"
      IsJavaScriptTarget = $true
      Expected = @("analyze", $target, "--json")
    },
    @{
      Id = "analyze-javascript-application"
      Provider = "auto"
      Expected = @("analyze-javascript-application", $target, "--json")
    },
    @{
      Id = "inspect-go-binary"
      Provider = "auto"
      Expected = @("inspect-go-binary", $target, "--json")
    },
    @{
      Id = "inspect-managed-artifact"
      Provider = "auto"
      Expected = @("inspect-managed-artifact", $target, "--json")
    },
    @{
      Id = "inspect-sqlite-database"
      Provider = "auto"
      Expected = @("inspect-sqlite-database", $target, "--json")
    }
  )
  foreach ($case in $cases) {
    $javascriptTarget = [bool]$case.IsJavaScriptTarget
    $actual = @(
      Get-ReaArguments -CommandId $case.Id -TargetPath $target `
        -Provider $case.Provider -IsJavaScriptTarget:$javascriptTarget
    )
    if (($actual -join "`0") -cne ($case.Expected -join "`0")) {
      throw "CLI 인자 검증에 실패했습니다: $($case.Id)"
    }
  }
  $quoted = ConvertTo-WindowsArgument $target
  if ($quoted -cne '"C:\테스트 폴더\100% & sample.exe"') {
    throw "Windows 인자 인용 검증에 실패했습니다."
  }
  $unsupportedRejected = $false
  try {
    [void](Get-ReaArguments -CommandId "arbitrary-command" -TargetPath $target)
  }
  catch {
    $unsupportedRejected = $true
  }
  if (-not $unsupportedRejected) {
    throw "허용되지 않은 명령이 거부되지 않았습니다."
  }
  if (-not (Test-ReaJavaScriptTarget -TargetPath "C:\apps\desktop.asar") -or
    (Test-ReaJavaScriptTarget -TargetPath "")) {
    throw "JavaScript/ASAR 대상 경로 검증에 실패했습니다."
  }
  $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "rea-gui-routing-" + [guid]::NewGuid().ToString("N")
  )
  try {
    $applicationDirectory = Join-Path $temporaryRoot "application"
    $appBundleDirectory = Join-Path $temporaryRoot "desktop.app"
    [void][System.IO.Directory]::CreateDirectory($applicationDirectory)
    [void][System.IO.Directory]::CreateDirectory($appBundleDirectory)
    if (-not (Test-ReaJavaScriptTarget -TargetPath $applicationDirectory) -or
      (Test-ReaJavaScriptTarget -TargetPath $appBundleDirectory)) {
      throw "JavaScript 앱 디렉터리와 .app 대상 구분 검증에 실패했습니다."
    }
  }
  finally {
    if ([System.IO.Directory]::Exists($temporaryRoot)) {
      [System.IO.Directory]::Delete($temporaryRoot, $true)
    }
  }
  Write-Output "REA GUI 명령 인자 검증을 통과했습니다."
}

if ($ValidateOnly) {
  Test-ReaGuiCommands
  exit 0
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  throw "REA 데스크톱 GUI는 Windows에서만 실행할 수 있습니다."
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -Path (Join-Path $PSScriptRoot "ReaGuiProcessRunner.cs")

$packageRoot = Split-Path -Parent $PSScriptRoot
$reaEntryPoint = Join-Path $packageRoot "scripts\rea.mjs"
$nodeExecutable = $env:REA_GUI_NODE_EXE
if ([string]::IsNullOrWhiteSpace($nodeExecutable)) {
  $nodeCommand = Get-Command "node.exe" -CommandType Application -ErrorAction SilentlyContinue
  if ($null -ne $nodeCommand) {
    $nodeExecutable = $nodeCommand.Source
  }
}
if ([string]::IsNullOrWhiteSpace($nodeExecutable) -or
  -not (Test-Path -LiteralPath $nodeExecutable -PathType Leaf) -or
  -not (Test-Path -LiteralPath $reaEntryPoint -PathType Leaf)) {
  [System.Windows.Forms.MessageBox]::Show(
    "REA CLI 또는 Node.js를 찾을 수 없습니다.`r`n`r`nNode.js를 설치하고 npm install --global rea-agents를 실행한 뒤 다시 시작하세요.",
    "REA Windows GUI",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Error
  ) | Out-Null
  exit 1
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "REA Windows 데스크톱 GUI"
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.ClientSize = New-Object System.Drawing.Size(980, 720)
$form.MinimumSize = New-Object System.Drawing.Size(1020, 600)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$title = New-Object System.Windows.Forms.Label
$title.Text = "REA 분석"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$title.SetBounds(16, 12, 900, 32)
$form.Controls.Add($title)

$commandLabel = New-Object System.Windows.Forms.Label
$commandLabel.Text = "분석 작업"
$commandLabel.SetBounds(16, 56, 76, 26)
$commandLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$form.Controls.Add($commandLabel)

$commandCombo = New-Object System.Windows.Forms.ComboBox
$commandCombo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$commandCombo.SetBounds(96, 54, 540, 28)
foreach ($command in $script:GuiCommands) {
  [void]$commandCombo.Items.Add($command.Label)
}
$commandCombo.SelectedIndex = 0
$form.Controls.Add($commandCombo)

$providerLabel = New-Object System.Windows.Forms.Label
$providerLabel.Text = "제공자"
$providerLabel.SetBounds(652, 56, 58, 26)
$providerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$form.Controls.Add($providerLabel)

$providerCombo = New-Object System.Windows.Forms.ComboBox
$providerCombo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$providerCombo.Items.AddRange([object[]]@("설정/자동 선택", "Ghidra", "IDA"))
$providerCombo.SelectedIndex = 0
$providerCombo.SetBounds(712, 54, 244, 28)
$form.Controls.Add($providerCombo)

$description = New-Object System.Windows.Forms.Label
$description.Text = $script:GuiCommands[0].Description
$description.SetBounds(16, 88, 940, 42)
$description.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$form.Controls.Add($description)

$targetLabel = New-Object System.Windows.Forms.Label
$targetLabel.Text = "대상 경로"
$targetLabel.SetBounds(16, 139, 76, 26)
$targetLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$form.Controls.Add($targetLabel)

$targetTextBox = New-Object System.Windows.Forms.TextBox
$targetTextBox.SetBounds(96, 136, 648, 28)
$form.Controls.Add($targetTextBox)

$fileButton = New-Object System.Windows.Forms.Button
$fileButton.Text = "파일 선택..."
$fileButton.SetBounds(752, 134, 100, 30)
$form.Controls.Add($fileButton)

$folderButton = New-Object System.Windows.Forms.Button
$folderButton.Text = "폴더 선택..."
$folderButton.SetBounds(858, 134, 98, 30)
$form.Controls.Add($folderButton)

$runButton = New-Object System.Windows.Forms.Button
$runButton.Text = "분석 실행"
$runButton.SetBounds(16, 176, 120, 32)
$runButton.BackColor = [System.Drawing.Color]::FromArgb(30, 105, 180)
$runButton.ForeColor = [System.Drawing.Color]::White
$runButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$form.Controls.Add($runButton)

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = "결과 지우기"
$clearButton.SetBounds(144, 176, 110, 32)
$form.Controls.Add($clearButton)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "준비됨"
$statusLabel.SetBounds(270, 178, 680, 28)
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$form.Controls.Add($statusLabel)

$resultsLabel = New-Object System.Windows.Forms.Label
$resultsLabel.Text = "실행 결과"
$resultsLabel.SetBounds(16, 218, 940, 24)
$form.Controls.Add($resultsLabel)

$outputTabs = New-Object System.Windows.Forms.TabControl
$outputTabs.SetBounds(16, 244, 940, 450)
$outputTabs.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$form.Controls.Add($outputTabs)

$stdoutTab = New-Object System.Windows.Forms.TabPage
$stdoutTab.Text = "표준 출력 (JSON)"
$outputTabs.TabPages.Add($stdoutTab)
$resultsBox = New-Object System.Windows.Forms.RichTextBox
$resultsBox.ReadOnly = $true
$resultsBox.WordWrap = $false
$resultsBox.DetectUrls = $false
$resultsBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$resultsBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$stdoutTab.Controls.Add($resultsBox)
$resultsBox.Text = "작업과 대상을 선택한 다음 '분석 실행'을 누르세요.`r`n분석 대상 프로그램 자체는 실행하지 않습니다."

$stderrTab = New-Object System.Windows.Forms.TabPage
$stderrTab.Text = "오류"
$outputTabs.TabPages.Add($stderrTab)
$errorsBox = New-Object System.Windows.Forms.RichTextBox
$errorsBox.ReadOnly = $true
$errorsBox.WordWrap = $false
$errorsBox.DetectUrls = $false
$errorsBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$errorsBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$stderrTab.Controls.Add($errorsBox)

$processState = [pscustomobject]@{
  Runner = $null
  IsRunning = $false
}
function Add-ReaOutputLine {
  param(
    [Parameter(Mandatory)]
    [Rea.WindowsGui.ReaGuiOutputLine]$Line
  )

  if ($Line.Stream -eq "stdout") {
    $resultsBox.AppendText("$($Line.Text)`r`n")
  }
  else {
    $errorsBox.AppendText("$($Line.Text)`r`n")
  }
}

$outputTimer = New-Object System.Windows.Forms.Timer
$outputTimer.Interval = 100
$providerLabel.Enabled = $script:GuiCommands[0].UsesProvider
$providerCombo.Enabled = $script:GuiCommands[0].UsesProvider
$folderButton.Enabled = $script:GuiCommands[0].AllowsDirectory
$updateProviderAvailability = {
  $selectedCommand = $script:GuiCommands[$commandCombo.SelectedIndex]
  $targetPath = $targetTextBox.Text.Trim()
  $isJavaScriptTarget = Test-ReaJavaScriptTarget -TargetPath $targetPath
  $providerLabel.Enabled = $selectedCommand.UsesProvider -and -not $isJavaScriptTarget
  $providerCombo.Enabled = $selectedCommand.UsesProvider -and
    -not $isJavaScriptTarget -and -not $processState.IsRunning
}.GetNewClosure()
$targetTextBox.add_TextChanged($updateProviderAvailability)
$updateProviderAvailability.Invoke()

$outputTimer.add_Tick({
  $line = $null
  while ($processState.Runner.TryDequeue([ref]$line)) {
    Add-ReaOutputLine -Line $line
    $line = $null
  }
  $resultsBox.SelectionStart = $resultsBox.TextLength
  $resultsBox.ScrollToCaret()
  $errorsBox.SelectionStart = $errorsBox.TextLength
  $errorsBox.ScrollToCaret()
  if (-not $processState.Runner.HasExited) {
    return
  }

  $processState.Runner.WaitForExit()
  while ($processState.Runner.TryDequeue([ref]$line)) {
    Add-ReaOutputLine -Line $line
    $line = $null
  }
  $exitCode = $processState.Runner.ExitCode
  $processState.Runner.Dispose()
  $processState.Runner = $null
  $processState.IsRunning = $false
  $outputTimer.Stop()
  $selectedCommand = $script:GuiCommands[$commandCombo.SelectedIndex]
  $runButton.Enabled = $true
  $commandCombo.Enabled = $true
  $targetTextBox.Enabled = $true
  $fileButton.Enabled = $true
  $folderButton.Enabled = $selectedCommand.AllowsDirectory
  $updateProviderAvailability.Invoke()
  if ($exitCode -eq 0) {
    $statusLabel.Text = "완료 (종료 코드 0)"
  }
  else {
    $statusLabel.Text = "실패 (종료 코드 $exitCode)"
  }
}.GetNewClosure())

$commandCombo.add_SelectedIndexChanged({
  $selectedCommand = $script:GuiCommands[$commandCombo.SelectedIndex]
  $description.Text = $selectedCommand.Description
  $updateProviderAvailability.Invoke()
  $folderButton.Enabled = $selectedCommand.AllowsDirectory -and -not $processState.IsRunning
}.GetNewClosure())

$fileButton.add_Click({
  $dialog = New-Object System.Windows.Forms.OpenFileDialog
  $dialog.Title = "분석할 파일 선택"
  $dialog.Filter = "모든 파일 (*.*)|*.*"
  $dialog.CheckFileExists = $true
  $dialog.Multiselect = $false
  if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
    $targetTextBox.Text = $dialog.FileName
  }
  $dialog.Dispose()
}.GetNewClosure())

$folderButton.add_Click({
  $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
  $dialog.Description = "분석할 앱 디렉터리를 선택하세요."
  $dialog.ShowNewFolderButton = $false
  if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
    $targetTextBox.Text = $dialog.SelectedPath
  }
  $dialog.Dispose()
}.GetNewClosure())

$runButton.add_Click({
  $selectedCommand = $script:GuiCommands[$commandCombo.SelectedIndex]
  $rawTargetPath = $targetTextBox.Text.Trim()
  if ([string]::IsNullOrWhiteSpace($rawTargetPath)) {
    [System.Windows.Forms.MessageBox]::Show(
      "분석 대상의 경로를 입력하거나 선택하세요.",
      "대상 필요",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    return
  }
  try {
    $targetPath = [System.IO.Path]::GetFullPath($rawTargetPath)
  }
  catch {
    [System.Windows.Forms.MessageBox]::Show(
      "유효한 Windows 파일 또는 폴더 경로를 입력하세요.`r`n$($_.Exception.Message)",
      "잘못된 경로",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    return
  }
  if (-not [Rea.WindowsGui.ReaGuiProcessRunner]::IsLocalPath($targetPath)) {
    [System.Windows.Forms.MessageBox]::Show(
      "네트워크 경로는 지원하지 않습니다. 로컬 드라이브의 파일 또는 폴더를 선택하세요.",
      "로컬 경로 필요",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    return
  }
  if (-not (Test-Path -LiteralPath $targetPath)) {
    [System.Windows.Forms.MessageBox]::Show(
      "분석 대상을 찾을 수 없습니다:`r`n$targetPath",
      "대상을 찾을 수 없음",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    return
  }
  try {
    $isLocalTarget = [Rea.WindowsGui.ReaGuiProcessRunner]::IsLocalTargetPath($targetPath)
  }
  catch {
    [System.Windows.Forms.MessageBox]::Show(
      "분석 대상의 실제 경로를 확인할 수 없습니다.`r`n$($_.Exception.Message)",
      "경로 확인 실패",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    return
  }
  if (-not $isLocalTarget) {
    [System.Windows.Forms.MessageBox]::Show(
      "네트워크 경로는 지원하지 않습니다. 실제 대상이 로컬 드라이브에 있는 파일 또는 폴더를 선택하세요.",
      "로컬 경로 필요",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    return
  }
  if (-not $selectedCommand.AllowsDirectory -and (Test-Path -LiteralPath $targetPath -PathType Container)) {
    [System.Windows.Forms.MessageBox]::Show(
      "선택한 작업에는 파일 경로가 필요합니다.",
      "파일 필요",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    return
  }

  $isJavaScriptTarget = Test-ReaJavaScriptTarget -TargetPath $targetPath
  $provider = "auto"
  if ($selectedCommand.UsesProvider -and -not $isJavaScriptTarget) {
    switch ($providerCombo.SelectedIndex) {
      1 { $provider = "ghidra" }
      2 { $provider = "ida" }
    }
  }
  try {
    $arguments = @(
      Get-ReaArguments -CommandId $selectedCommand.Id -TargetPath $targetPath `
        -Provider $provider -IsJavaScriptTarget:$isJavaScriptTarget
    )
  }
  catch {
    $statusLabel.Text = "명령 구성 실패"
    $errorsBox.AppendText("$($_.Exception.Message)`r`n")
    return
  }

  $resultsBox.Clear()
  $errorsBox.Clear()
  $statusLabel.Text = "실행 중: $($selectedCommand.Label)"
  $runButton.Enabled = $false
  $commandCombo.Enabled = $false
  $targetTextBox.Enabled = $false
  $fileButton.Enabled = $false
  $folderButton.Enabled = $false
  $providerCombo.Enabled = $false
  $processState.IsRunning = $true
  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = $nodeExecutable
  $startInfo.WorkingDirectory = $packageRoot
  $allArguments = @($reaEntryPoint) + @($arguments)
  $startInfo.Arguments = [string]::Join(" ", [string[]]@(
    $allArguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }
  ))
  try {
    $processState.Runner = New-Object Rea.WindowsGui.ReaGuiProcessRunner($startInfo)
    $processState.Runner.Start()
    $outputTimer.Start()
  }
  catch {
    if ($null -ne $processState.Runner) {
      $processState.Runner.Dispose()
      $processState.Runner = $null
    }
    $processState.IsRunning = $false
    $runButton.Enabled = $true
    $commandCombo.Enabled = $true
    $targetTextBox.Enabled = $true
    $fileButton.Enabled = $true
    $folderButton.Enabled = $selectedCommand.AllowsDirectory
    $updateProviderAvailability.Invoke()
    $statusLabel.Text = "실행 실패"
    $errorsBox.AppendText("$($_.Exception.Message)`r`n")
  }
}.GetNewClosure())

$clearButton.add_Click({
  if (-not $processState.IsRunning) {
    $resultsBox.Clear()
    $errorsBox.Clear()
    $statusLabel.Text = "준비됨"
  }
}.GetNewClosure())

$form.add_FormClosing({
  param($sender, $eventArgs)
  if ($processState.IsRunning -and $eventArgs.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) {
    [System.Windows.Forms.MessageBox]::Show(
      "분석이 끝날 때까지 기다린 뒤 창을 닫으세요. Windows 종료 시에는 실행 중인 CLI 작업도 함께 종료됩니다.",
      "분석 진행 중",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    $eventArgs.Cancel = $true
  }
}.GetNewClosure())

[void]$form.ShowDialog()
$outputTimer.Dispose()
$form.Dispose()

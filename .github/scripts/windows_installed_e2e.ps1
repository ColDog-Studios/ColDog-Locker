param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [Parameter(Mandatory = $true)][string]$SetupPath,
    [Parameter(Mandatory = $true)][string]$BaselineMsiPath,
    [Parameter(Mandatory = $true)][string]$BaselineSetupPath,
    [Parameter(Mandatory = $true)][string]$ReviewScripts,
    [Parameter(Mandatory = $true)][ValidateSet("X64", "Arm64")][string]$ExpectedArchitecture
)

$ErrorActionPreference = "Stop"

function Invoke-InstallerProcess {
    param([string]$FilePath, [string[]]$Arguments)

    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "Installer '$FilePath' exited with code $($process.ExitCode)."
    }
}

$msi = (Resolve-Path $MsiPath).Path
$setup = (Resolve-Path $SetupPath).Path
$baselineMsi = (Resolve-Path $BaselineMsiPath).Path
$baselineSetup = (Resolve-Path $BaselineSetupPath).Path
$scripts = (Resolve-Path $ReviewScripts).Path
$installRoot = Join-Path $env:ProgramFiles "ColDog Studios\ColDog Locker"
$cli = Join-Path $installRoot "cdlocker.exe"
$gui = Join-Path $installRoot "ColDogLocker.exe"
$userDataRoot = Join-Path $env:LOCALAPPDATA "ColDog Studios\ColDog Locker"
$defaultLockerRoot = Join-Path $env:USERPROFILE "Documents\ColDog Locker"
$marker = Join-Path $userDataRoot "preserve-on-uninstall.txt"
$work = Join-Path $env:RUNNER_TEMP "cdlocker-installed-e2e"

foreach ($path in @($userDataRoot, $defaultLockerRoot)) {
    if (Test-Path $path) {
        throw "Refusing destructive installer validation because '$path' existed before the test."
    }
}

foreach ($artifact in @($msi, $setup, $baselineMsi, $baselineSetup)) {
    $signature = Get-AuthenticodeSignature $artifact
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned) {
        throw "Expected unsigned prerelease artifact '$artifact', got signature status '$($signature.Status)'."
    }
}

Invoke-InstallerProcess $baselineSetup @("/quiet", "/norestart")
New-Item -ItemType Directory -Force -Path $userDataRoot | Out-Null
Set-Content -Path $marker -Value "preserve"

# The current setup must major-upgrade the older MSI without invoking the optional
# destructive uninstall action from the package it replaces.
Invoke-InstallerProcess $setup @("/quiet", "/norestart")
if (!(Test-Path $cli) -or !(Test-Path $gui)) {
    throw "The installer did not publish both application entry points."
}
if (!(Test-Path $marker)) {
    throw "Major upgrade removed per-user application data."
}

$devOutput = & $cli dev 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $devOutput -notmatch "Architecture:\s+$ExpectedArchitecture") {
    throw "Installed CLI architecture check failed. Output:`n$devOutput"
}

python (Join-Path $scripts "cli_e2e.py") --cli $cli --work-dir $work
if ($LASTEXITCODE -ne 0) {
    throw "Installed CLI E2E failed with exit code $LASTEXITCODE."
}

$guiLog = Join-Path $env:RUNNER_TEMP "coldog-locker-gui.log"
$guiProcess = Start-Process -FilePath $gui -RedirectStandardOutput $guiLog -RedirectStandardError "$guiLog.err" -PassThru
Start-Sleep -Seconds 8
if ($guiProcess.HasExited) {
    $stderr = Get-Content "$guiLog.err" -Raw -ErrorAction SilentlyContinue
    throw "Installed GUI exited during startup with code $($guiProcess.ExitCode). $stderr"
}
Stop-Process -Id $guiProcess.Id -Force
$guiProcess.WaitForExit()

# A lower product version must not replace the current package.
$downgrade = Start-Process -FilePath msiexec.exe -ArgumentList @("/i", $baselineMsi, "/qn", "/norestart") -Wait -PassThru
if ($downgrade.ExitCode -in @(0, 3010)) {
    throw "Windows Installer unexpectedly accepted a package downgrade."
}
& $cli --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Installed CLI failed after the rejected downgrade."
}

Invoke-InstallerProcess msiexec.exe @("/i", $msi, "/qn", "/norestart", "REINSTALL=ALL", "REINSTALLMODE=vomus")
& $cli --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Installed CLI failed after MSI reinstall."
}

Invoke-InstallerProcess msiexec.exe @("/x", $msi, "/qn", "/norestart")
if ((Test-Path $cli) -or (Test-Path $gui)) {
    throw "Uninstall left installed application entry points behind."
}
if (!(Test-Path $marker)) {
    throw "Default uninstall removed per-user application data."
}

Remove-Item $userDataRoot -Recurse -Force
Invoke-InstallerProcess msiexec.exe @("/i", $msi, "/qn", "/norestart")
New-Item -ItemType Directory -Force -Path $userDataRoot, $defaultLockerRoot | Out-Null
Set-Content -Path (Join-Path $userDataRoot "delete-on-opt-in.txt") -Value "delete"
Set-Content -Path (Join-Path $defaultLockerRoot "delete-on-opt-in.txt") -Value "delete"
Invoke-InstallerProcess msiexec.exe @("/x", $msi, "/qn", "/norestart", "REMOVE_USER_DATA_ON_UNINSTALL=1")
if ((Test-Path $userDataRoot) -or (Test-Path $defaultLockerRoot)) {
    throw "Explicit opt-in uninstall did not remove both documented application-data directories."
}

Write-Host "Installed Windows CLI, GUI startup, upgrade, downgrade refusal, repair, unsigned-package, and both uninstall modes passed."

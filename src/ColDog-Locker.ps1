#MARK: ----------[ Assemblies ]----------#

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Import the necessary .NET methods
Add-Type -TypeDefinition @"
    using System.IO;
    using System.Security.Cryptography;

    public class cdlEncryptor
    {
        public static void EncryptDirectory(string directory, string password)
        {
            foreach (string file in Directory.GetFiles(directory))
            {
                EncryptFile(file, password);
            }

            foreach (string subDirectory in Directory.GetDirectories(directory))
            {
                EncryptDirectory(subDirectory, password);
            }
        }

        public static void EncryptFile(string inputFile, string password)
        {
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76}, 10000, HashAlgorithmName.SHA256);
                aes.Key = pdb.GetBytes(32);
                aes.IV = pdb.GetBytes(16);

                using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
                {
                    using (FileStream fsCrypt = new FileStream(inputFile + ".enc", FileMode.Create))
                    {
                        using (CryptoStream cs = new CryptoStream(fsCrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            byte[] buffer = new byte[1048576]; // 1MB buffer
                            int read;
                            while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                cs.Write(buffer, 0, read);
                            }
                        }
                    }
                }

                File.Delete(inputFile);
                File.Move(inputFile + ".enc", inputFile);
            }
        }

        public static void DecryptDirectory(string directory, string password)
        {
            foreach (string file in Directory.GetFiles(directory))
            {
                DecryptFile(file, password);
            }

            foreach (string subDirectory in Directory.GetDirectories(directory))
            {
                DecryptDirectory(subDirectory, password);
            }
        }

        public static void DecryptFile(string inputFile, string password)
        {
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76}, 10000, HashAlgorithmName.SHA256);
                aes.Key = pdb.GetBytes(32);
                aes.IV = pdb.GetBytes(16);

                using (FileStream fsCrypt = new FileStream(inputFile, FileMode.Open))
                {
                    using (CryptoStream cs = new CryptoStream(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (var fsOut = new FileStream(inputFile + ".dec", FileMode.Create))
                        {
                            byte[] buffer = new byte[1048576]; // 1MB buffer
                            int read;
                            while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                fsOut.Write(buffer, 0, read);
                            }
                        }
                    }
                }

                File.Delete(inputFile);
                File.Move(inputFile + ".dec", inputFile);
            }
        }
    }
"@

#MARK: ----------[ Variables ]----------#

$version = "v0.1.0-Beta"
$currentVersion = ($version.TrimStart("v")).TrimEnd("-Beta")
$dateMod = "7/4/2024"
$roamingConfig = "$env:AppData\ColDog Studios\ColDog Locker"
$localConfig = "$env:LocalAppData\ColDog Studios\ColDog Locker"
$cdlDir = Get-Location

$Host.UI.RawUI.WindowTitle = "ColDog Locker $version"

#MARK: ----------[ Main Functions ]----------#

function Show-Menu {
    while ($true) {
        Get-Settings
        Get-LockerMetadata
        Show-MenuTitle -subMenu "Main Menu"

        $menuChoices = " 1) New Locker`n" +
        " 2) Remove Locker`n" +
        " 3) Lock Locker`n" +
        " 4) Unlock Locker`n" +
        " 5) About ColDog Locker`n" +
        " 6) ColDog Locker Help`n" +
        " 7) Check for Updates`n" +
        " 9) Update ColDog Locker Settings`n"

        Write-Host "Choose an option from the following:`n" -ForegroundColor White
        Write-Host $menuChoices
        $menuChoice = Read-Host -Prompt ">"

        switch ($menuChoice) {
            1 { New-Locker }
            2 { Remove-Locker }
            3 { Protect-Locker }
            4 { Unprotect-Locker }
            5 { Show-About }
            6 { Show-Help }
            7 { Update-ColDogLocker }
            9 { Update-Settings }
            "dev" { Show-Dev }
            #"sysinfo" { Get-SystemInformation }
            default { Show-Message -type "Warning" -message "Please select a valid option." -title "ColDog Locker" }
        }
    }
}

#MARK: ----------[ New-Locker ]----------#
function New-Locker {
    Show-MenuTitle -subMenu "Main Menu > New File"

    # User Input
    $lockerName = Read-Host -Prompt "Locker Name"
    Write-Host "`n    Minimum Password Length: 8 characters"
    Write-Host "Recommended Password Length: 15 characters`n"
    $pass = Read-Host -Prompt " Locker Password" -AsSecureString
    $passConfirm = Read-Host -Prompt "Confirm Password" -AsSecureString

    # Convert SecureString to Clear Text for Passwords
    $passClear = Convert-SecureString2Text -secureString $pass
    $passConfirmClear = Convert-SecureString2Text -secureString $passConfirm

    # Check User Input, if all checks pass, configuration is created
    if ($lockerName -eq "" -or $pass -eq "" -or $passConfirm -eq "") {
        Show-Message -type "Warning" -message "Input cannot be empty, blank, or null. Please try again." -title "ColDog Locker"
    }
    elseif ($pass.Length -lt 8) {
        Show-Message -type "Warning" -message "Password must be at least 8 characters long. Please try again." -title "ColDog Locker"
    }
    elseif ("$passClear" -cne "$passConfirmClear") {
        Show-Message -type "Warning" -message "Passwords do not match. Please try again." -title "ColDog Locker"
    }
    elseif ("$passClear" -ceq "$passConfirmClear") {
        $passHash = Invoke-PasswordHashing -passClear $passClear
        $passClear = $null
        $passConfirmClear = $null
        Add-LockerMetadata -lockerName $lockerName -passHash $passHash
    }
    else {
        Show-Message -type "Warning" -message "Invalid input. Please try again." -title "ColDog Locker"
    }
}

#MARK: ----------[ Remove-Locker ]----------#
function Remove-Locker {
    $result = Show-Lockers -action "Remove"

    if (-not $result.success) { return }

    $selectedLocker = $result.selectedLocker

    # Show confirmation prompt
    $confirmation = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to remove $($selectedLocker.lockerName)?", "Remove Locker", "YesNo", "Warning")

    if ($confirmation -eq "Yes") { Remove-LockerMetadata }
}

#MARK: ----------[ Protect-Locker ]----------#
function Protect-Locker {
    $result = Show-Lockers -action "Lock"

    if (-not $result.success) { return }

    $selectedLocker = $result.selectedLocker

    while ($true) {
        $pass = Read-Host -Prompt "`nEnter the password to lock $($selectedLocker.lockerName)" -AsSecureString

        $passClear = Convert-SecureString2Text -SecureString $pass

        # Check if the password is null or empty. If not, hash the password
        if ($null -eq $passClear -or $passClear -eq "" ) {
            Add-LogEntry -message "Password cannot be empty, blank, or null." -level "Warning"
            Show-Message -type "Warning" -message "Password cannot be empty, blank, or null. Please try again." -title "ColDog Locker"
            continue
        }
        else { $passHash = Invoke-PasswordHashing -passClear $passClear }

        if ($selectedLocker.password -ceq $passHash) {
            try {
                # Encrypt the Locker by calling the EncryptDirectory method
                [cdlEncryptor]::EncryptDirectory($selectedLocker.cdlLocation, $passClear)
                $passClear = $null

                # Lock the Locker
                Set-ItemProperty -Path $selectedLocker.cdlLocation -Name Attributes -Value "Hidden, System"
                $selectedLocker.isLocked = $true
                Rename-Item -Path $selectedLocker.cdlLocation -NewName ".$($selectedLocker.lockerName)" | Out-Null
                $selectedLocker.cdlLocation = "$cdlDir\.$($selectedLocker.lockerName)"

                # Convert the updated array to JSON and write it to the file
                $json = $script:cdlLockers | ConvertTo-Json -Depth 3
                Set-Content -Path "$localConfig\lockers.json" -Value $json | Out-Null

                Add-LogEntry -message "Locker $($selectedLocker.lockerName) locked successfully." -level "Success"
                Show-Message -type "Info" -message "Locker $($selectedLocker.lockerName) locked successfully." -title "ColDog Locker"
                break
            }
            catch {
                # Handle any errors that occurred during the script execution
                Add-LogEntry -message "An error occurred while locking $selectedLocker.lockerName: $($_.Exception.Message)" -level "Error"
                Show-Message -type "Error" -message "An error occurred while locking $selectedLocker.lockerName: $($_.Exception.Message)" -title "Error - ColDog Locker"
                exit 1
            }
        }
        else {
            Add-LogEntry -message "Failed password attempt" -level "Warning"
            Show-Message -type "Warning" -message "Failed password atttept. Please try again." -title "Warning"
        }
    }
}

#MARK: ----------[ Unprotect-Locker ]----------#
function Unprotect-Locker {
    $result = Show-Lockers -action "Unlock"

    if (-not $result.success) { return }

    $selectedLocker = $result.selectedLocker
    $failedAttempts = 0

    while ($true) {
        # Show confirmation prompt
        $pass = Read-Host -Prompt "`nEnter the password to unlock $($selectedLocker.lockerName)" -AsSecureString

        $passClear = Convert-SecureString2Text -secureString $pass

        # Check if the password is null or empty. If not, hash the password
        if ($null -eq $passClear -or $passClear -eq "" ) {
            Add-LogEntry -message "Password cannot be empty, blank, or null." -level "Warning"
            Show-Message -type "Warning" -message "Password cannot be empty, blank, or null. Please try again." -title "ColDog Locker"
            continue
        }
        else { $passHash = Invoke-PasswordHashing -passClear $passClear }

        if ($selectedLocker.password -ceq $passHash) {
            try {
                # Decrypt the Locker by calling the DecryptDirectory method
                [cdlEncryptor]::DecryptDirectory($selectedLocker.cdlLocation, $passClear)
                $passClear = $null

                # Unlock the Locker
                Set-ItemProperty -Path $selectedLocker.cdlLocation -Name Attributes -Value "Normal"
                $selectedLocker.isLocked = $false
                Rename-Item -Path $selectedLocker.cdlLocation -NewName $selectedLocker.lockerName | Out-Null
                $selectedLocker.cdlLocation = "$cdlDir\$($selectedLocker.lockerName)"

                # Convert the updated array to JSON and write it to the file
                $json = $script:cdlLockers | ConvertTo-Json -Depth 3
                Set-Content -Path "$localConfig\lockers.json" -Value $json

                Add-LogEntry -message "Locker $($selectedLocker.lockerName) unlocked successfully." -level "Success"
                Show-Message -type "Info" -message "Locker $($selectedLocker.lockerName) unlocked successfully." -title "ColDog Locker"
                break
            }
            catch {
                # Handle any errors that occurred during the script execution
                Add-LogEntry -message "An error occurred while unlocking $($selectedLocker.lockerName): $($_.Exception.Message)" -level "Error"
                Show-Message -type "Error" -message "An error occurred while unlocking $($selectedLocker.lockerName): $($_.Exception.Message)" -title "Error - ColDog Locker"
                exit 1
            }
        }
        else {
            $failedAttempts++
            if ($failedAttempts -ge 10) {
                Add-LogEntry -message "10 failed password attempts. Locking $selectedLocker.lockerName permanently." -level "Error"
                Show-Message -type "Error" -message "10 failed password attempts. Locking $selectedLocker.lockerName permanently." -title "ColDog Locker"
                break
            }
            else {
                $remainingAttempts = 10 - $failedAttempts
                Add-LogEntry -message "Failed password attempt. $remainingAttempts attempts remaining." -level "Warning"
                Show-Message -type "Warning" -message "Failed password atttept. $remainingAttempts attempts remaining." -title "Warning"
            }
        }
    }
}

#MARK: ----------[ Utility Functions ]----------#

function Show-About {
    $message = "The idea of ColDog Locker was created by Collin 'ColDog' Laney on 11/17/21, for a security project in Cybersecurity class.`n" +
    "Collin Laney is the Founder and CEO of ColDog Studios"

    Show-Message -type "Info" -message $message -title "About ColDog Locker"
}

function Show-Help {
    $message = "ColDog Locker is a simple file locker that allows you to encrypt and decrypt the contents of a 'managed' directory with a password.`n`n" +
    "To lock a directory, select the 'Lock Locker' option from the main menu and follow the prompts.`n`n" +
    "To unlock a directory, select the 'Unlock Locker' option from the main menu and follow the prompts.`n`n" +
    "To remove a directory from ColDog Locker management, select the 'Remove Locker' option from the main menu and follow the prompts.`n`n" +
    "To check for updates, select the 'Check for Updates' option from the main menu."

    Show-Message -type "Info" -message $message -title "ColDog Locker Help"
}

function Update-ColDogLocker {
    param (
        [Parameter(Mandatory = $false)]
        [string]$owner = "ColDogStudios",

        [Parameter(Mandatory = $false)]
        [string]$repository = "ColDog-Locker",

        [Parameter(Mandatory = $false)]
        [string]$downloadDirectory = "$env:userprofile\Downloads",

        [Parameter(Mandatory = $false)]
        [string]$uri = "https://api.github.com/repos/$owner/$repository/releases/latest"
    )

    try {
        # Get the release info using the GitHub API
        $releaseInfo = Invoke-RestMethod -Uri $uri
        $downloadVersion = $releaseInfo.tag_name
        $latestVersion = ($downloadVersion.TrimStart("v")).TrimEnd("-alpha")
        #$asset = $releaseInfo.assets | Where-Object { $_.name -eq "ColDog_Locker_${downloadVersion}_setup.msi" }
        $asset = $releaseInfo.assets | Where-Object { $_.name -eq "ColDog_Locker_${downloadVersion}.exe" }

        # Check if the latest version is newer than the current version and prompt the user to download it if avaliable
        if ([version]$latestVersion -gt [version]$currentVersion) {
            $message = "A newer version is available: `n`n" +
            "Current Version: $currentVersion`n" +
            "Latest Version: $latestVersion`n`n" +
            "Do you want to download the latest version?"

            $updatePromptChoice = [System.Windows.Forms.MessageBox]::Show($message, "Update Available", "YesNo", "Question")

            if ("$updatePromptChoice" -eq "Yes" ) {
                try {
                    # Download the latest version
                    #$fileName = Join-Path $downloadDirectory "ColDog_Locker_${downloadVersion}_setup.msi"
                    $fileName = Join-Path $downloadDirectory "ColDog_Locker_${downloadVersion}.exe"
                    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $fileName

                    Add-LogEntry -message "Downloaded the latest version to: $fileName" -level "Success"
                    Show-Message -type "Info" -message "Downloaded the latest version to: $fileName.`nPlease run the installer to update ColDog Locker." -title "Download Complete"
                }
                catch {
                    Add-LogEntry -message "An error occurred while downloading the latest version: $($_.Exception.Message)" -level "Error"
                    Show-Message -type "Error" -message "An error occurred while downloading the latest version: $($_.Exception.Message)" -title "Error - ColDog Locker"
                    exit 1
                }
            }
        }
        else {
            $message = "ColDog Locker is up to date: `n`n" +
            "Current Version: $currentVersion `n" +
            "Latest Version: $latestVersion"

            #Add-LogEntry -message "Successfully checked for updates: $($message)" -level "Success"
        }
    }
    catch {
        # Handle any errors that occurred during the script execution
        Add-LogEntry -Message "An error occurred while checking for updates: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred while checking for updates: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit 1
    }
}

function Show-Dev {
    $message = "Current Version: $version `n" +
    "Date Modified: $dateMod `n" +
    "Alpha Build `n`n" +
    "Metadata Location: $localConfig`n" +
    "Old Metadata Location: $roamingConfig"

    Show-Message -type "Info" -message $message -title "Development"
}

#MARK: ----------[ Reference Functions ]----------#

function Show-MenuTitle {
    param (
        [Parameter(Mandatory = $true)]
        [string]$subMenu
    )

    Clear-Host
    $width = (Get-Host).UI.RawUI.WindowSize.Width
    $title = "ColDog Locker $version"
    $copyright = "Copyright (c) ColDog Studios. All Rights Reserved."
    $line = "#" * $width
    $separatorLength = $width / 2.2
    $separator = "-" * $separatorLength
    $emptyLine = " " * $width

    Write-Host $line -ForegroundColor Blue
    Write-Host $emptyLine
    Write-Host ($title.PadLeft(($width + $title.Length) / 2)).PadRight($width) -ForegroundColor White
    Write-Host ($subMenu.PadLeft(($width + $subMenu.Length) / 2)).PadRight($width) -ForegroundColor Yellow
    Write-Host ($separator.PadLeft(($width + $separator.Length) / 2)).PadRight($width) -ForegroundColor DarkGray
    Write-Host ($copyright.PadLeft(($width + $copyright.Length) / 2)).PadRight($width) -ForegroundColor White
    Write-Host $emptyLine
    Write-Host $line -ForegroundColor Blue
    Write-Host $emptyLine
}

function Convert-SecureString2Text {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$secureString
    )

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    $passClear = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    return $passClear
}

function Invoke-PasswordHashing {
    param (
        [Parameter(Mandatory = $true)]
        [string]$passClear
    )

    try {
        # Convert the input string to a byte array
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($passClear)

        # Compute the SHA-256 hash of the byte array
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash256 = $sha256.ComputeHash($bytes)

        # Convert the SHA-256 hash to a hexadecimal string
        $hex256 = [System.BitConverter]::ToString($hash256).Replace("-", "").ToLower()

        # Compute the SHA-512 hash of the SHA-256 hash
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        $hash512 = $sha512.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hex256))

        # Convert the SHA-512 hash to a hexadecimal string
        $hex512 = [System.BitConverter]::ToString($hash512).Replace("-", "").ToLower()

        return $hex512
    }
    catch {
        # Handle any errors that occurred during the script execution
        Add-LogEntry -Message "An error occurred with password hashing: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred with password hashing: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit 1
    }
}

#MARK: ----------[ Settings ]----------#
function Initialize-Settings {
    $autoUpdate = [System.Windows.Forms.MessageBox]::Show("Automatically check for updates on ColDog Locker startup?", "Auto Update", "YesNo", "Question")
    
    if ($autoUpdate -eq "Yes") { $autoUpdate = $true }
    elseif ($autoUpdate -eq "No") { $autoUpdate = $false }

    $script:cdlSettings = [PSCustomObject] @{
        debugMode  = $false
        maxLogSize = 10485760 # 10MB
        autoUpdate = $autoUpdate
    }

    $script:cdlSettings | ConvertTo-Json | Set-Content "$localConfig\settings.json"
}

function Get-Settings {
    if (Test-Path "$localConfig\settings.json") {
        $script:cdlSettings = Get-Content "$localConfig\settings.json" | ConvertFrom-Json
    }
    else { Initialize-Settings }
}

function Update-Settings {
    param (
        [Parameter(Mandatory = $false)]
        [bool]$DebugMode,

        [Parameter(Mandatory = $false)]
        [int]$MaxLogSize,

        [Parameter(Mandatory = $false)]
        [bool]$AutoUpdate
    )

    $debugMode = [System.Windows.Forms.MessageBox]::Show("Enable Debug Mode?", "Debug Mode", "YesNo", "Question")

    if ($debugMode -eq "Yes") { $script:cdlSettings.debugMode = $true }
    elseif ($debugMode -eq "No") { $script:cdlSettings.debugMode = $false }

    $maxLogSize = Read-Host "`nEnter the maximum log file size in MB"
    $maxLogSize = [int]$maxLogSize
    $script:cdlSettings.maxLogSize = $maxLogSize * 1048576

    $autoUpdate = [System.Windows.Forms.MessageBox]::Show("Enable Auto Update?", "Auto Update", "YesNo", "Question")

    if ($autoUpdate -eq "Yes") { $script:cdlSettings.autoUpdate = $true }
    elseif ($autoUpdate -eq "No") { $script:cdlSettings.autoUpdate = $false }

    # Update the settings file with the new settings
    $script:cdlSettings | ConvertTo-Json | Set-Content "$localConfig\settings.json"

    Add-LogEntry -message "Settings updated successfully. Debug mode: $debugMode. Max log file size: $($script:cdlSettings.maxLogSize). Auto update: $autoUpdate" -level "Success"
    Show-Message -type "Info" -message "Settings updated successfully." -title "ColDog Locker"
}

#MARK: ----------[ Locker Manipulation ]----------#
function Add-LockerMetadata {
    param (
        [Parameter(Mandatory = $true)]
        [string]$lockerName,

        [Parameter(Mandatory = $true)]
        [string]$passHash
    )

    # Check if the lockers.json file exists, if not, create an empty array
    if (-not (Test-Path "$localConfig\lockers.json")) {
        $script:cdlLockers = @()

        # Ensure the content is an array
        if ($script:cdlLockers -isnot [System.Collections.IEnumerable]) {
            $script:cdlLockers = @($script:cdlLockers)
        }
    }

    # Check if the locker name already exists
    $lockerExists = $script:cdlLockers | Where-Object { $_.lockerName -eq $lockerName }

    if ($lockerExists) {
        Add-LogEntry -message "A locker with the name '$lockerName' already exists." -level "Warning"
        Show-Message -type "Warning" -message "A locker with the name '$lockerName' already exists. Please choose a different name." -title "ColDog Locker"
        return
    }

    try {
        # Create a hashtable with the guid, Locker name, password, location, and isLocked attribute
        $cdlLocker = [PSCustomObject] @{
            guid        = [guid]::NewGuid().ToString()
            LockerName  = $lockerName
            password    = $passHash
            cdlLocation = "$cdlDir\$lockerName"
            isLocked    = $false
        }

        # Add the new locker to the array
        $script:cdlLockers += $cdlLocker

        # Convert the array to JSON and write it to the file
        $json = $script:cdlLockers | ConvertTo-Json -Depth 3
        Set-Content -Path "$localConfig\lockers.json" -Value $json | Out-Null

        # Check if the directory already exists, otherwise create it
        if (Test-Path "$cdlDir\$lockerName") {
            Add-LogEntry -message "A directory with the name '$lockerName' already exists. Ignoring creating a new directory. " -level "Info"
        }
        else { New-Item -ItemType Directory -Path "$cdlDir\$lockerName" | Out-Null }

        Add-LogEntry -message "$lockerName created successfully." -level "Success"
        Show-Message -type "Info" -message "$lockerName created successfully." -title "ColDog Locker"
    }
    catch {
        # Handle any errors that occurred during the script execution
        Add-LogEntry -Message "An error occurred while adding $lockerName to the JSON table: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred while adding $lockerName to the JSON table: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit 1
    }
}

function Remove-LockerMetadata {
    try {
        # Remove the selected Locker-password pair
        $script:cdlLockers = $script:cdlLockers | Where-Object { $_.lockerName -ne $selectedLocker.lockerName }

        # Convert the updated array to JSON and write it to the file
        $json = $script:cdlLockers | ConvertTo-Json -Depth 3
        Set-Content -Path "$localConfig\lockers.json" -Value $json

        Add-LogEntry -message "Locker $($selectedLocker.lockerName) removed successfully." -level "Success"
        Show-Message -type "Info" -message "Locker $($selectedLocker.lockerName) removed successfully." -title "ColDog Locker"
    }
    catch {
        # Handle any errors that occurred during the script execution
        Add-LogEntry -Message "An error occurred while removing $selectedLocker to the JSON table: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred while removing $selectedLocker to the JSON table: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit 1
    }
}

function Get-LockerMetadata {
    try {
        if (-not (Test-Path "$localConfig\lockers.json")) { return }

        $script:cdlLockers = Get-Content "$localConfig\lockers.json" | ConvertFrom-Json

        # Ensure the content is an array
        if ($script:cdlLockers -isnot [System.Collections.IEnumerable]) {
            $script:cdlLockers = @($script:cdlLockers)
        }
    }
    catch {
        # Handle any errors that occurred during the script execution
        Add-LogEntry -message "An error occurred while reading the lockers from the JSON file: $($_.Exception.Message)" -level "Error"
        Show-Message -type "Error" -message "An error occurred while reading the lockers from the JSON file: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit 1
    }
}

function Show-Lockers {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Remove", "Lock", "Unlock")]
        [string]$action
    )

    Get-Settings
    Get-LockerMetadata

    # Specify Locked and Unlocked lockers
    $unlockedLockers = $script:cdlLockers | Where-Object { $_.isLocked -eq $false }
    $unlockedLockers = @($unlockedLockers)
    $lockedLockers = $script:cdlLockers | Where-Object { $_.isLocked -eq $true }
    $lockedLockers = @($lockedLockers)

    # Check if there are any lockers of each type
    if ($null -eq $script:cdlLockers -or $script:cdlLockers.Count -eq 0) {
        Show-Message -type "Warning" -message "There are no lockers created." -title "ColDog Locker"
        return @{ success = $false }
    }
    elseif ($action -eq "Lock" -and ($null -eq $unlockedLockers -or $unlockedLockers.Count -eq 0)) {
        Show-Message -type "Warning" -message "There are no unlocked lockers to lock." -title "ColDog Locker"
        return @{ success = $false }
    }
    elseif ($action -eq "Unlock" -and ($null -eq $lockedLockers -or $lockedLockers.Count -eq 0)) {
        Show-Message -type "Warning" -message "There are no locked lockers to unlock." -title "ColDog Locker"
        return @{ success = $false }
    }

    Show-MenuTitle -subMenu "Main Menu > $action Locker"

    try {
        # Display each Locker name to the console based on the action
        switch ($action) {
            "Remove" {
                Write-Host "Unlocked Lockers:`n"
                for ($i = 0; $i -lt $unlockedLockers.Count; $i++) {
                    Write-Host "$($i + 1). $($unlockedLockers[$i].lockerName)"
                }
            }
            "Lock" {
                Write-Host "Unlocked Lockers:`n"
                for ($i = 0; $i -lt $unlockedLockers.Count; $i++) {
                    Write-Host "$($i + 1). $($unlockedLockers[$i].lockerName)"
                }
            }
            "Unlock" {
                Write-Host "Locked Lockers:`n"
                for ($i = 0; $i -lt $lockedLockers.Count; $i++) {
                    Write-Host "$($i + 1). $($lockedLockers[$i].lockerName)"
                }
            }
        }

        # Prompt the user to choose a Locker to remove, lock, or unlock
        $selectedLockerIndex = Read-Host "`nEnter the number corresponding to the locker you want to $($action.ToLower())"

        # Validate user input
        if (-not [int]::TryParse($selectedLockerIndex, [ref]$null)) {
            Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
            return @{ success = $false }
        }

        $selectedLockerIndex = [int]$selectedLockerIndex - 1

        # Check if the selected index is within the valid range
        switch ($action) {
            "Remove" {
                if ($selectedLockerIndex -lt 0 -or $selectedLockerIndex -ge $script:cdlLockers.Count) {
                    Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
                    return @{ success = $false }
                }
            }
            "Lock" {
                if ($selectedLockerIndex -lt 0 -or $selectedLockerIndex -ge $unlockedLockers.Count) {
                    Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
                    return @{ success = $false }
                }
            }
            "Unlock" {
                if ($selectedLockerIndex -lt 0 -or $selectedLockerIndex -ge $lockedLockers.Count) {
                    Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
                    return @{ success = $false }
                }
            }
        }

        # Show confirmation prompt
        switch ($action) {
            "Remove" { $selectedLocker = $script:cdlLockers[$selectedLockerIndex] }
            "Lock" { $selectedLocker = $unlockedLockers[$selectedLockerIndex] }
            "Unlock" { $selectedLocker = $lockedLockers[$selectedLockerIndex] }
        }

        return @{ success = $true; selectedLocker = $selectedLocker }
    }
    catch {
        # Handle any errors that occurred during the script execution
        Add-LogEntry -message "An error occurred while $($action)ing $($selectedLocker): $($_.Exception.Message)" -level "Error"
        Show-Message -type "Error" -message "An error occurred while $($action)ing $($selectedLocker): $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit 1
    }
}

#MARK: ----------[ Logging ]----------#
function Add-LogEntry {
    param (
        [Parameter(Mandatory = $true)]
        [string]$message,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$level,

        [Parameter(Mandatory = $false)]
        [string]$logDirectory = "$localConfig\logs"
    )

    # Ensure the log folder exists
    if (!(Test-Path -Path $logDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $logDirectory
    }

    # Create the log entry
    $logEntry = "[$(Get-Date)] [$level] $message"

    # If Debug mode is enabled, add the line of code causing the error to the log entry
    if ($script:cdlSettings.debugMode) {
        $logEntry += " Line: $($Error[0].InvocationInfo.ScriptLineNumber)"
    }

    # Write the log entry to the level-specific log file and the combined log file
    Add-Content -Path "$logDirectory\cdl$level.log" -Value $logEntry
    Add-Content -Path "$logDirectory\cdl.log" -Value $logEntry
}

function Resize-Log {
    param (
        [Parameter(Mandatory = $false)]
        [string]$logDirectory = "$localConfig\logs"
    )

    try {
        # Resize each log file if it's larger than 10MB
        Get-ChildItem -Path $logDirectory -Filter "*.log" | ForEach-Object {
            $logFilePath = $_.FullName

            # Get the file size in bytes
            $fileSizeBytes = (Get-Item $logFilePath).Length

            # Convert the file size to megabytes
            $fileSizeMB = $fileSizeBytes / 1MB

            # Check if the file size is greater than 10MB
            if ($fileSizeMB -gt 10) {
                # Keep the last 1000 lines and overwrite the file
                Get-Content $logFilePath | Select-Object -Last 1000 | Set-Content $logFilePath
            }
        }
    }
    # catch if no log files exist
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-LogEntry -message "No log files found in the log directory." -level "Info"
        return
    }
    catch {
        # Handle any errors that occurred during the script execution
        Add-LogEntry -message "An error occurred while resizing the log files: $($_.Exception.Message)" -level "Error"
        Show-Message -type "Error" -message "An error occurred while resizing the log files: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit 1
    }
}

#MARK: ----------[ Msg Boxes ]----------#
function Show-Message {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$type,

        [Parameter(Mandatory = $true)]
        [string]$message,

        [Parameter(Mandatory = $true)]
        [string]$title
    )

    switch ($type) {
        "Info" { [System.Windows.Forms.MessageBox]::Show($message, $title, "OK", "Information") | Out-Null }
        "Warning" { [System.Windows.Forms.MessageBox]::Show($message, $title, "OK", "Warning") | Out-Null }
        "Error" { [System.Windows.Forms.MessageBox]::Show($message, $title, "OK", "Error") | Out-Null }
    }
}

#MARK: ----------[ Initialization ]----------#

# Create CDL directories if they do not already exist
#if (-not(Test-Path "$roamingConfig" -PathType Container)) { New-Item -ItemType Directory "$roamingConfig" }
if (-not(Test-Path "$localConfig" -PathType Container)) { New-Item -ItemType Directory "$localConfig" }

Get-Settings
Get-LockerMetadata

if (Test-Path "$localConfig\logs\*.log") { Resize-Log }
if ($script:cdlSettings.autoUpdate) { Update-ColDogLocker }

#MARK: ----------[ Run Program ]----------#

Show-Menu

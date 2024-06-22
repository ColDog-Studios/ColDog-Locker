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

# Use the cdlEncryptor class to encrypt and decrypt directories
#$encryptionPassword = "your encryption password"
#$inputDirectory = "C:\\Users\\ColDog\\Documents\\GitHub\\ColDog-Locker-Source\\Private"
#
#[cdlEncryptor]::EncryptDirectory($inputDirectory, $encryptionPassword)
#[cdlEncryptor]::DecryptDirectory($inputDirectory, $encryptionPassword)

#MARK: ----------[ Variables ]----------#

$version = "v0.0.5-Alpha"
$currentVersion = ($version.TrimStart("v")).TrimEnd("-Alpha")
$dateMod = "6/15/2024"
$roamingConfig = "$env:AppData\ColDog Studios\ColDog Locker"
$localConfig = "$env:LocalAppData\ColDog Studios\ColDog Locker"
$cdlDir = Get-Location

$Host.UI.RawUI.WindowTitle = "ColDog Locker $version"

#MARK: ----------[ Initialization ]----------#

# Create CDL directories if they do not already exist
if (-not(Test-Path "$roamingConfig" -PathType Container)) { New-Item -ItemType Directory "$roamingConfig" }
if (-not(Test-Path "$localConfig" -PathType Container)) { New-Item -ItemType Directory "$localConfig" }

#MARK: ----------[ Main Functions ]----------#

function Show-cdlMenu {
    while ($true) {
        # Call Functions
        Show-MenuTitle -subMenu "Main Menu"

        $menuChoices = " 1) New Folder`n" +
        " 2) Remove Folder`n" +
        " 3) Lock Folder`n" +
        " 4) Unlock Folder`n" +
        " 5) About ColDog Locker`n" +
        " 6) ColDog Locker Help`n" +
        " 7) Check for Updates`n"

        Write-Host "Choose an option from the following:`n" -ForegroundColor White
        Write-Host $menuChoices
        $menuChoice = Read-Host -Prompt ">"

        switch ($menuChoice) {
            1 { New-cdlFolder }
            2 { Remove-cdlFolder }
            3 { Lock-CDL }
            4 { Unlock-CDL }
            5 { Get-cdlAbout }
            6 { Get-cdlHelp }
            7 { Get-cdlUpdates }
            #"log" { Edit-cdlLog }
            "dev" { Get-cdlDeveloperInfo }
            #"sysinfo" { Get-SystemInformation }
            default {
                Show-Message -type "Warning" -message "Please select a valid option." -title "ColDog Locker"
            }
        }
    }
}

#MARK: ----------[ New-cdlFolder ]----------#
function New-cdlFolder {
    # Call Functions
    Get-FolderPasswordPairs
    Show-MenuTitle -subMenu "Main Menu > New File"

    # User Input
    $script:inputFolderName = Read-Host -Prompt "Locker Name"
    Write-Host "`n    Minimum Password Length: 8 characters"
    Write-Host "Recommended Password Length: 15 characters`n"
    $inputPassword = Read-Host -Prompt " Locker Password" -AsSecureString
    $confirmPassword = Read-Host -Prompt "Confirm Password" -AsSecureString

    # Convert SecureString to Clear Text for Password
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($inputPassword)
    $script:inputPassClear = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    # Convert SecureString to Clear Text for Confirmation
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
    $confirmPassClear = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    # Check if folder name already exists
    $folderExists = $script:folderPasswordPairs | Where-Object { $_.FolderName -eq $script:inputFolderName }

    if ($folderExists) {
        Invoke-Log -message "A folder with the name '$script:inputFolderName' already exists." -level "Warning"
        Show-Message -type "Warning" -message "A folder with the name '$script:inputFolderName' already exists. Please choose a different name." -title "ColDog Locker"
        return
    }

    # Check User Input, if all checks pass, configuration is created
    if ($script:inputFolderName -eq "" -or $script:inputPassClear -eq "" -or $confirmPassClear -eq "") {
        Show-Message -type "Warning" -message "Input cannot be empty, blank, or null. Please try again." -title "ColDog Locker"
    }
    elseif ($inputPassClear.Length -lt 8) {
        Show-Message -type "Warning" -message "Password must be at least 8 characters long. Please try again." -title "ColDog Locker"
    }
    elseif ("$inputPassClear" -cne "$confirmPassClear") {
        Show-Message -type "Warning" -message "Passwords do not match. Please try again." -title "ColDog Locker"
    }
    elseif ("$inputPassClear" -ceq "$confirmPassClear") {
        try {
            # Password hashing
            Invoke-PassHash

            # Create config
            Add-FolderPasswordPair
        }
        catch {
            # Handle any errors that occurred during the script execution
            Invoke-Log -message "An error occurred while creating your folder: $($_.Exception.Message)" -level "Error"
            Show-Message -type "Error" -message "An error occurred while creating your folder: $($_.Exception.Message)" -title "Error - ColDog Locker"
            exit
        }
    }
    else {
        Show-Message -type "Warning" -message "Invalid input. Please try again." -title "ColDog Locker"
    }
}

#MARK: ----------[ Remove-cdlFolder ]----------#
function Remove-cdlFolder {
    # If the JSON file exists, read its content
    if (Test-Path "$roamingConfig\folders.json") {

        # Get and Convert the JSON content to an array of folder-password pairs
        $jsonContent = Get-Content "$roamingConfig\folders.json"
        $folderPasswordPairs = $jsonContent | ConvertFrom-Json

        # Ensure the content is an array
        if ($folderPasswordPairs -isnot [System.Collections.IEnumerable]) {
            $folderPasswordPairs = @($folderPasswordPairs)
        }

        # Check if there are any folder-password pairs
        if ($null -eq $folderPasswordPairs -or $folderPasswordPairs.Count -eq 0) {
            Show-Message -type "Warning" -message "There are no folders to remove." -title "ColDog Locker"
            return
        }

        # call functions
        Show-MenuTitle -subMenu "Main Menu > Remove Folder"

        # Display each folder name to the console
        Write-Host "Folders:"
        Write-Host ""
        for ($i = 0; $i -lt $folderPasswordPairs.Count; $i++) {
            Write-Host "$($i + 1). $($folderPasswordPairs[$i].folderName)"
        }

        # Prompt the user to choose a folder
        Write-Host ""
        $selectedPairIndex = Read-Host "Enter the number corresponding to the folder you want to remove"
        Write-Host ""

        # Validate user input
        if (-not [int]::TryParse($selectedPairIndex, [ref]$null)) {
            Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
            return
        }

        $selectedPairIndex = [int]$selectedPairIndex - 1

        # Check if the selected index is within the valid range
        if ($selectedPairIndex -lt 0 -or $selectedPairIndex -ge $folderPasswordPairs.Count) {
            Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
            return
        }

        # Show confirmation prompt
        $script:selectedPair = $folderPasswordPairs[$selectedPairIndex]

        Write-Host "You selected $($script:selectedPair.folderName)"
        Write-Host ""
        $confirmation = Read-Host "Are you sure you want to remove this folder? (y/N)"

        if ($confirmation -ieq 'y') {
            try {
                Remove-FolderPasswordPair
            }
            catch {
                # Handle any errors that occurred during the script execution
                Invoke-Log -message "An error occurred while removing $($script:selectedPair.folderName): $($_.Exception.Message)" -level "Error"
                Show-Message -type "Error" -message "An error occurred while removing $($script:selectedPair.folderName): $($_.Exception.Message)" -title "Error - ColDog Locker"
                exit
            }
        }
    }
    else {
        Show-Message -type "Warning" -message "There are no folders to remove." -title "ColDog Locker"
    }
}

#MARK: ----------[ Lock-CDL ]----------#
function Lock-CDL {
    # If the JSON file does not exist, return early, otherwise read its contents
    if (-not (Test-Path "$roamingConfig\folders.json")) {
        Show-Message -type "Warning" -message "There are no folders to lock." -title "ColDog Locker"
        return
    }

    # Get and Convert the JSON content to an array of folder-password pairs
    $jsonContent = Get-Content "$roamingConfig\folders.json"
    $folderPasswordPairs = $jsonContent | ConvertFrom-Json

    # Ensure the content is an array
    if ($folderPasswordPairs -isnot [System.Collections.IEnumerable]) {
        $folderPasswordPairs = @($folderPasswordPairs)
    }

    # Check if there are any folder-password pairs with the isLocked : false attribute
    $unlockedFolders = $folderPasswordPairs | Where-Object { $_.isLocked -eq $false }
    $unlockedFolders = @($unlockedFolders)

    if ($null -eq $unlockedFolders -or $unlockedFolders.Count -eq 0) {
        Show-Message -type "Warning" -message "There are no unlocked folders to lock." -title "ColDog Locker"
        return
    }

    # call functions
    Show-MenuTitle -subMenu "Main Menu > Lock Folder"

    # Display each folder name to the console
    Write-Host "Unlocked Folders:"
    Write-Host ""
    for ($i = 0; $i -lt $unlockedFolders.Count; $i++) {
        Write-Host "$($i + 1). $($unlockedFolders[$i].folderName)"
    }

    # Prompt the user to choose a folder
    Write-Host ""
    $selectedPairIndex = Read-Host "Enter the number corresponding to the folder you want to lock"

    # Validate user input
    if (-not [int]::TryParse($selectedPairIndex, [ref]$null)) {
        Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
        return
    }

    $selectedPairIndex = [int]$selectedPairIndex - 1

    # Check if the selected index is within the valid range
    if ($selectedPairIndex -lt 0 -or $selectedPairIndex -ge $unlockedFolders.Count) {
        Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
        return
    }

    while ($true) {
        # Show confirmation prompt
        $script:selectedPair = $unlockedFolders[$selectedPairIndex]

        Write-Host "`nYou selected $($script:selectedPair.folderName)"
        Write-Host ""
        $inputPassword = Read-Host -Prompt "Enter the password to lock $($script:selectedPair.folderName)" -AsSecureString

        # Convert SecureString to Clear Text for Password
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($inputPassword)
        $script:inputPassClear = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        # Check if the entered password is correct
        Invoke-PassHash

        if ($script:selectedPair.password -ceq $script:hex512) {
            try {
                # Encrypt the folder by calling the EncryptDirectory method
                [cdlEncryptor]::EncryptDirectory($script:selectedPair.cdlLocation, $script:inputPassClear)

                # Lock the folder
                Set-ItemProperty -Path $script:selectedPair.cdlLocation -Name Attributes -Value "Hidden, System"
                $script:selectedPair.isLocked = $true
                Rename-Item -Path $script:selectedPair.cdlLocation -NewName ".$($script:selectedPair.folderName)"
                $script:selectedPair.cdlLocation = "$cdlDir\.$($script:selectedPair.folderName)"

                # Convert the updated array to JSON and write it to the file
                $json = $folderPasswordPairs | ConvertTo-Json -Depth 3
                Set-Content -Path "$roamingConfig\folders.json" -Value $json

                Invoke-Log -message "Folder $($script:selectedPair.folderName) locked successfully." -level "Success"
                Show-Message -type "Info" -message "Folder $($script:selectedPair.folderName) locked successfully." -title "ColDog Locker"
                break
            }
            catch {
                # Handle any errors that occurred during the script execution
                Invoke-Log -message "An error occurred while locking $script:selectedPair.folderName: $($_.Exception.Message)" -level "Error"
                Show-Message -type "Error" -message "An error occurred while locking $script:selectedPair.folderName: $($_.Exception.Message)" -title "Error - ColDog Locker"
                exit
            }
        }
        else {
            Invoke-Log -message "Failed password attempt" -level "Warning"
            Show-Message -type "Warning" -message "Failed password atttept. Please try again." -title "Warning"
        }
    }
}

#MARK: ----------[ Unlock-CDL ]----------#
function Unlock-CDL {
    # If the JSON file does not exist, return early, otherwise read its contents
    if (-not (Test-Path "$roamingConfig\folders.json")) {
        Show-Message -type "Warning" -message "There are no locked folders to unlock." -title "ColDog Locker"
        return
    }

    # Get and Convert the JSON content to an array of folder-password pairs
    $jsonContent = Get-Content "$roamingConfig\folders.json"
    $folderPasswordPairs = $jsonContent | ConvertFrom-Json

    # Ensure the content is an array
    if ($folderPasswordPairs -isnot [System.Collections.IEnumerable]) {
        $folderPasswordPairs = @($folderPasswordPairs)
    }

    # Check if there are any folder-password pairs with the isLocked : true attribute
    $lockedFolders = $folderPasswordPairs | Where-Object { $_.isLocked -eq $true }
    $lockedFolders = @($lockedFolders)

    # If there are no locked folders, return early
    if ($null -eq $lockedFolders -or $lockedFolders.Count -eq 0) {
        Show-Message -type "Warning" -message "There are no locked folders to unlock." -title "ColDog Locker"
        return
    }

    # call functions
    Show-MenuTitle -subMenu "Main Menu > Unlock Folder"

    # Display each folder name to the console
    Write-Host "Locked Folders:"
    Write-Host ""
    for ($i = 0; $i -lt $lockedFolders.Count; $i++) {
        Write-Host "$($i + 1). $($lockedFolders[$i].folderName)"
    }

    # Prompt the user to choose a folder
    Write-Host ""
    $selectedPairIndex = Read-Host "Enter the number corresponding to the folder you want to unlock"

    # Validate user input
    if (-not [int]::TryParse($selectedPairIndex, [ref]$null)) {
        Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
        return
    }

    $selectedPairIndex = [int]$selectedPairIndex - 1

    # Check if the selected index is within the valid range
    if ($selectedPairIndex -lt 0 -or $selectedPairIndex -ge $lockedFolders.Count) {
        Show-Message -type "Warning" -message "Invalid selection. Please choose a valid number from the list." -title "ColDog Locker"
        return
    }

    $failedAttempts = 0

    while ($true) {
        # Show confirmation prompt
        $script:selectedPair = $lockedFolders[$selectedPairIndex]

        Write-Host "`nYou selected $($script:selectedPair.folderName)"
        Write-Host ""
        $inputPassword = Read-Host -Prompt "Enter the password to unlock $($script:selectedPair.folderName)" -AsSecureString

        # Convert SecureString to Clear Text for Password
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($inputPassword)
        $script:inputPassClear = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        # Check if the entered password is correct
        Invoke-PassHash

        if ($script:selectedPair.password -ceq $script:hex512) {
            try {
                # Decrypt the folder by calling the DecryptDirectory method
                [cdlEncryptor]::DecryptDirectory($script:selectedPair.cdlLocation, $script:inputPassClear)

                # Unlock the folder
                Set-ItemProperty -Path $script:selectedPair.cdlLocation -Name Attributes -Value "Normal"
                $script:selectedPair.isLocked = $false
                Rename-Item -Path $script:selectedPair.cdlLocation -NewName $script:selectedPair.folderName
                $script:selectedPair.cdlLocation = "$cdlDir\$($script:selectedPair.folderName)"

                # Convert the updated array to JSON and write it to the file
                $json = $folderPasswordPairs | ConvertTo-Json -Depth 3
                Set-Content -Path "$roamingConfig\folders.json" -Value $json

                Invoke-Log -message "Folder $($script:selectedPair.folderName) unlocked successfully." -level "Success"
                Show-Message -type "Info" -message "Folder $($script:selectedPair.folderName) unlocked successfully." -title "ColDog Locker"
                break
            }
            catch {
                # Handle any errors that occurred during the script execution
                Invoke-Log -message "An error occurred while unlocking $($script:selectedPair.folderName): $($_.Exception.Message)" -level "Error"
                Show-Message -type "Error" -message "An error occurred while unlocking $($script:selectedPair.folderName): $($_.Exception.Message)" -title "Error - ColDog Locker"
                exit
            }
        }
        else {
            $failedAttempts++
            if ($failedAttempts -ge 10) {
                Invoke-Log -message "10 failed password attempts. Locking $script:selectedPair.folderName permanently." -level "Error"
                Show-Message -type "Error" -message "10 failed password attempts. Locking $script:selectedPair.folderName permanently." -title "ColDog Locker"

                break
            }
            else {
                $remainingAttempts = 10 - $failedAttempts
                Invoke-Log -message "Failed password attempt. $remainingAttempts attempts remaining." -level "Warning"
                Show-Message -type "Warning" -message "Failed password atttept. $remainingAttempts attempts remaining." -title "Warning"
            }
        }
    }
}

#MARK: ----------[ Utility Functions ]----------#

function Get-cdlAbout {
    try {
        $message = "The idea of ColDog Locker was created by Collin 'ColDog' Laney on 11/17/21, for a security project in Cybersecurity class.`n" +
        "Collin Laney is the Founder and CEO of ColDog Studios"
        
        Show-Message -type "Info" -message $message -title "About ColDog Locker"
    }
    catch {
        # Handle any errors that occurred during execution
        Invoke-Log -Message "An error occurred in about: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred in about: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit
    }
}

function Get-cdlHelp {
    try {
        $message = "ColDog Locker is a simple file locker that allows you to lock and unlock folders with a password.`n`n" +
        "To lock a folder, select the 'Lock Folder' option from the main menu and follow the prompts.`n`n" +
        "To unlock a folder, select the 'Unlock Folder' option from the main menu and follow the prompts.`n`n" +
        "To remove a folder, select the 'Remove Folder' option from the main menu and follow the prompts.`n`n" +
        "To check for updates, select the 'Check for Updates' option from the main menu."
        
        Show-Message -type "Info" -message $message -title "ColDog Locker Help"
    }
    catch {
        # Handle any errors that occurred during execution
        Invoke-Log -Message "An error occurred in help: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred in help: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit
    }
}

function Get-cdlUpdates {
    try {
        # variables setup
        $owner = "ColDogStudios"
        $repository = "ColDog-Locker"
        $downloadDirectory = "$env:userprofile\Downloads"
        $uri = "https://api.github.com/repos/$owner/$repository/releases/latest"

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

            $updatePromptChoice = [System.Windows.Forms.MessageBox]::Show($message, "Update Available", "YesNo", "Information")

            if ("$updatePromptChoice" -eq "Yes" ) {
                try {
                    # Download the latest version
                    #$fileName = Join-Path $downloadDirectory "ColDog_Locker_${downloadVersion}_setup.msi"
                    $fileName = Join-Path $downloadDirectory "ColDog_Locker_${downloadVersion}.exe"
                    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $fileName

                    Invoke-Log -message "Downloaded the latest version to: $fileName" -level "Success"
                    Show-Message -type "Info" -message "Downloaded the latest version to: $fileName.`nPlease run the installer to update ColDog Locker." -title "Download Complete"
                }
                catch {
                    Invoke-Log -message "An error occurred while downloading the latest version: $($_.Exception.Message)" -level "Error"
                    Show-Message -type "Error" -message "An error occurred while downloading the latest version: $($_.Exception.Message)" -title "Error - ColDog Locker"
                }
            }
        }
        else {
            $message = "ColDog Locker is up to date: `n`n" +
            "Current Version: $currentVersion `n" +
            "Latest Version: $latestVersion"

            Show-Message -type "Info" -message $message -title "ColDog Locker Update Check"
        }
    }
    catch {
        # Handle any errors that occurred during the script execution
        Invoke-Log -Message "An error occurred while checking for updates: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred while checking for updates: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit
    }
}

function Get-cdlDeveloperInfo {
    try {
        $message = "Current Version: $version `n" +
        "Date Modified: $dateMod `n" +
        "Alpha Build"
        
        Show-Message -type "Info" -message $message -title "Development"
    }
    catch {
        # Handle any errors that occurred during execution
        Invoke-Log -message "An error occurred in dev: $($_.Exception.Message)" -level "Error"
        Show-Message -type "Error" -message "An error occurred in dev: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit
    }
}

#MARK: ----------[ Reference Functions ]----------#

function Show-MenuTitle {
    param (
        [string]$subMenu = ""
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

# used by: New-cdlFolder, Unlock-CDL
function Invoke-PassHash {
    try {
        # Convert the input string to a byte array
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($script:inputPassClear)

        # Compute the SHA-256 hash of the byte array
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash256 = $sha256.ComputeHash($bytes)

        # Convert the SHA-256 hash to a hexadecimal string
        $hex256 = [System.BitConverter]::ToString($hash256).Replace("-", "").ToLower()

        # Compute the SHA-512 hash of the SHA-256 hash
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        $hash512 = $sha512.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hex256))

        # Convert the SHA-512 hash to a hexadecimal string
        $script:hex512 = [System.BitConverter]::ToString($hash512).Replace("-", "").ToLower()

        # Hide Clear Text Password
        #$script:inputPassClear = $null
    }
    catch {
        # Handle any errors that occurred during the script execution
        Invoke-Log -Message "An error occurred with password hashing: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred with password hashing: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit
    }
}

#function ConvertSecureStringToClearText {
#    param (
#        [System.Security.SecureString]$secureString
#    )
#    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
#    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
#}

#$script:inputPassClear = ConvertSecureStringToClearText $inputPassword
#$confirmPassClear = ConvertSecureStringToClearText $confirmPassword

# used by: New-cdlFolder, Remove-cdlFolder, Lock-CDL, Unlock-CDL
function Get-FolderPasswordPairs {
    # If the JSON file exists, read it from the file, otherwise initialize an empty array
    if (Test-Path "$roamingConfig\folders.json") {
        $content = Get-Content "$roamingConfig\folders.json" | ForEach-Object { $_.Trim() }
        if ($content -eq '') {
            $script:folderPasswordPairs = @()
        }
        else {
            $script:folderPasswordPairs = $content | ConvertFrom-Json
        }
    }
    else {
        $script:folderPasswordPairs = @()
    }
}

# used by: New-cdlFolder
function Add-FolderPasswordPair {
    try {
        # If the JSON table exists, read it from the file, otherwise initialize an empty array
        if (Test-Path "$roamingConfig\folders.json") {
            $folderPasswordPairs = Get-Content "$roamingConfig\folders.json" | ConvertFrom-Json
        }
        else {
            $folderPasswordPairs = @()
        }
        
        # Ensure $folderPasswordPairs is an array
        if (-not $folderPasswordPairs) {
            $folderPasswordPairs = @()
        }
        elseif ($folderPasswordPairs -isnot [System.Collections.IEnumerable]) {
            $folderPasswordPairs = @($folderPasswordPairs)
        }
        
        # Create a hashtable with the guid, folder name, password, location, and isLocked attribute
        $folderPasswordPair = [PSCustomObject]@{
            guid        = [guid]::NewGuid().ToString()
            folderName  = $script:inputFolderName
            password    = $script:hex512
            cdlLocation = "$cdlDir\$script:inputFolderName"
            isLocked    = $false
        }
    
        # Add the hashtable to the array
        $updatedFolderPasswordPairs = @($folderPasswordPairs + $folderPasswordPair)
    
        # Convert the array to JSON and write it to the file
        $json = $updatedFolderPasswordPairs | ConvertTo-Json
        Set-Content -Path "$roamingConfig\folders.json" -Value $json
    
        # Assign the modified array back to the script-scoped variable
        $script:folderPasswordPairs = $updatedFolderPasswordPairs
    
        # Create the folder
        New-Item -ItemType Directory -Path "$cdlDir\$script:inputFolderName" | Out-Null
    
        Invoke-Log -message "$script:inputFolderName created successfully." -level "Success"
        Show-Message -type "Info" -message "$script:inputFolderName created successfully." -title "ColDog Locker"
    }
    catch {
        # Handle any errors that occurred during the script execution
        Invoke-Log -Message "An error occurred while adding $script:inputFolderName to the JSON table: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred while adding $script:inputFolderName to the JSON table: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit
    }
}

# used by: Remove-cdlFolder
function Remove-FolderPasswordPair {
    try {
        # Read the existing folder-password pairs from the JSON file
        $jsonContent = Get-Content "$roamingConfig\folders.json"
        $folderPasswordPairs = $jsonContent | ConvertFrom-Json

        # Ensure the content is an array
        if ($folderPasswordPairs -isnot [System.Collections.IEnumerable]) {
            $folderPasswordPairs = @($folderPasswordPairs)
        }

        # Remove the selected folder-password pair
        $folderPasswordPairs = $folderPasswordPairs | Where-Object { $_.folderName -ne $script:selectedPair.folderName }

        # Convert the updated array to JSON and write it to the file
        $json = $folderPasswordPairs | ConvertTo-Json -Depth 3
        Set-Content -Path "$roamingConfig\folders.json" -Value $json

        Invoke-Log -message "Folder $($script:selectedPair.folderName) removed successfully." -level "Success"
        Show-Message -type "Info" -message "Folder $($script:selectedPair.folderName) removed successfully." -title "ColDog Locker"
    }
    catch {
        # Handle any errors that occurred during the script execution
        Invoke-Log -Message "An error occurred while removing $script:selectedPair to the JSON table: $($_.Exception.Message)" -Level "Error"
        Show-Message -type "Error" -message "An error occurred while removing $script:selectedPair to the JSON table: $($_.Exception.Message)" -title "Error - ColDog Locker"
        exit
    }
}

#MARK: ----------[ CDL Logging ]----------#
function Invoke-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$message,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Success", "Warning", "Error", "Debug")]
        [string]$level,

        [string]$logFile = "$localConfig\cdl.log"
    )

    $logEntry = "[$(Get-Date)] [$level] $message"
    Add-Content -Path $logFile -Value $logEntry
}

#MARK: ----------[ Message Boxes ]----------#
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
        "Info" { [System.Windows.Forms.MessageBox]::Show($message, $title, "OK", "Information") }
        "Warning" { [System.Windows.Forms.MessageBox]::Show($message, $title, "OK", "Warning") }
        "Error" { [System.Windows.Forms.MessageBox]::Show($message, $title, "OK", "Error") }
    }
}

#MARK: ----------[ Run Program ]----------#
Show-cdlMenu

# TODO: Add a function to edit the log file
# TODO: Add a function to display system information
# TODOL: Fix JSON get folder-password pairs - create function to elimiate repeated code
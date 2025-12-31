using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Application.Validation;
using ColDogStudios.ColDogLocker.Infrastructure.Encryption;
using ColDogStudios.ColDogLocker.Infrastructure.Console;
using ColDogStudios.ColDogLocker.Infrastructure.Data;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Cli.Commands;

/// <summary>
/// Handlers for locker-related CLI commands (new, remove, lock, unlock, list, status, change-password, verify).
/// </summary>
public static class LockerCommandHandlers
{
    public static int HandleNew(string[] args)
    {
        // Usage: ColDogLocker.exe new <Locker Name> [--path "D:\Lockers"] [--password <password>]
        
        if (args.Length < 2)
        {
            System.Console.Error.WriteLine("Error: Locker name is required.");
            System.Console.WriteLine("Usage: ColDogLocker new <Locker Name> [--path <path>] [--password <password>]");
            return 1;
        }

        var lockerName = args[1];
        string? customPath = null;
        string? providedPassword = null;

        // Parse optional parameters
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i] == "--path" && i + 1 < args.Length)
            {
                customPath = args[i + 1];
                i++; // Skip the next argument
            }
            else if (args[i] == "--password" && i + 1 < args.Length)
            {
                providedPassword = args[i + 1];
                i++; // Skip the next argument
            }
        }

        // Determine locker location
        string lockerLocation = customPath != null 
            ? Path.Combine(customPath, lockerName)
            : Path.Combine(Variables.cdlDir, lockerName);

        // Check if locker already exists
        if (LockerService.Lockers.Any(l => l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase)))
        {
            System.Console.Error.WriteLine($"Error: Locker '{lockerName}' already exists.");
            return 1;
        }

        // Get password
        string password;
        if (!string.IsNullOrEmpty(providedPassword))
        {
            // Use provided password (for automation)
            password = providedPassword;
            
            // Still validate it
            try
            {
                PasswordFilter.SecurityCheck(password);
                PasswordFilter.IllegalWordCheck(password);
            }
            catch (Exception ex)
            {
                System.Console.Error.WriteLine($"Error: Password validation failed: {ex.Message}");
                return 1;
            }
        }
        else
        {
            // Prompt for password
            System.Console.WriteLine("Password Requirements:");
            System.Console.WriteLine("  - At least 10 characters");
            System.Console.WriteLine("  - At least one uppercase letter");
            System.Console.WriteLine("  - At least one lowercase letter");
            System.Console.WriteLine("  - At least one digit");
            System.Console.WriteLine("  - At least one special character");
            System.Console.WriteLine();

            while (true)
            {
                System.Console.Write("Enter password: ");
                password = ConsoleHelper.ReadPassword();
                
                if (string.IsNullOrEmpty(password))
                {
                    System.Console.WriteLine("Password cannot be empty.");
                    continue;
                }

                try
                {
                    PasswordFilter.SecurityCheck(password);
                    PasswordFilter.IllegalWordCheck(password);
                    break;
                }
                catch (Exception ex)
                {
                    System.Console.WriteLine($"Password validation failed: {ex.Message}");
                }
            }

            System.Console.Write("Confirm password: ");
            string confirmPassword = ConsoleHelper.ReadPassword();

            if (password != confirmPassword)
            {
                System.Console.Error.WriteLine("Error: Passwords do not match.");
                return 1;
            }
        }

        // Create the locker
        try
        {
            string passwordHash = EncryptionHelper.HashPassword(password);
            var locker = new LockerModel(lockerName, passwordHash, lockerLocation);
            
            LockerService.AddLocker(locker);

            System.Console.ForegroundColor = ConsoleColor.Green;
            System.Console.WriteLine($"\nLocker '{lockerName}' created successfully at: {lockerLocation}");
            System.Console.ResetColor();
            return 0;
        }
        catch (Exception ex)
        {
            System.Console.Error.WriteLine($"Error creating locker: {ex.Message}");
            return 1;
        }
    }

    public static int HandleRemove(string[] args)
    {
        // Usage: ColDogLocker.exe remove <Locker Name> [--force] [--delete]

        if (args.Length < 2)
        {
            System.Console.Error.WriteLine("Error: Locker name is required.");
            System.Console.WriteLine("Usage: ColDogLocker remove <Locker Name> [--force] [--delete]");
            return 1;
        }

        var lockerName = args[1];
        var force = args.Contains("--force");
        var deleteDirectory = args.Contains("--delete");

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            System.Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Check if locked
        if (locker.IsLocked)
        {
            System.Console.Error.WriteLine($"Error: Cannot remove locked locker '{lockerName}'. Unlock it first.");
            return 1;
        }

        // Confirm removal unless --force
        if (!force)
        {
            if (deleteDirectory)
            {
                System.Console.Write($"Are you sure you want to remove locker '{lockerName}' and DELETE its directory? This cannot be undone! (y/N): ");
            }
            else
            {
                System.Console.Write($"Are you sure you want to remove locker '{lockerName}'? (y/N): ");
            }
            
            var confirmation = System.Console.ReadLine()?.Trim().ToLowerInvariant();
            if (confirmation != "y" && confirmation != "yes")
            {
                System.Console.WriteLine("Operation cancelled.");
                return 0;
            }
        }

        // Remove the locker
        try
        {
            // Use LockerService.RemoveLocker to properly delete from database
            // Note: RemoveLocker has a Console.ReadLine() which we need to avoid in CLI
            LockerRepository.DeleteLocker(locker.Guid);
            LockerService.Lockers.Remove(locker);
            Logger.AddEntry($"{lockerName} removed successfully.", LogLevel.Success);

            // Delete directory if requested
            if (deleteDirectory && Directory.Exists(locker.LockerLocation))
            {
                Directory.Delete(locker.LockerLocation, recursive: true);
                System.Console.ForegroundColor = ConsoleColor.Green;
                System.Console.WriteLine($"Locker '{lockerName}' removed and directory deleted.");
                System.Console.ResetColor();
            }
            else
            {
                System.Console.ForegroundColor = ConsoleColor.Green;
                System.Console.WriteLine($"Locker '{lockerName}' removed successfully.");
                System.Console.ResetColor();
                System.Console.WriteLine($"Note: The directory at '{locker.LockerLocation}' was not deleted.");
            }
            
            return 0;
        }
        catch (Exception ex)
        {
            System.Console.Error.WriteLine($"Error removing locker: {ex.Message}");
            return 1;
        }
    }

    public static int HandleLock(string[] args)
    {
        // Usage: ColDogLocker.exe lock <Locker Name> [--password <pass>]

        if (args.Length < 2)
        {
            System.Console.Error.WriteLine("Error: Locker name is required.");
            System.Console.WriteLine("Usage: ColDogLocker lock <Locker Name> [--password <password>]");
            return 1;
        }

        var lockerName = args[1];
        string? password = null;

        // Parse optional --password parameter
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i] == "--password" && i + 1 < args.Length)
            {
                password = args[i + 1];
                i++; // Skip the next argument
            }
        }

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            System.Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Check if already locked
        if (locker.IsLocked)
        {
            System.Console.WriteLine($"Locker '{lockerName}' is already locked.");
            return 0;
        }

        // Prompt for password if not provided
        if (string.IsNullOrEmpty(password))
        {
            System.Console.Write("Enter password: ");
            password = ConsoleHelper.ReadPassword();
        }

        if (string.IsNullOrEmpty(password))
        {
            System.Console.Error.WriteLine("Error: Password cannot be empty.");
            return 1;
        }

        // Lock the locker
        try
        {
            LockerService.Lock(locker, password);

            System.Console.ForegroundColor = ConsoleColor.Green;
            System.Console.WriteLine($"Locker '{lockerName}' locked successfully.");
            System.Console.ResetColor();
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            System.Console.Error.WriteLine("Error: Incorrect password.");
            return 1;
        }
        catch (Exception ex)
        {
            System.Console.Error.WriteLine($"Error locking locker: {ex.Message}");
            return 1;
        }
    }

    public static int HandleUnlock(string[] args)
    {
        // Usage: ColDogLocker.exe unlock <Locker Name> [--password <pass>]

        if (args.Length < 2)
        {
            System.Console.Error.WriteLine("Error: Locker name is required.");
            System.Console.WriteLine("Usage: ColDogLocker unlock <Locker Name> [--password <password>]");
            return 1;
        }

        var lockerName = args[1];
        string? password = null;

        // Parse optional --password parameter
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i] == "--password" && i + 1 < args.Length)
            {
                password = args[i + 1];
                i++; // Skip the next argument
            }
        }

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            System.Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Check if already unlocked
        if (!locker.IsLocked)
        {
            System.Console.WriteLine($"Locker '{lockerName}' is already unlocked.");
            return 0;
        }

        // Prompt for password if not provided
        if (string.IsNullOrEmpty(password))
        {
            System.Console.Write("Enter password: ");
            password = ConsoleHelper.ReadPassword();
        }

        if (string.IsNullOrEmpty(password))
        {
            System.Console.Error.WriteLine("Error: Password cannot be empty.");
            return 1;
        }

        // Unlock the locker
        try
        {
            LockerService.Unlock(locker, password);

            System.Console.ForegroundColor = ConsoleColor.Green;
            System.Console.WriteLine($"Locker '{lockerName}' unlocked successfully.");
            System.Console.ResetColor();
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            System.Console.Error.WriteLine("Error: Incorrect password.");
            return 1;
        }
        catch (Exception ex)
        {
            System.Console.Error.WriteLine($"Error unlocking locker: {ex.Message}");
            return 1;
        }
    }

    public static int HandleList(string[] args)
    {
        // Usage: ColDogLocker.exe list [--locked|--unlocked]

        // Reload from database to get fresh data
        LockerService.LoadLockers();

        // Check for filter flags
        bool? filterLocked = null;
        if (args.Contains("--locked"))
            filterLocked = true;
        else if (args.Contains("--unlocked"))
            filterLocked = false;

        // Apply filter
        var lockers = LockerService.Lockers.AsEnumerable();
        if (filterLocked.HasValue)
        {
            lockers = lockers.Where(l => l.IsLocked == filterLocked.Value);
        }

        var lockerList = lockers.OrderBy(l => l.LockerName).ToList();

        if (lockerList.Count == 0)
        {
            if (filterLocked == true)
                System.Console.WriteLine("No locked lockers found.");
            else if (filterLocked == false)
                System.Console.WriteLine("No unlocked lockers found.");
            else
                System.Console.WriteLine("No lockers found.");
            
            System.Console.WriteLine($"Create a new locker with: ColDogLocker new <name>");
            return 0;
        }

        System.Console.WriteLine($"{"Name",-20} {"Status",-10} {"Location"}");
        System.Console.WriteLine(new string('-', 80));

        foreach (var locker in lockerList)
        {
            var status = locker.IsLocked ? "Locked" : "Unlocked";
            System.Console.WriteLine($"{locker.LockerName,-20} {status,-10} {locker.LockerLocation}");
        }

        System.Console.WriteLine();
        System.Console.WriteLine($"Total: {lockerList.Count} locker(s)");
        return 0;
    }

    public static int HandleStatus(string[] args)
    {
        // Usage: ColDogLocker.exe status <Locker Name>

        if (args.Length < 2)
        {
            System.Console.Error.WriteLine("Error: Locker name is required.");
            System.Console.WriteLine("Usage: ColDogLocker status <Locker Name>");
            return 1;
        }

        var lockerName = args[1];

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            System.Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Display status
        System.Console.WriteLine($"Locker: {locker.LockerName}");
        System.Console.WriteLine($"Status: {(locker.IsLocked ? "Locked" : "Unlocked")}");
        System.Console.WriteLine($"Location: {locker.LockerLocation}");
        System.Console.WriteLine($"GUID: {locker.Guid}");
        
        // Check if directory exists
        if (Directory.Exists(locker.LockerLocation))
        {
            var dirInfo = new DirectoryInfo(locker.LockerLocation);
            System.Console.WriteLine($"Created: {dirInfo.CreationTime:yyyy-MM-dd HH:mm:ss}");
            System.Console.WriteLine($"Last Modified: {dirInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss}");
            
            // Count files
            int fileCount = dirInfo.GetFiles("*", SearchOption.AllDirectories).Length;
            int folderCount = dirInfo.GetDirectories("*", SearchOption.AllDirectories).Length;
            System.Console.WriteLine($"Contents: {fileCount} file(s), {folderCount} folder(s)");
        }
        else
        {
            System.Console.ForegroundColor = ConsoleColor.Yellow;
            System.Console.WriteLine("Warning: Directory does not exist.");
            System.Console.ResetColor();
        }

        return 0;
    }

    public static int HandleChangePassword(string[] args)
    {
        // Usage: ColDogLocker.exe change-password <Locker Name>

        if (args.Length < 2)
        {
            System.Console.Error.WriteLine("Error: Locker name is required.");
            System.Console.WriteLine("Usage: ColDogLocker change-password <Locker Name>");
            return 1;
        }

        var lockerName = args[1];

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            System.Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Check if locked
        if (locker.IsLocked)
        {
            System.Console.Error.WriteLine($"Error: Locker '{lockerName}' must be unlocked to change password.");
            return 1;
        }

        // Get old password
        System.Console.Write("Enter current password: ");
        string oldPassword = ConsoleHelper.ReadPassword();

        if (string.IsNullOrEmpty(oldPassword))
        {
            System.Console.Error.WriteLine("Error: Password cannot be empty.");
            return 1;
        }

        // Get new password
        System.Console.WriteLine("\nPassword Requirements:");
        System.Console.WriteLine("  - At least 10 characters");
        System.Console.WriteLine("  - At least one uppercase letter");
        System.Console.WriteLine("  - At least one lowercase letter");
        System.Console.WriteLine("  - At least one digit");
        System.Console.WriteLine("  - At least one special character");
        System.Console.WriteLine();

        string newPassword;
        while (true)
        {
            System.Console.Write("Enter new password: ");
            newPassword = ConsoleHelper.ReadPassword();
            
            if (string.IsNullOrEmpty(newPassword))
            {
                System.Console.WriteLine("Password cannot be empty.");
                continue;
            }

            try
            {
                PasswordFilter.SecurityCheck(newPassword);
                PasswordFilter.IllegalWordCheck(newPassword);
                break;
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"Password validation failed: {ex.Message}");
            }
        }

        System.Console.Write("Confirm new password: ");
        string confirmPassword = ConsoleHelper.ReadPassword();

        if (newPassword != confirmPassword)
        {
            System.Console.Error.WriteLine("Error: Passwords do not match.");
            return 1;
        }

        // Change password
        try
        {
            System.Console.WriteLine("\nChanging password...");
            LockerService.ChangePassword(locker, oldPassword, newPassword);

            System.Console.ForegroundColor = ConsoleColor.Green;
            System.Console.WriteLine($"Password changed successfully for '{lockerName}'.");
            System.Console.ResetColor();
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            System.Console.Error.WriteLine("Error: Incorrect current password.");
            return 1;
        }
        catch (Exception ex)
        {
            System.Console.Error.WriteLine($"Error changing password: {ex.Message}");
            return 1;
        }
    }

    public static int HandleVerify(string[] args)
    {
        // Usage: ColDogLocker.exe verify <Locker Name>

        if (args.Length < 2)
        {
            System.Console.Error.WriteLine("Error: Locker name is required.");
            System.Console.WriteLine("Usage: ColDogLocker verify <Locker Name>");
            return 1;
        }

        var lockerName = args[1];

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            System.Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Verify locker
        var result = LockerService.Verify(locker);

        System.Console.WriteLine();
        System.Console.WriteLine($"Locker: {result.LockerName}");
        System.Console.WriteLine($"GUID: {result.Guid}");
        System.Console.WriteLine($"Status: {(result.IsLocked ? "Locked" : "Unlocked")}");
        System.Console.WriteLine();

        // Display checks
        System.Console.WriteLine($"[{(result.DirectoryExists ? "OK" : "FAIL")}] Directory exists");
        System.Console.WriteLine($"[{(result.HasAccess ? "OK" : "FAIL")}] Directory accessible");
        if (result.DirectoryExists)
        {
            System.Console.WriteLine($"      Contents: {result.FileCount} file(s), {result.DirectoryCount} folder(s)");
        }

        // Display errors
        if (result.Errors.Count > 0)
        {
            System.Console.WriteLine();
            System.Console.ForegroundColor = ConsoleColor.Red;
            System.Console.WriteLine("ERRORS:");
            System.Console.ResetColor();
            foreach (var error in result.Errors)
            {
                System.Console.WriteLine($"  [!] {error}");
            }
        }

        // Display warnings
        if (result.Warnings.Count > 0)
        {
            System.Console.WriteLine();
            System.Console.ForegroundColor = ConsoleColor.Yellow;
            System.Console.WriteLine("WARNINGS:");
            System.Console.ResetColor();
            foreach (var warning in result.Warnings)
            {
                System.Console.WriteLine($"  [!] {warning}");
            }
        }

        // Overall status
        System.Console.WriteLine();
        if (result.IsValid)
        {
            System.Console.ForegroundColor = ConsoleColor.Green;
            System.Console.WriteLine("Overall: VALID");
            System.Console.ResetColor();
            return 0;
        }
        else if (result.Errors.Count > 0)
        {
            System.Console.ForegroundColor = ConsoleColor.Red;
            System.Console.WriteLine("Overall: INVALID");
            System.Console.ResetColor();
            return 1;
        }
        else
        {
            System.Console.ForegroundColor = ConsoleColor.Yellow;
            System.Console.WriteLine("Overall: WARNING");
            System.Console.ResetColor();
            return 0;
        }
    }
}

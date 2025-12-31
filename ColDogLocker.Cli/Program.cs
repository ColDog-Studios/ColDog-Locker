using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Application.Validation;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Encryption;
using ColDogStudios.ColDogLocker.Infrastructure.FileSystem;

namespace ColDogStudios.ColDogLocker.Cli;

class Program
{
    static int Main(string[] args)
    {
        Console.WriteLine();
        
        try
        {
            // Initialize application for CLI commands (except for UI launchers)
            if (args.Length > 0 && args[0].ToLowerInvariant() is not "gui" and not "terminal" and not "tui")
            {
                InitializeForCli();
            }

            // No arguments - launch TUI (default behavior)
            if (args.Length == 0)
            {
                //return LaunchTui();
                return HandleHelpCommand(args);
            }

            // Parse the first argument as the command/subcommand
            var command = args[0].ToLowerInvariant();

            return command switch
            {
                "gui" => LaunchGui(),
                "terminal" or "tui" => LaunchTui(),
                "new" => HandleNewCommand(args),
                "remove" => HandleRemoveCommand(args),
                "lock" => HandleLockCommand(args),
                "unlock" => HandleUnlockCommand(args),
                "list" => HandleListCommand(args),
                "status" => HandleStatusCommand(args),
                "change-password" => HandleChangePasswordCommand(args),
                "verify" => HandleVerifyCommand(args),
                "settings" => HandleSettingsCommand(args),
                "db-vacuum" => HandleDbVacuumCommand(args),
                "db-info" => HandleDbInfoCommand(args),
                "help" => HandleHelpCommand(args),
                "--version" or "-v" => HandleVersionCommand(),
                _ => HandleUnknownCommand(command)
            };
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine($"Error: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    static void InitializeForCli()
    {
        // Create directories if needed
        if (!Directory.Exists(Variables.localConfig))
        {
            Directory.CreateDirectory(Variables.localConfig);
        }

        // Initialize database and migrate from JSON if needed
        ColDogStudios.ColDogLocker.Infrastructure.Data.LockerRepository.InitializeDatabase();
        ColDogStudios.ColDogLocker.Infrastructure.Data.LockerRepository.MigrateFromJson();

        // Load settings and lockers (minimal initialization for CLI)
        SettingsManager.LoadSettings();
        LockerService.LoadLockers();
    }

    #region UI Launchers

    static int LaunchGui()
    {
        return ColDogStudios.ColDogLocker.Gui.GuiLauncher.Launch();
    }

    static int LaunchTui()
    {
        return ColDogStudios.ColDogLocker.Tui.TuiLauncher.Launch();
    }

    #endregion

    #region Command Handlers

    static int HandleNewCommand(string[] args)
    {
        // Usage: ColDogLocker.exe new <Locker Name> [--path "D:\Lockers"] [--password <password>]
        
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker new <Locker Name> [--path <path>] [--password <password>]");
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
            Console.Error.WriteLine($"Error: Locker '{lockerName}' already exists.");
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
                Console.Error.WriteLine($"Error: Password validation failed: {ex.Message}");
                return 1;
            }
        }
        else
        {
            // Prompt for password
            Console.WriteLine("Password Requirements:");
            Console.WriteLine("  - At least 10 characters");
            Console.WriteLine("  - At least one uppercase letter");
            Console.WriteLine("  - At least one lowercase letter");
            Console.WriteLine("  - At least one digit");
            Console.WriteLine("  - At least one special character");
            Console.WriteLine();

            while (true)
            {
                Console.Write("Enter password: ");
                password = ReadPassword();
                
                if (string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("Password cannot be empty.");
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
                    Console.WriteLine($"Password validation failed: {ex.Message}");
                }
            }

            Console.Write("Confirm password: ");
            string confirmPassword = ReadPassword();

            if (password != confirmPassword)
            {
                Console.Error.WriteLine("Error: Passwords do not match.");
                return 1;
            }
        }

        // Create the locker
        try
        {
            string passwordHash = EncryptionHelper.HashPassword(password);
            var locker = new LockerModel(lockerName, passwordHash, lockerLocation);
            
            LockerService.AddLocker(locker);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\nLocker '{lockerName}' created successfully at: {lockerLocation}");
            Console.ResetColor();
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error creating locker: {ex.Message}");
            return 1;
        }
    }

    static int HandleRemoveCommand(string[] args)
    {
        // Usage: ColDogLocker.exe remove <Locker Name> [--force] [--delete]

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker remove <Locker Name> [--force] [--delete]");
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
            Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Check if locked
        if (locker.IsLocked)
        {
            Console.Error.WriteLine($"Error: Cannot remove locked locker '{lockerName}'. Unlock it first.");
            return 1;
        }

        // Confirm removal unless --force
        if (!force)
        {
            if (deleteDirectory)
            {
                Console.Write($"Are you sure you want to remove locker '{lockerName}' and DELETE its directory? This cannot be undone! (y/N): ");
            }
            else
            {
                Console.Write($"Are you sure you want to remove locker '{lockerName}'? (y/N): ");
            }
            
            var confirmation = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (confirmation != "y" && confirmation != "yes")
            {
                Console.WriteLine("Operation cancelled.");
                return 0;
            }
        }

        // Remove the locker
        try
        {
            LockerService.Lockers.Remove(locker);
            LockerService.SaveLockers();

            // Delete directory if requested
            if (deleteDirectory && Directory.Exists(locker.LockerLocation))
            {
                Directory.Delete(locker.LockerLocation, recursive: true);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Locker '{lockerName}' removed and directory deleted.");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Locker '{lockerName}' removed successfully.");
                Console.ResetColor();
                Console.WriteLine($"Note: The directory at '{locker.LockerLocation}' was not deleted.");
            }
            
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error removing locker: {ex.Message}");
            return 1;
        }
    }

    static int HandleLockCommand(string[] args)
    {
        // Usage: ColDogLocker.exe lock <Locker Name> [--password <pass>]

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker lock <Locker Name> [--password <password>]");
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
            Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Check if already locked
        if (locker.IsLocked)
        {
            Console.WriteLine($"Locker '{lockerName}' is already locked.");
            return 0;
        }

        // Prompt for password if not provided
        if (string.IsNullOrEmpty(password))
        {
            Console.Write("Enter password: ");
            password = ReadPassword();
        }

        if (string.IsNullOrEmpty(password))
        {
            Console.Error.WriteLine("Error: Password cannot be empty.");
            return 1;
        }

        // Lock the locker
        try
        {
            LockerService.Lock(locker, password);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Locker '{lockerName}' locked successfully.");
            Console.ResetColor();
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Error: Incorrect password.");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error locking locker: {ex.Message}");
            return 1;
        }
    }

    static int HandleUnlockCommand(string[] args)
    {
        // Usage: ColDogLocker.exe unlock <Locker Name> [--password <pass>]

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker unlock <Locker Name> [--password <password>]");
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
            Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Check if already unlocked
        if (!locker.IsLocked)
        {
            Console.WriteLine($"Locker '{lockerName}' is already unlocked.");
            return 0;
        }

        // Prompt for password if not provided
        if (string.IsNullOrEmpty(password))
        {
            Console.Write("Enter password: ");
            password = ReadPassword();
        }

        if (string.IsNullOrEmpty(password))
        {
            Console.Error.WriteLine("Error: Password cannot be empty.");
            return 1;
        }

        // Unlock the locker
        try
        {
            LockerService.Unlock(locker, password);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Locker '{lockerName}' unlocked successfully.");
            Console.ResetColor();
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Error: Incorrect password.");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error unlocking locker: {ex.Message}");
            return 1;
        }
    }

    static int HandleListCommand(string[] args)
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
                Console.WriteLine("No locked lockers found.");
            else if (filterLocked == false)
                Console.WriteLine("No unlocked lockers found.");
            else
                Console.WriteLine("No lockers found.");
            
            Console.WriteLine($"Create a new locker with: ColDogLocker new <name>");
            return 0;
        }

        Console.WriteLine($"{"Name",-20} {"Status",-10} {"Location"}");
        Console.WriteLine(new string('-', 80));

        foreach (var locker in lockerList)
        {
            var status = locker.IsLocked ? "Locked" : "Unlocked";
            Console.WriteLine($"{locker.LockerName,-20} {status,-10} {locker.LockerLocation}");
        }

        Console.WriteLine();
        Console.WriteLine($"Total: {lockerList.Count} locker(s)");
        return 0;
    }

    static int HandleStatusCommand(string[] args)
    {
        // Usage: ColDogLocker.exe status <Locker Name>

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker status <Locker Name>");
            return 1;
        }

        var lockerName = args[1];

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Display status
        Console.WriteLine($"Locker: {locker.LockerName}");
        Console.WriteLine($"Status: {(locker.IsLocked ? "Locked" : "Unlocked")}");
        Console.WriteLine($"Location: {locker.LockerLocation}");
        Console.WriteLine($"GUID: {locker.Guid}");
        
        // Check if directory exists
        if (Directory.Exists(locker.LockerLocation))
        {
            var dirInfo = new DirectoryInfo(locker.LockerLocation);
            Console.WriteLine($"Created: {dirInfo.CreationTime:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"Last Modified: {dirInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss}");
            
            // Count files
            int fileCount = dirInfo.GetFiles("*", SearchOption.AllDirectories).Length;
            int folderCount = dirInfo.GetDirectories("*", SearchOption.AllDirectories).Length;
            Console.WriteLine($"Contents: {fileCount} file(s), {folderCount} folder(s)");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Warning: Directory does not exist.");
            Console.ResetColor();
        }

        return 0;
    }

    static int HandleChangePasswordCommand(string[] args)
    {
        // Usage: ColDogLocker.exe change-password <Locker Name>

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker change-password <Locker Name>");
            return 1;
        }

        var lockerName = args[1];

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Check if locked
        if (locker.IsLocked)
        {
            Console.Error.WriteLine($"Error: Locker '{lockerName}' must be unlocked to change password.");
            return 1;
        }

        // Get old password
        Console.Write("Enter current password: ");
        string oldPassword = ReadPassword();

        if (string.IsNullOrEmpty(oldPassword))
        {
            Console.Error.WriteLine("Error: Password cannot be empty.");
            return 1;
        }

        // Get new password
        Console.WriteLine("\nPassword Requirements:");
        Console.WriteLine("  - At least 10 characters");
        Console.WriteLine("  - At least one uppercase letter");
        Console.WriteLine("  - At least one lowercase letter");
        Console.WriteLine("  - At least one digit");
        Console.WriteLine("  - At least one special character");
        Console.WriteLine();

        string newPassword;
        while (true)
        {
            Console.Write("Enter new password: ");
            newPassword = ReadPassword();
            
            if (string.IsNullOrEmpty(newPassword))
            {
                Console.WriteLine("Password cannot be empty.");
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
                Console.WriteLine($"Password validation failed: {ex.Message}");
            }
        }

        Console.Write("Confirm new password: ");
        string confirmPassword = ReadPassword();

        if (newPassword != confirmPassword)
        {
            Console.Error.WriteLine("Error: Passwords do not match.");
            return 1;
        }

        // Change password
        try
        {
            Console.WriteLine("\nChanging password...");
            LockerService.ChangePassword(locker, oldPassword, newPassword);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Password changed successfully for '{lockerName}'.");
            Console.ResetColor();
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Error: Incorrect current password.");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error changing password: {ex.Message}");
            return 1;
        }
    }

    static int HandleVerifyCommand(string[] args)
    {
        // Usage: ColDogLocker.exe verify <Locker Name>

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker verify <Locker Name>");
            return 1;
        }

        var lockerName = args[1];

        // Find the locker
        var locker = LockerService.Lockers.FirstOrDefault(l => 
            l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

        if (locker == null)
        {
            Console.Error.WriteLine($"Error: Locker '{lockerName}' not found.");
            return 1;
        }

        // Verify locker
        var result = LockerService.Verify(locker);

        Console.WriteLine();
        Console.WriteLine($"Locker: {result.LockerName}");
        Console.WriteLine($"GUID: {result.Guid}");
        Console.WriteLine($"Status: {(result.IsLocked ? "Locked" : "Unlocked")}");
        Console.WriteLine();

        // Display checks
        Console.WriteLine($"[{(result.DirectoryExists ? "OK" : "FAIL")}] Directory exists");
        Console.WriteLine($"[{(result.HasAccess ? "OK" : "FAIL")}] Directory accessible");
        if (result.DirectoryExists)
        {
            Console.WriteLine($"      Contents: {result.FileCount} file(s), {result.DirectoryCount} folder(s)");
        }

        // Display errors
        if (result.Errors.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ERRORS:");
            Console.ResetColor();
            foreach (var error in result.Errors)
            {
                Console.WriteLine($"  [!] {error}");
            }
        }

        // Display warnings
        if (result.Warnings.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("WARNINGS:");
            Console.ResetColor();
            foreach (var warning in result.Warnings)
            {
                Console.WriteLine($"  [!] {warning}");
            }
        }

        // Overall status
        Console.WriteLine();
        if (result.IsValid)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Overall: VALID");
            Console.ResetColor();
            return 0;
        }
        else if (result.Errors.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Overall: INVALID");
            Console.ResetColor();
            return 1;
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Overall: WARNING");
            Console.ResetColor();
            return 0;
        }
    }

    static int HandleSettingsCommand(string[] args)
    {
        // Usage: ColDogLocker.exe settings [set <key> <value>]

        if (args.Length == 1)
        {
            // Show current settings
            Console.WriteLine("Current Settings:");
            Console.WriteLine($"  Debug Mode: {SettingsManager.Settings.DebugMode}");
            Console.WriteLine($"  Log Retention Days: {SettingsManager.Settings.LogRetentionDays}");
            Console.WriteLine($"  Auto Update: {SettingsManager.Settings.AutoUpdate}");
            Console.WriteLine($"  Database Vacuum Interval: {SettingsManager.Settings.DatabaseVacuumInterval} days");
            Console.WriteLine($"  Last Database Vacuum: {SettingsManager.Settings.LastDatabaseVacuum?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");
            return 0;
        }

        if (args.Length >= 3 && args[1].ToLowerInvariant() == "set")
        {
            var key = args[2].ToLowerInvariant();
            
            if (args.Length < 4)
            {
                Console.Error.WriteLine("Error: Value is required.");
                return 1;
            }

            var value = args[3].ToLowerInvariant();

            switch (key)
            {
                case "debug":
                case "debugmode":
                    if (bool.TryParse(value, out bool debugMode))
                    {
                        SettingsManager.Settings.DebugMode = debugMode;
                        Logger.SetDebugMode(debugMode);
                        SettingsManager.SaveSettings();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"Debug mode set to: {debugMode}");
                        Console.ResetColor();
                        return 0;
                    }
                    Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                    return 1;

                case "log-retention":
                case "logretention":
                    if (int.TryParse(value, out int retention) && retention > 0 && retention <= 3650)
                    {
                        SettingsManager.Settings.LogRetentionDays = retention;
                        Logger.SetLogRetentionDays(retention);
                        SettingsManager.SaveSettings();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"Log retention days set to: {retention}");
                        Console.ResetColor();
                        return 0;
                    }
                    Console.Error.WriteLine("Error: Invalid value. Must be between 1 and 3650 days.");
                    return 1;

                case "auto-update":
                case "autoupdate":
                    if (bool.TryParse(value, out bool autoUpdate))
                    {
                        SettingsManager.Settings.AutoUpdate = autoUpdate;
                        SettingsManager.SaveSettings();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"Auto update set to: {autoUpdate}");
                        Console.ResetColor();
                        return 0;
                    }
                    Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                    return 1;

                case "db-vacuum-interval":
                case "vacuuminterval":
                    if (int.TryParse(value, out int interval) && interval >= 0 && interval <= 365)
                    {
                        SettingsManager.Settings.DatabaseVacuumInterval = interval;
                        SettingsManager.SaveSettings();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"Database vacuum interval set to: {interval} days (0 = disabled)");
                        Console.ResetColor();
                        return 0;
                    }
                    Console.Error.WriteLine("Error: Invalid value. Must be between 0 and 365 days.");
                    return 1;

                default:
                    Console.Error.WriteLine($"Error: Unknown setting '{key}'.");
                    Console.WriteLine("Available settings: debug, log-retention, auto-update, db-vacuum-interval");
                    return 1;
            }
        }

        Console.Error.WriteLine("Usage: ColDogLocker settings [set <key> <value>]");
        return 1;
    }

    static int HandleDbVacuumCommand(string[] args)
    {
        // Usage: ColDogLocker.exe db-vacuum

        try
        {
            Console.WriteLine("Vacuuming database...");
            long reclaimed = ColDogStudios.ColDogLocker.Infrastructure.Data.LockerRepository.VacuumDatabase();

            // Update last vacuum time
            SettingsManager.Settings.LastDatabaseVacuum = DateTime.Now;
            SettingsManager.SaveSettings();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Database vacuumed successfully.");
            Console.ResetColor();
            Console.WriteLine($"Reclaimed: {reclaimed:N0} bytes ({reclaimed / 1024.0:F2} KB)");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error vacuuming database: {ex.Message}");
            return 1;
        }
    }

    static int HandleDbInfoCommand(string[] args)
    {
        // Usage: ColDogLocker.exe db-info

        try
        {
            var info = ColDogStudios.ColDogLocker.Infrastructure.Data.LockerRepository.GetDatabaseInfo();

            Console.WriteLine();
            Console.WriteLine("Database Information:");
            Console.WriteLine($"  Path: {info.Path}");
            Console.WriteLine($"  Exists: {info.Exists}");

            if (info.Exists)
            {
                Console.WriteLine($"  Size: {info.SizeBytes:N0} bytes ({info.SizeBytes / 1024.0:F2} KB)");
                Console.WriteLine($"  Created: {info.Created:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"  Last Modified: {info.LastModified:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"  Lockers: {info.LockerCount}");
                Console.WriteLine($"  SQLite Version: {info.SqliteVersion}");
                Console.WriteLine($"  Integrity: {(info.IntegrityOk ? "OK" : "FAILED")}");
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error getting database info: {ex.Message}");
            return 1;
        }
    }

    static int HandleHelpCommand(string[] args)
    {
        // TODO: Show help for specific command or general help
        // Usage: ColDogLocker.exe help [command]
        
        if (args.Length > 1)
        {
            var helpCommand = args[1].ToLowerInvariant();
            ShowCommandHelp(helpCommand);
        }
        else
        {
            ShowGeneralHelp();
        }

        return 0;
    }

    static int HandleVersionCommand()
    {
        Console.WriteLine($"ColDog Locker v{BuildInfo.Version}");
        Console.WriteLine("A secure file locker application");
        Console.WriteLine("Copyright © 2025 ColDog Studios");
        Console.WriteLine($"Build: {BuildInfo.BuildVersion}");
        Console.WriteLine($"Built: {BuildInfo.BuildDate} at {BuildInfo.BuildTime}");
        return 0;
    }

    static int HandleUnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        Console.WriteLine("Type 'ColDogLocker help' for usage information.");
        return 1;
    }

    #endregion

    #region Help System

    static void ShowGeneralHelp()
    {
        Console.WriteLine("ColDog Locker - Secure File Locker");
        Console.WriteLine();
        Console.WriteLine("USAGE:");
        Console.WriteLine("  ColDogLocker                           Launch GUI (default)");
        Console.WriteLine("  ColDogLocker gui                       Launch GUI explicitly");
        Console.WriteLine("  ColDogLocker terminal                  Launch Terminal UI");
        Console.WriteLine();
        Console.WriteLine("COMMANDS:");
        Console.WriteLine("  new <name> [options]                   Create a new locker");
        Console.WriteLine("    --path <path>                        Custom directory path");
        Console.WriteLine("    --password <pass>                    Password (insecure, for automation)");
        Console.WriteLine("  remove <name> [options]                Remove a locker");
        Console.WriteLine("    --force                              Skip confirmation prompt");
        Console.WriteLine("    --delete                             Also delete directory and contents");
        Console.WriteLine("  lock <name> [--password <pass>]        Lock a locker");
        Console.WriteLine("  unlock <name> [--password <pass>]      Unlock a locker");
        Console.WriteLine("  change-password <name>                 Change locker password");
        Console.WriteLine("  list [--locked|--unlocked]             List all lockers");
        Console.WriteLine("  status <name>                          Show locker status");
        Console.WriteLine("  verify <name>                          Verify locker integrity");
        Console.WriteLine("  settings [set <key> <value>]           View or modify settings");
        Console.WriteLine("  db-vacuum                              Optimize database");
        Console.WriteLine("  db-info                                Show database information");
        Console.WriteLine("  help [command]                         Show help information");
        Console.WriteLine("  --version, -v                          Show version information");
        Console.WriteLine();
        Console.WriteLine("For more information on a specific command, use:");
        Console.WriteLine("  ColDogLocker help <command>");
    }

    static void ShowCommandHelp(string command)
    {
        Console.WriteLine($"Help for command: {command}");
        Console.WriteLine();

        switch (command)
        {
            case "new":
                Console.WriteLine("CREATE NEW LOCKER:");
                Console.WriteLine("  ColDogLocker new <Locker Name> [--path <path>]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Creates a new locker with the specified name.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --path <path>    Specify a custom path for the locker");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker new MyLocker");
                Console.WriteLine("  ColDogLocker new MyLocker --path \"D:\\Lockers\"");
                break;

            case "remove":
                Console.WriteLine("REMOVE LOCKER:");
                Console.WriteLine("  ColDogLocker remove <Locker Name> [--force]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Removes the specified locker. Prompts for confirmation unless --force is used.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --force    Skip confirmation prompt");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker remove MyLocker");
                Console.WriteLine("  ColDogLocker remove MyLocker --force");
                break;

            case "lock":
                Console.WriteLine("LOCK LOCKER:");
                Console.WriteLine("  ColDogLocker lock <Locker Name> [--password <password>]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Locks the specified locker. Prompts for password unless provided.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --password <password>    Provide password (for automation, use cautiously)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker lock MyLocker");
                Console.WriteLine("  ColDogLocker lock MyLocker --password MySecurePass123");
                break;

            case "unlock":
                Console.WriteLine("UNLOCK LOCKER:");
                Console.WriteLine("  ColDogLocker unlock <Locker Name> [--password <password>]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Unlocks the specified locker. Prompts for password unless provided.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --password <password>    Provide password (for automation, use cautiously)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker unlock MyLocker");
                Console.WriteLine("  ColDogLocker unlock MyLocker --password MySecurePass123");
                break;

            case "list":
                Console.WriteLine("LIST LOCKERS:");
                Console.WriteLine("  ColDogLocker list [--locked | --unlocked]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Lists all lockers and their current status.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --locked      Show only locked lockers");
                Console.WriteLine("  --unlocked    Show only unlocked lockers");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker list");
                Console.WriteLine("  ColDogLocker list --locked");
                Console.WriteLine("  ColDogLocker list --unlocked");
                break;

            case "change-password":
                Console.WriteLine("CHANGE LOCKER PASSWORD:");
                Console.WriteLine("  ColDogLocker change-password <Locker Name>");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Changes the password for an existing locker. The locker must be unlocked");
                Console.WriteLine("  to change its password. You will be prompted to enter the current password");
                Console.WriteLine("  for verification, then provide a new password that meets security requirements.");
                Console.WriteLine();
                Console.WriteLine("REQUIREMENTS:");
                Console.WriteLine("  - Locker must be unlocked");
                Console.WriteLine("  - Must provide correct current password");
                Console.WriteLine("  - New password must meet requirements (8+ characters, uppercase, lowercase, digit, special char)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker change-password MyLocker");
                break;

            case "verify":
                Console.WriteLine("VERIFY LOCKER:");
                Console.WriteLine("  ColDogLocker verify <Locker Name>");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Verifies the integrity and consistency of a locker by performing");
                Console.WriteLine("  multiple checks on the directory structure and attributes.");
                Console.WriteLine();
                Console.WriteLine("CHECKS PERFORMED:");
                Console.WriteLine("  - Directory existence");
                Console.WriteLine("  - Directory access permissions");
                Console.WriteLine("  - Hidden/System attributes match lock state");
                Console.WriteLine("  - File and folder counts");
                Console.WriteLine();
                Console.WriteLine("OUTPUT:");
                Console.WriteLine("  [OK]   - Check passed");
                Console.WriteLine("  [FAIL] - Critical error found");
                Console.WriteLine("  [!]    - Warning or inconsistency detected");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker verify MyLocker");
                break;

            case "settings":
                Console.WriteLine("MANAGE SETTINGS:");
                Console.WriteLine("  ColDogLocker settings [<key> [<value>]]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  View or modify application settings. Call without arguments to view all");
                Console.WriteLine("  settings, with a key to view a specific setting, or with key and value");
                Console.WriteLine("  to update a setting.");
                Console.WriteLine();
                Console.WriteLine("AVAILABLE SETTINGS:");
                Console.WriteLine("  debug                 Enable/disable debug mode (true/false)");
                Console.WriteLine("  log-retention         Days to keep log files (1-3650)");
                Console.WriteLine("  auto-update           Enable/disable auto-updates (true/false)");
                Console.WriteLine("  db-vacuum-interval    Days between database optimizations (0=disabled, 1-365)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker settings");
                Console.WriteLine("  ColDogLocker settings debug");
                Console.WriteLine("  ColDogLocker settings debug true");
                Console.WriteLine("  ColDogLocker settings log-retention 60");
                Console.WriteLine("  ColDogLocker settings db-vacuum-interval 30");
                break;

            case "db-vacuum":
                Console.WriteLine("VACUUM DATABASE:");
                Console.WriteLine("  ColDogLocker db-vacuum");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Optimizes the database by reclaiming unused space and rebuilding");
                Console.WriteLine("  internal structures. This is useful after deleting many lockers or");
                Console.WriteLine("  when the database file seems larger than expected.");
                Console.WriteLine();
                Console.WriteLine("NOTES:");
                Console.WriteLine("  - Briefly locks the database during optimization");
                Console.WriteLine("  - Updates LastDatabaseVacuum timestamp in settings");
                Console.WriteLine("  - Reports bytes reclaimed after completion");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker db-vacuum");
                break;

            case "db-info":
                Console.WriteLine("DATABASE INFORMATION:");
                Console.WriteLine("  ColDogLocker db-info");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Displays detailed information about the SQLite database including");
                Console.WriteLine("  size, locker count, SQLite version, and integrity status.");
                Console.WriteLine();
                Console.WriteLine("INFORMATION DISPLAYED:");
                Console.WriteLine("  - Database file path");
                Console.WriteLine("  - Database file size");
                Console.WriteLine("  - Total number of lockers");
                Console.WriteLine("  - SQLite version");
                Console.WriteLine("  - Database integrity check status");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker db-info");
                break;

            case "status":
                Console.WriteLine("SHOW LOCKER STATUS:");
                Console.WriteLine("  ColDogLocker status <Locker Name>");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Shows detailed status information for the specified locker.");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker status MyLocker");
                break;

            case "gui":
                Console.WriteLine("LAUNCH GUI:");
                Console.WriteLine("  ColDogLocker gui");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Launches the graphical user interface.");
                break;

            case "terminal":
            case "tui":
                Console.WriteLine("LAUNCH TERMINAL UI:");
                Console.WriteLine("  ColDogLocker terminal");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Launches the terminal-based user interface.");
                break;

            default:
                Console.WriteLine($"No help available for command: {command}");
                Console.WriteLine();
                Console.WriteLine("Available commands: new, remove, lock, unlock, list, status, change-password, verify, settings, db-vacuum, db-info, gui, terminal");
                break;
        }
    }

    #endregion

    #region Helper Methods

    static string ReadPassword()
    {
        var password = new System.Text.StringBuilder();
        ConsoleKeyInfo key;
        
        do
        {
            key = Console.ReadKey(intercept: true);
            
            if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
            {
                password.Append(key.KeyChar);
                Console.Write("*");
            }
            else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
                Console.Write("\b \b");
            }
        } while (key.Key != ConsoleKey.Enter);
        
        Console.WriteLine();
        return password.ToString();
    }

    #endregion
}

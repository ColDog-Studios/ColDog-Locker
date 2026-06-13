/*
**  Copyright (C) 2026 ColDog Studios
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  long with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Security;
using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Tui.Input;

namespace ColDogStudios.ColDogLocker.Cli.Commands
{
    /// <summary>
    ///     Handlers for locker-related CLI commands (new, remove, lock, unlock, list, status, change-password, verify).
    /// </summary>
    public static class LockerCommands
    {
        #region New Locker

        public static int New(string[] args)
        {
            // Usage: cdlocker new <Locker Name> [--path "D:\Lockers"] [--password <password>]

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Locker name is required.");
                Console.WriteLine("Usage: cdlocker new <Locker Name> [--path <path>] [--password <password>]");
                return 1;
            }

            var lockerName = args[1];
            if (Path.IsPathRooted(lockerName))
            {
                Console.Error.WriteLine("Error: Locker name must be a relative name, not an absolute path.");
                return 1;
            }

            string? customPath = null;
            string? providedPassword = null;

            // Parse optional parameters
            for (var i = 2; i < args.Length; i++)
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
            var lockerLocation = customPath is not null
                ? Path.Combine(customPath, lockerName)
                : Path.Combine(AppPaths.CdlDir, lockerName);

            // Validate path is not protected
            var pathValidationError = LockerPathFilter.ValidatePath(lockerLocation);
            if (pathValidationError != null)
            {
                Console.Error.WriteLine($"Error: {pathValidationError}");
                return 1;
            }

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
                var validationError = PasswordFilter.ValidatePassword(password);
                if (validationError != null)
                {
                    Console.Error.WriteLine($"Error: Password validation failed: {validationError}");
                    return 1;
                }
            }
            else
            {
                // Prompt for password
                Console.WriteLine("Password Requirements:");
                foreach (var requirement in PasswordFilter.Validate(string.Empty))
                {
                    Console.WriteLine($"  - {requirement.Description}");
                }
                Console.WriteLine();

                while (true)
                {
                    Console.Write("Enter password: ");
                    password = ConsoleHelper.ReadPassword();

                    if (string.IsNullOrEmpty(password))
                    {
                        Console.WriteLine("Password cannot be empty.");
                        continue;
                    }

                    var validationError = PasswordFilter.ValidatePassword(password);
                    if (validationError == null)
                    {
                        break;
                    }

                    Console.WriteLine($"Password validation failed: {validationError}");
                }

                Console.Write("Confirm password: ");
                var confirmPassword = ConsoleHelper.ReadPassword();

                if (password != confirmPassword)
                {
                    Console.Error.WriteLine("Error: Passwords do not match.");
                    return 1;
                }
            }

            // Create the locker
            try
            {
                var passwordHash = EncryptionHelper.HashPassword(password);
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

        #endregion

        #region Remove Locker

        public static int Remove(string[] args)
        {
            // Usage: cdlocker remove <Locker Name> [--force] [--delete]

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Locker name is required.");
                Console.WriteLine("Usage: cdlocker remove <Locker Name> [--force] [--delete]");
                return 1;
            }

            var lockerName = args[1];
            var force = args.Contains("--force");
            var deleteDirectory = args.Contains("--delete");

            // Find the locker
            var locker = LockerService.Lockers.FirstOrDefault(l =>
                l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

            if (locker is null)
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
                if (confirmation is not "y" and not "yes")
                {
                    Console.WriteLine("Operation cancelled.");
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
                Logger.Log(LogLevel.Info, $"{lockerName} removed successfully.");

                // Delete directory if requested
                if (deleteDirectory && Directory.Exists(locker.LockerLocation))
                {
                    LockerService.DeleteLockerDirectory(locker);
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

        #endregion

        #region Lock Locker

        public static int Lock(string[] args)
        {
            // Usage: cdlocker lock <Locker Name> [--password <pass>]

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Locker name is required.");
                Console.WriteLine("Usage: cdlocker lock <Locker Name> [--password <password>]");
                return 1;
            }

            var lockerName = args[1];
            string? password = null;

            // Parse optional --password parameter
            for (var i = 2; i < args.Length; i++)
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

            if (locker is null)
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
                password = ConsoleHelper.ReadPassword();
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

        #endregion

        #region Unlock Locker

        public static int Unlock(string[] args)
        {
            // Usage: cdlocker unlock <Locker Name> [--password <pass>]

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Locker name is required.");
                Console.WriteLine("Usage: cdlocker unlock <Locker Name> [--password <password>]");
                return 1;
            }

            var lockerName = args[1];
            string? password = null;

            // Parse optional --password parameter
            for (var i = 2; i < args.Length; i++)
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

            if (locker is null)
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
                password = ConsoleHelper.ReadPassword();
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

        #endregion

        #region List Lockers

        public static int List(string[] args)
        {
            // Usage: cdlocker list [--locked|--unlocked]

            // Reload from database to get fresh data
            LockerService.LoadLockers();

            // Check for filter flags
            bool? filterLocked = null;
            if (args.Contains("--locked"))
            {
                filterLocked = true;
            }
            else if (args.Contains("--unlocked"))
            {
                filterLocked = false;
            }

            // Apply filter
            var lockers = LockerService.Lockers.AsEnumerable();
            if (filterLocked.HasValue)
            {
                lockers = lockers.Where(l => l.IsLocked == filterLocked.Value);
            }

            var lockerList = lockers.OrderBy(l => l.LockerName).ToList();

            if (lockerList.Count == 0)
            {
                if (filterLocked is true)
                {
                    Console.WriteLine("No locked lockers found.");
                }
                else if (filterLocked is false)
                {
                    Console.WriteLine("No unlocked lockers found.");
                }
                else
                {
                    Console.WriteLine("No lockers found.");
                }

                Console.WriteLine("Create a new locker with: cdlocker new <name>");
                return 0;
            }

            Console.WriteLine($"{"Name",-20} {"Status",-10} Location");
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

        #endregion

        # region Locker Status

        public static int Status(string[] args)
        {
            // Usage: cdlocker status <Locker Name>

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Locker name is required.");
                Console.WriteLine("Usage: cdlocker status <Locker Name>");
                return 1;
            }

            var lockerName = args[1];

            // Find the locker
            var locker = LockerService.Lockers.FirstOrDefault(l =>
                l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

            if (locker is null)
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
                var fileCount = dirInfo.GetFiles("*", SearchOption.AllDirectories).Length;
                var folderCount = dirInfo.GetDirectories("*", SearchOption.AllDirectories).Length;
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

        #endregion

        #region Change Locker Password

        public static int ChangePassword(string[] args)
        {
            // Usage: cdlocker change-password <Locker Name> [--old-password <password> --new-password <password>]

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Locker name is required.");
                Console.WriteLine("Usage: cdlocker change-password <Locker Name> [--old-password <password> --new-password <password>]");
                return 1;
            }

            var lockerName = args[1];
            string? providedOldPassword = null;
            string? providedNewPassword = null;

            for (var i = 2; i < args.Length; i++)
            {
                if (args[i] == "--old-password" && i + 1 < args.Length)
                {
                    providedOldPassword = args[i + 1];
                    i++;
                }
                else if (args[i] == "--new-password" && i + 1 < args.Length)
                {
                    providedNewPassword = args[i + 1];
                    i++;
                }
                else
                {
                    Console.Error.WriteLine($"Error: Unknown or incomplete option '{args[i]}'.");
                    Console.WriteLine("Usage: cdlocker change-password <Locker Name> [--old-password <password> --new-password <password>]");
                    return 1;
                }
            }

            var useProvidedPasswords = providedOldPassword != null || providedNewPassword != null;
            if (useProvidedPasswords && (string.IsNullOrEmpty(providedOldPassword) || string.IsNullOrEmpty(providedNewPassword)))
            {
                Console.Error.WriteLine("Error: Both --old-password and --new-password are required for non-interactive password changes.");
                return 1;
            }

            // Find the locker
            var locker = LockerService.Lockers.FirstOrDefault(l =>
                l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

            if (locker is null)
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

            string oldPassword;
            string newPassword;

            if (useProvidedPasswords)
            {
                oldPassword = providedOldPassword!;
                newPassword = providedNewPassword!;

                var validationError = PasswordFilter.ValidatePassword(newPassword);
                if (validationError != null)
                {
                    Console.Error.WriteLine($"Error: New password validation failed: {validationError}");
                    return 1;
                }
            }
            else
            {
                // Get old password
                Console.Write("Enter current password: ");
                oldPassword = ConsoleHelper.ReadPassword();

                if (string.IsNullOrEmpty(oldPassword))
                {
                    Console.Error.WriteLine("Error: Password cannot be empty.");
                    return 1;
                }

                Console.WriteLine("\nPassword Requirements:");
                Console.WriteLine("  - At least 12 characters");
                Console.WriteLine("  - At least one uppercase letter");
                Console.WriteLine("  - At least one lowercase letter");
                Console.WriteLine("  - At least one digit");
                Console.WriteLine("  - At least one special character");
                Console.WriteLine();

                while (true)
                {
                    Console.Write("Enter new password: ");
                    newPassword = ConsoleHelper.ReadPassword();

                    if (string.IsNullOrEmpty(newPassword))
                    {
                        Console.WriteLine("Password cannot be empty.");
                        continue;
                    }

                    var validationError = PasswordFilter.ValidatePassword(newPassword);
                    if (validationError == null)
                    {
                        break;
                    }

                    Console.WriteLine($"Password validation failed: {validationError}");
                }

                Console.Write("Confirm new password: ");
                var confirmPassword = ConsoleHelper.ReadPassword();

                if (newPassword != confirmPassword)
                {
                    Console.Error.WriteLine("Error: Passwords do not match.");
                    return 1;
                }
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

        #endregion

        #region Verify Locker

        public static int Verify(string[] args)
        {
            // Usage: cdlocker verify <Locker Name>

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Locker name is required.");
                Console.WriteLine("Usage: cdlocker verify <Locker Name>");
                return 1;
            }

            var lockerName = args[1];

            // Find the locker
            var locker = LockerService.Lockers.FirstOrDefault(l =>
                l.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase));

            if (locker is null)
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

            if (result.Errors.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Overall: INVALID");
                Console.ResetColor();
                return 1;
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Overall: WARNING");
            Console.ResetColor();
            return 0;
        }

        #endregion
    }
}

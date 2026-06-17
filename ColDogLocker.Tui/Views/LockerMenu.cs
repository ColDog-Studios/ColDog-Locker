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
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Services.Security;
using ColDogStudios.ColDogLocker.Tui.Input;

namespace ColDogStudios.ColDogLocker.Tui.Views
{
    public static class LockerMenu
    {
        // Create a new locker ///////////////////////////////////////////////////////////////////////////////////
        public static void NewLocker()
        {
            //
            string? lockerName;
            while (true)
            {
                // Show New Menu
                MainMenu.MenuTitle("Main Menu > New Locker");

                // Get locker name from user
                Console.Write("Enter Locker Name (or 0 to return): ");
                lockerName = Console.ReadLine();

                // Check if user wants to return to main menu
                if (lockerName == "0")
                {
                    return;
                }

                // Validate locker name
                if (!string.IsNullOrEmpty(lockerName))
                {
                    break;
                }

                Console.WriteLine("\nLocker name cannot be empty. Please try again.");
            }

            var passwordSecurityMessage =
                "\nPassword Requirements:\n" +
                string.Join(
                    Environment.NewLine,
                    PasswordFilter.Validate(string.Empty)
                        .Select(requirement => $" - {requirement.Description}")) +
                Environment.NewLine;

            string? password;
            while (true)
            {
                // Get locker password from user
                Console.WriteLine(passwordSecurityMessage);
                Console.Write("Enter Locker Password: ");
                password = ConsoleHelper.ReadPassword();

                // Validate password
                Logger.Log(LogLevel.Debug, "Validating locker password");
                var validationError = PasswordFilter.ValidatePassword(password);
                if (validationError != null)
                {
                    Logger.Log(LogLevel.Debug, $"Password not validated: {validationError}");
                    Console.WriteLine($"\nPassword not validated: {validationError}. Please try again.");
                    continue;
                }

                // Confirm locker password
                Console.Write("Confirm Locker Password: ");
                var confirmPassword = ConsoleHelper.ReadPassword();

                // Validate password confirmation
                Logger.Log(LogLevel.Debug, "Validating locker password confirmation");
                if (password == confirmPassword)
                {
                    break;
                }

                Logger.Log(LogLevel.Debug, "Passwords do not match");
                Console.WriteLine("\nPasswords do not match. Please try again.");
            }

            // Get locker location
            var lockerLocation = Path.Combine(AppPaths.CdlDir, lockerName);

            // Validate locker path is not protected
            Logger.Log(LogLevel.Debug, $"Validating locker path: {lockerLocation}");
            var pathValidationError = LockerPathFilter.ValidatePath(lockerLocation);
            if (pathValidationError != null)
            {
                Logger.Log(LogLevel.Error, $"Locker path validation failed: {pathValidationError}");
                Console.WriteLine($"\nError: {pathValidationError}");
                Console.Write("Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            if (LockerService.LockerExistsInMemory(lockerName))
            {
                Logger.Log(LogLevel.Warning, $"Locker creation failed: duplicate locker name {lockerName}");
                Console.Write($"\nLocker '{lockerName}' already exists. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            try
            {
                // Hash the password
                Logger.Log(LogLevel.Debug, "Hashing locker password");
                var passwordHash = EncryptionHelper.HashPassword(password);
                Logger.Log(LogLevel.Debug, "Locker password hashed successfully");

                // Create the locker
                Logger.Log(LogLevel.Debug, $"Creating locker: {lockerName} at {lockerLocation}");
                var locker = new LockerModel(lockerName, passwordHash, lockerLocation);
                LockerService.AddLocker(locker);
                Logger.Log(LogLevel.Info, $"Locker created successfully: {lockerName}");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, $"Locker creation failed: {lockerName}", ex);
                Console.Write($"\nError creating locker: {ex.Message}. Press Enter to continue...");
                Console.ReadLine();
            }
        }

        // Remove an existing locker /////////////////////////////////////////////////////////////////////////////
        public static void RemoveLocker()
        {
            while (true)
            {
                // Show Remove Menu
                MainMenu.MenuTitle("Main Menu > Remove Locker");

                // List unlocked lockers
                var unlockedLockers = LockerFilter.ListLockers(false);

                // Check if there are any unlocked lockers
                if (unlockedLockers.Count == 0)
                {
                    Console.Write("\nYou have no lockers to remove. Press Enter to continue...");
                    Console.ReadLine();
                    return;
                }

                // Display the lockers
                DisplayLockers(unlockedLockers);

                // Get locker index from user
                Console.Write("\nEnter the number of the locker to remove (or 0 to return): ");
                var input = Console.ReadLine();

                // Check if user wants to return to main menu
                if (input == "0")
                {
                    return;
                }

                if (int.TryParse(input, out var index) && index > 0 && index <= unlockedLockers.Count)
                {
                    var locker = unlockedLockers[index - 1];

                    // Confirm locker removal
                    Console.Write($"\nAre you sure you want to remove {locker.LockerName}? (y/N): ");
                    if (Console.ReadLine()?.ToLower() == "y")
                    {
                        // Remove locker from the metadata
                        LockerService.RemoveLocker(locker);
                        Console.Write($"\n{locker.LockerName} removed successfully. Press Enter to continue...");
                        Console.ReadLine();
                    }

                    return;
                }

                Console.Write("\nInvalid selection. Press Enter to continue...");
                Console.ReadLine();
            }
        }

        // Lock an existing locker //////////////////////////////////////////////////////////////////////////////
        public static void Lock()
        {
            // Show Lock Menu
            MainMenu.MenuTitle("Main Menu > Lock Locker");

            // List unlocked lockers
            var unlockedLockers = LockerFilter.ListLockers(false);

            // Check if there are any unlocked lockers
            if (unlockedLockers.Count == 0)
            {
                Console.Write("\nYou have no lockers to lock. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            // Display the lockers
            DisplayLockers(unlockedLockers);

            // Get locker index from user
            Console.Write("\nEnter the number of the locker to lock (or 0 to return): ");
            var input = Console.ReadLine();

            // Check if user wants to return to main menu
            if (input == "0")
            {
                return;
            }

            if (!int.TryParse(input, out var index) || index <= 0 || index > unlockedLockers.Count)
            {
                Console.Write("\nInvalid selection. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            var locker = unlockedLockers[index - 1];

            // Get locker password from user
            Console.Write("\nEnter Locker Password: ");
            var password = ConsoleHelper.ReadPassword();

            // Validate password
            if (string.IsNullOrEmpty(password))
            {
                Console.Write("\nPassword cannot be empty. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            // Attempt to lock the locker
            try
            {
                LockerService.Lock(locker, password);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write($"\n{ex.Message} Press Enter to continue...");
                Console.ReadLine();
            }
        }

        // Unlock an existing locker //////////////////////////////////////////////////////////////////////////////
        public static void Unlock()
        {
            // Show Unlock Menu
            MainMenu.MenuTitle("Main Menu > Unlock Locker");

            // List locked lockers
            var lockedLockers = LockerFilter.ListLockers(true);

            // Check if there are any locked lockers
            if (lockedLockers.Count == 0)
            {
                Console.Write("\nYou have no lockers to unlock. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            // Display the lockers
            DisplayLockers(lockedLockers);

            // Get locker index from user
            Console.Write("\nEnter the number of the locker to unlock (or 0 to return): ");
            var input = Console.ReadLine();

            // Check if user wants to return to main menu
            if (input == "0")
            {
                return;
            }

            if (!int.TryParse(input, out var index) || index <= 0 || index > lockedLockers.Count)
            {
                Console.WriteLine("\nInvalid selection. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            var locker = lockedLockers[index - 1];

            // Get locker password from user
            Console.Write("\nEnter Locker Password: ");
            var password = ConsoleHelper.ReadPassword();

            // Validate password
            if (string.IsNullOrEmpty(password))
            {
                Console.Write("\nPassword cannot be empty. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            // Attempt to unlock the locker
            try
            {
                LockerService.Unlock(locker, password);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write($"\n{ex.Message} Press Enter to continue...");
                Console.ReadLine();
            }
        }

        // Helper method to display lockers with numbering
        private static void DisplayLockers(List<LockerModel> lockers)
        {
            Console.WriteLine();
            for (var i = 0; i < lockers.Count; i++)
            {
                Console.WriteLine($"{i + 1}) {lockers[i].LockerName}");
            }
        }
    }
}

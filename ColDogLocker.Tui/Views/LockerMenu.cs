using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Application.Validation;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Infrastructure.Console;
using ColDogStudios.ColDogLocker.Infrastructure.Encryption;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

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

            //TODO: Get this messsage from ColDogLocker.Application.Validation.PasswordFilter
            var passwordSecurityMessage =
                "\nPassword Requirements:\n" +
                " - At least 12 characters long\n" +
                " - At least an upper-case letter\n" +
                " - At least a lower-case letter\n" +
                " - At least a number\n" +
                " - At least a special character (!@#$%^&*)\n";

            string? password;
            string? confirmPassword;
            while (true)
            {
                // Get locker password from user
                Console.WriteLine(passwordSecurityMessage);
                Console.Write("Enter Locker Password: ");
                password = ConsoleHelper.ReadPassword();

                // Validate password
                Logger.AddEntry("Validating locker password", LogLevel.Debug);
                var validationError = PasswordFilter.ValidatePassword(password);
                if (validationError != null)
                {
                    Logger.AddEntry($"Password not validated: {validationError}", LogLevel.Debug);
                    Console.WriteLine($"\nPassword not validated: {validationError}. Please try again.");
                    continue;
                }

                // Confirm locker password
                Console.Write("Confirm Locker Password: ");
                confirmPassword = ConsoleHelper.ReadPassword();

                // Validate password confirmation
                Logger.AddEntry("Validating locker password confirmation", LogLevel.Debug);
                if (password == confirmPassword)
                {
                    break;
                }

                Logger.AddEntry("Passwords do not match", LogLevel.Debug);
                Console.WriteLine("\nPasswords do not match. Please try again.");
            }

            // Get locker location
            var lockerLocation = Path.Combine(Variables.cdlDir, lockerName);
            
            // Validate locker path is not protected
            Logger.AddEntry($"Validating locker path: {lockerLocation}", LogLevel.Debug);
            var pathValidationError = LockerPathValidator.ValidatePath(lockerLocation);
            if (pathValidationError != null)
            {
                Logger.AddEntry($"Locker path validation failed: {pathValidationError}", LogLevel.Error);
                Console.WriteLine($"\nError: {pathValidationError}");
                Console.Write("Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            //TODO: Ensure hashing and creation is validated properly
            
            // Hash the password
            Logger.AddEntry("Hashing locker password", LogLevel.Debug);
            var passwordHash = EncryptionHelper.HashPassword(password);
            Logger.AddEntry("Locker password hashed successfully", LogLevel.Debug);

            // Create the locker
            Logger.AddEntry($"Creating locker: {lockerName} at {lockerLocation}", LogLevel.Debug);
            var locker = new LockerModel(lockerName, passwordHash, lockerLocation);
            LockerService.AddLocker(locker);
            Logger.AddEntry($"Locker created successfully: {lockerName}", LogLevel.Info);
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
                return;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write($"\n{ex.Message} Press Enter to continue...");
                Console.ReadLine();
                return;
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
                return;

            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write($"\n{ex.Message} Press Enter to continue...");
                Console.ReadLine();
                return;
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

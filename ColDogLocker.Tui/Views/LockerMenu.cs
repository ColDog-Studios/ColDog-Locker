using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Application.Validation;
using ColDogStudios.ColDogLocker.Infrastructure.Encryption;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
using ColDogStudios.ColDogLocker.Tui.Components;

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

            string passwordSecurityMessage =
                "\nPassword Requirements:\n" +
                " - At least 10 characters long\n" +
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
                password = Password.SecureRead();

                // Validate password
                try
                {
                    if (string.IsNullOrEmpty(password))
                    {
                        throw new Exception("Password cannot be empty");
                    }

                    // Check password security
                    PasswordFilter.SecurityCheck(password);
                    PasswordFilter.IllegalWordCheck(password);
                }
                catch (Exception ex)
                {
                    Logger.AddEntry($"Password not validated: {ex.Message}", LogLevel.Error);
                    Console.WriteLine($"\nPassword not validated: {ex.Message}. Please try again.");
                    continue;
                }

                // Confirm locker password
                Console.Write("Confirm Locker Password: ");
                confirmPassword = Password.SecureRead();

                // Validate password confirmation
                if (password == confirmPassword)
                {
                    break;
                }

                Console.WriteLine("\nPasswords do not match. Please try again.");
            }

            // Hash the password and create locker
            string passwordHash = EncryptionHelper.HashPassword(password);
            var locker = new LockerModel(lockerName, passwordHash, Path.Combine(Variables.cdlDir, lockerName));
            LockerService.AddLocker(locker);
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

                // Get locker index from user
                Console.Write("\nEnter the number of the locker to remove (or 0 to return): ");
                string? input = Console.ReadLine();
                
                // Check if user wants to return to main menu
                if (input == "0")
                {
                    return;
                }

                if (int.TryParse(input, out int index) && index > 0 && index <= unlockedLockers.Count)
                {
                    var locker = unlockedLockers[index - 1];

                    // Confirm locker removal
                    Console.Write($"\nAre you sure you want to remove {locker.LockerName}? (y/N): ");
                    if (Console.ReadLine()?.ToLower() == "y")
                    {
                        // Remove locker from the metadata
                        LockerService.RemoveLocker(locker);
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

            // Get locker index from user
            Console.Write("\nEnter the number of the locker to lock (or 0 to return): ");
            string? input = Console.ReadLine();
            
            // Check if user wants to return to main menu
            if (input == "0")
            {
                return;
            }

            if (!int.TryParse(input, out int index) || index <= 0 || index > unlockedLockers.Count)
            {
                Console.Write("\nInvalid selection. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            var locker = unlockedLockers[index - 1];

            // Get locker password from user
            Console.Write("\nEnter Locker Password: ");
            string? password = Password.SecureRead();

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

            // Get locker index from user
            Console.Write("\nEnter the number of the locker to unlock (or 0 to return): ");
            string? input = Console.ReadLine();
            
            // Check if user wants to return to main menu
            if (input == "0")
            {
                return;
            }

            if (!int.TryParse(input, out int index) || index <= 0 || index > lockedLockers.Count)
            {
                Console.WriteLine("\nInvalid selection. Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            var locker = lockedLockers[index - 1];

            // Get locker password from user
            Console.Write("\nEnter Locker Password: ");
            string? password = Password.SecureRead();

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
    }
}

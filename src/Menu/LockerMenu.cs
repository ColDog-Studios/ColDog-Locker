using ColDogStudios.ColDogLocker.Core;
using ColDogStudios.ColDogLocker.Models;
using ColDogStudios.ColDogLocker.Utils;

namespace ColDogStudios.ColDogLocker.Menu
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
                Console.Write("Enter Locker Name: ");
                lockerName = Console.ReadLine();

                // Validate locker name
                if (!string.IsNullOrEmpty(lockerName))
                {
                    break;
                }

                Console.WriteLine("\nLocker name cannot be empty. Please try again.");
            }

            string passwordSecurityMessage =
                "\nPassword Requirements:\n" +
                " - At least an upper-case letter\n" +
                " - At least a lower-case letter\n" +
                " - At least a number\n" +
                " - At least a special character\n";

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
            Locker.AddLocker(locker);
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

                // Get locker index from user
                Console.Write("\nEnter the number of the locker to remove: ");
                if (int.TryParse(Console.ReadLine(), out int index) && index > 0 && index <= unlockedLockers.Count)
                {
                    var locker = unlockedLockers[index - 1];

                    // Confirm locker removal
                    Console.Write($"\nAre you sure you want to remove {locker.LockerName}? (y/N): ");
                    if (Console.ReadLine()?.ToLower() == "y")
                    {
                        // Remove locker from the metadata
                        Locker.RemoveLocker(locker);
                    }
                    return;
                }

                Console.Write("\nInvalid selection.");
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

            // Get locker index from user
            Console.Write("\nEnter the number of the locker to lock: ");
            if (!int.TryParse(Console.ReadLine(), out int index) || index <= 0 || index > unlockedLockers.Count)
            {
                Console.Write("\nInvalid selection.");
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
                Console.Write("\nPassword cannot be empty.");
                Console.ReadLine();
                return;
            }

            // Attempt to lock the locker
            try
            {
                Locker.Lock(locker, password);
                return;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write(ex.Message);
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

            // Get locker index from user
            Console.Write("\nEnter the number of the locker to unlock: ");
            if (!int.TryParse(Console.ReadLine(), out int index) || index <= 0 || index > lockedLockers.Count)
            {
                Console.WriteLine("\nInvalid selection.");
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
                Console.Write("\nPassword cannot be empty.");
                Console.ReadLine();
                return;
            }

            // Attempt to unlock the locker
            try
            {
                Locker.Unlock(locker, password);
                return;

            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Write(ex.Message);
                Console.ReadLine();
                return;
            }
        }
    }
}

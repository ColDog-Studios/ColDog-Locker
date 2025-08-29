using ColDogStudios.ColDogLocker.Models;
using ColDogStudios.ColDogLocker.Utils;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Core
{
    public static class Locker
    {
        public static readonly List<LockerModel> Lockers = [];

        // Load locker metadata from the JSON file
        public static void LoadLockers()
        {
            try
            {
                // Define file path
                string filePath = Path.Combine(Variables.localConfig, "lockers.json");
                if (File.Exists(filePath))
                {
                    // Read and deserialize JSON data
                    string json = File.ReadAllText(filePath);
                    var lockers = JsonConvert.DeserializeObject<List<LockerModel>>(json);
                    if (lockers != null)
                    {
                        Lockers.Clear();
                        Lockers.AddRange(lockers);
                        Logger.AddEntry($"Successfully loaded {lockers.Count} lockers.", LogLevel.Info);
                    }
                    else
                    {
                        Logger.AddEntry("Lockers file is empty or invalid. Starting with empty locker list.", LogLevel.Warning);
                        Lockers.Clear();
                    }
                }
                else
                {
                    Logger.AddEntry("Lockers file not found. Starting with empty locker list.", LogLevel.Info);
                    Lockers.Clear();
                }
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"An error occurred while reading the lockers from the JSON file: {ex.Message}. Starting with empty locker list.", LogLevel.Error);
                Lockers.Clear(); // Ensure we have a clean state
            }
        }

        // Save locker metadata to the JSON file
        public static void SaveLockers()
        {
            try
            {
                // Serialize and write JSON data
                string json = JsonConvert.SerializeObject(Lockers, Formatting.Indented);
                File.WriteAllText(Path.Combine(Variables.localConfig, "lockers.json"), json);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"An error occurred while saving the lockers to the JSON file: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        // Add a new locker to the metadata
        public static void AddLocker(LockerModel locker)
        {
            // Create locker directory if it does not exist
            if (Directory.Exists(locker.LockerLocation))
            {
                Logger.AddEntry($"{locker.LockerName} already exists. Skipping directory creation.", LogLevel.Info);
                Console.WriteLine($"\n{locker.LockerName} already exists. Skipping directory creation.");
            }
            else
            {
                Directory.CreateDirectory(locker.LockerLocation);
                Logger.AddEntry($"Created directory: {locker.LockerLocation}", LogLevel.Info);
            }

            // Add the locker to the metadata
            Lockers.Add(locker);
            SaveLockers();

            Logger.AddEntry($"{locker.LockerName} created successfully.", LogLevel.Success);
            Console.Write($"\n{locker.LockerName} created successfully.");
            Console.ReadLine();
        }

        // Remove a locker from the metadata
        public static void RemoveLocker(LockerModel locker)
        {
            // Remove the locker from the metadata
            Lockers.Remove(locker);
            SaveLockers();

            Logger.AddEntry($"{locker.LockerName} removed successfully.", LogLevel.Success);
            Console.Write($"\n{locker.LockerName} removed successfully.");
            Console.ReadLine();
        }

        // Method to lock the locker
        public static void Lock(LockerModel locker, string password)
        {
            if (locker == null)
                throw new ArgumentNullException(nameof(locker));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            // Verify the password against the stored hash using bcrypt
            if (!EncryptionHelper.VerifyPassword(password, locker.Password))
            {
                Logger.AddEntry($"Failed to lock locker {locker.LockerName}. Incorrect password.", LogLevel.Error);
                throw new UnauthorizedAccessException("Incorrect password.");
            }

            // Rename the locker directory to be prefixed with a period
            string? lockerDirectory = Path.GetDirectoryName(locker.LockerLocation);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.AddEntry($"Invalid locker location: {locker.LockerLocation}", LogLevel.Error);
                throw new InvalidOperationException("Invalid locker location.");
            }
            
            string newLockerLocation = Path.Combine(lockerDirectory, $".{locker.LockerName}");
            Directory.Move(locker.LockerLocation, newLockerLocation);

            // Encrypt the locker directory
            EncryptionHelper.EncryptDirectory(newLockerLocation, password);

            // Set Hidden and System attributes to the locker directory
            File.SetAttributes(newLockerLocation, File.GetAttributes(newLockerLocation) | FileAttributes.Hidden | FileAttributes.System);

            // Update the locker status
            locker.IsLocked = true;
            locker.LockerLocation = newLockerLocation;

            // Save the updated locker metadata
            SaveLockers();

            // Log and display success message
            Logger.AddEntry($"Locker {locker.LockerName} locked successfully.", LogLevel.Success);
            Console.Write($"\n{locker.LockerName} locked successfully.");
            Console.ReadLine();
        }

        // Method to unlock the locker
        public static void Unlock(LockerModel locker, string password)
        {
            if (locker == null)
                throw new ArgumentNullException(nameof(locker));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            // Verify the password against the stored hash using bcrypt
            if (!EncryptionHelper.VerifyPassword(password, locker.Password))
            {
                Logger.AddEntry($"Failed to unlock locker {locker.LockerName}. Incorrect password.", LogLevel.Error);
                throw new UnauthorizedAccessException("Incorrect password.");
            }

            // Rename the locker directory to remove the period prefix and verify it is not null
            string? lockerDirectory = Path.GetDirectoryName(locker.LockerLocation);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.AddEntry($"Invalid locker location: {locker.LockerLocation}", LogLevel.Error);
                throw new InvalidOperationException("Invalid locker location.");
            }
            
            string newLockerLocation = Path.Combine(lockerDirectory, locker.LockerName);
            Directory.Move(locker.LockerLocation, newLockerLocation);

            // Decrypt the locker directory
            EncryptionHelper.DecryptDirectory(newLockerLocation, password);

            // Remove Hidden and System attributes from the locker directory
            File.SetAttributes(newLockerLocation, File.GetAttributes(newLockerLocation) & ~FileAttributes.Hidden & ~FileAttributes.System);

            // Update the locker status
            locker.IsLocked = false;
            locker.LockerLocation = newLockerLocation;

            // Save the updated locker metadata
            SaveLockers();

            // Log and display success message
            Logger.AddEntry($"{locker.LockerName} unlocked successfully.", LogLevel.Success);
            Console.Write($"\n{locker.LockerName} unlocked successfully.");
            Console.ReadLine();
        }
    }
}

using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Core.Utils;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Core.Services
{
    public static class LockerService
    {
        public static readonly List<LockerModel> Lockers = [];

        // Load locker metadata from the JSON file
        public static void LoadLockers()
        {
            try
            {
                string filePath = Path.Combine(Variables.LocalConfig, "lockers.json");
                if (File.Exists(filePath))
                {
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
                Lockers.Clear();
            }
        }

        // Save locker metadata to the JSON file
        public static void SaveLockers()
        {
            try
            {
                string json = JsonConvert.SerializeObject(Lockers, Formatting.Indented);
                File.WriteAllText(Path.Combine(Variables.LocalConfig, "lockers.json"), json);
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
            if (Directory.Exists(locker.LockerPath))
            {
                Logger.AddEntry($"{locker.LockerName} already exists. Skipping directory creation.", LogLevel.Info);
            }
            else
            {
                Directory.CreateDirectory(locker.LockerPath);
                Logger.AddEntry($"Created directory: {locker.LockerPath}", LogLevel.Info);
            }

            locker.UpdateSize(); // Calculate initial size
            Lockers.Add(locker);
            SaveLockers();

            Logger.AddEntry($"{locker.LockerName} created successfully.", LogLevel.Success);
        }

        // Remove a locker from the metadata
        public static void RemoveLocker(LockerModel locker)
        {
            Lockers.Remove(locker);
            SaveLockers();
            Logger.AddEntry($"{locker.LockerName} removed successfully.", LogLevel.Success);
        }

        // Method to lock the locker with async support
        public static async Task LockAsync(LockerModel locker, string password, IProgress<EncryptionHelper.ProgressInfo>? progress = null, CancellationToken cancellationToken = default)
        {
            if (locker == null)
                throw new ArgumentNullException(nameof(locker));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (!EncryptionHelper.VerifyPassword(password, locker.Password))
            {
                Logger.AddEntry($"Failed to lock locker {locker.LockerName}. Incorrect password.", LogLevel.Error);
                throw new UnauthorizedAccessException("Incorrect password.");
            }

            string? lockerDirectory = Path.GetDirectoryName(locker.LockerPath);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.AddEntry($"Invalid locker location: {locker.LockerPath}", LogLevel.Error);
                throw new InvalidOperationException("Invalid locker location.");
            }
            
            string newLockerLocation = Path.Combine(lockerDirectory, $".{locker.LockerName}");
            Directory.Move(locker.LockerPath, newLockerLocation);

            await EncryptionHelper.EncryptDirectoryAsync(newLockerLocation, password, progress, cancellationToken);

            File.SetAttributes(newLockerLocation, File.GetAttributes(newLockerLocation) | FileAttributes.Hidden | FileAttributes.System);

            locker.IsLocked = true;
            locker.LockerPath = newLockerLocation;
            locker.LastModified = DateTime.Now;

            SaveLockers();
            Logger.AddEntry($"Locker {locker.LockerName} locked successfully.", LogLevel.Success);
        }

        // Synchronous version for backward compatibility
        public static void Lock(LockerModel locker, string password)
        {
            LockAsync(locker, password).GetAwaiter().GetResult();
        }

        // Method to unlock the locker with async support
        public static async Task UnlockAsync(LockerModel locker, string password, IProgress<EncryptionHelper.ProgressInfo>? progress = null, CancellationToken cancellationToken = default)
        {
            if (locker == null)
                throw new ArgumentNullException(nameof(locker));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (!EncryptionHelper.VerifyPassword(password, locker.Password))
            {
                Logger.AddEntry($"Failed to unlock locker {locker.LockerName}. Incorrect password.", LogLevel.Error);
                throw new UnauthorizedAccessException("Incorrect password.");
            }

            string? lockerDirectory = Path.GetDirectoryName(locker.LockerPath);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.AddEntry($"Invalid locker location: {locker.LockerPath}", LogLevel.Error);
                throw new InvalidOperationException("Invalid locker location.");
            }
            
            string newLockerLocation = Path.Combine(lockerDirectory, locker.LockerName);
            Directory.Move(locker.LockerPath, newLockerLocation);

            await EncryptionHelper.DecryptDirectoryAsync(newLockerLocation, password, progress, cancellationToken);

            File.SetAttributes(newLockerLocation, File.GetAttributes(newLockerLocation) & ~FileAttributes.Hidden & ~FileAttributes.System);

            locker.IsLocked = false;
            locker.LockerPath = newLockerLocation;
            locker.LastModified = DateTime.Now;
            locker.UpdateSize();

            SaveLockers();
            Logger.AddEntry($"{locker.LockerName} unlocked successfully.", LogLevel.Success);
        }

        // Synchronous version for backward compatibility
        public static void Unlock(LockerModel locker, string password)
        {
            UnlockAsync(locker, password).GetAwaiter().GetResult();
        }

        // Get all lockers (for GUI binding)
        public static List<LockerModel> GetAllLockers()
        {
            foreach (var locker in Lockers)
            {
                locker.UpdateSize(); // Refresh size information
            }
            return Lockers.ToList();
        }

        // Get filtered lockers by locked status
        public static List<LockerModel> GetLockers(bool isLocked)
        {
            return Lockers.Where(l => l.IsLocked == isLocked).ToList();
        }
    }
}

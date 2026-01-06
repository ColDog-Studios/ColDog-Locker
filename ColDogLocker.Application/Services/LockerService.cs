using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Infrastructure.Data;
using ColDogStudios.ColDogLocker.Infrastructure.Encryption;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Application.Services
{
    public static class LockerService
    {
        public static readonly List<LockerModel> Lockers = [];

        // Load locker metadata from the database
        public static void LoadLockers()
        {
            try
            {
                Lockers.Clear();
                Lockers.AddRange(LockerRepository.GetAllLockers());
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"An error occurred while loading lockers from database: {ex.Message}. Starting with empty locker list.", LogLevel.Error);
                Lockers.Clear(); // Ensure we have a clean state
            }
        }

        // Save locker metadata to the database (updates existing locker)
        public static void SaveLockers()
        {
            // This method is now primarily for backwards compatibility
            // Individual operations (Add, Remove, Lock, Unlock) will update the database directly
            // But we can use this to sync the in-memory list back to the database if needed
            try
            {
                foreach (var locker in Lockers)
                {
                    LockerRepository.UpdateLocker(locker);
                }
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"An error occurred while saving lockers to database: {ex.Message}", LogLevel.Error);
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
            }
            else
            {
                Directory.CreateDirectory(locker.LockerLocation);
                Logger.AddEntry($"Created directory: {locker.LockerLocation}", LogLevel.Info);
            }

            // Add the locker to the database and in-memory list
            LockerRepository.InsertLocker(locker);
            Lockers.Add(locker);

            Logger.AddEntry($"{locker.LockerName} created successfully.", LogLevel.Success);
        }

        // Remove a locker from the metadata
        public static void RemoveLocker(LockerModel locker)
        {
            // Remove the locker from the database and in-memory list
            LockerRepository.DeleteLocker(locker.Guid);
            Lockers.Remove(locker);

            Logger.AddEntry($"{locker.LockerName} removed successfully.", LogLevel.Success);
            Console.Write($"\n{locker.LockerName} removed successfully. Press Enter to continue...");
            Console.ReadLine();
        }

        // Method to lock the locker
        public static void Lock(LockerModel locker, string password)
        {
            ArgumentNullException.ThrowIfNull(locker);
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

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

            // Save the updated locker to database
            LockerRepository.UpdateLocker(locker);

            // Log and display success message
            Logger.AddEntry($"Locker {locker.LockerName} locked successfully.", LogLevel.Success);
        }

        // Method to unlock the locker
        public static void Unlock(LockerModel locker, string password)
        {
            ArgumentNullException.ThrowIfNull(locker);
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

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

            // Save the updated locker to database
            LockerRepository.UpdateLocker(locker);

            // Log and display success message
            Logger.AddEntry($"{locker.LockerName} unlocked successfully.", LogLevel.Success);
        }

        // Method to change a locker's password
        public static void ChangePassword(LockerModel locker, string oldPassword, string newPassword)
        {
            ArgumentNullException.ThrowIfNull(locker);
            if (string.IsNullOrEmpty(oldPassword))
            {
                throw new ArgumentException("Old password cannot be null or empty.", nameof(oldPassword));
            }

            if (string.IsNullOrEmpty(newPassword))
            {
                throw new ArgumentException("New password cannot be null or empty.", nameof(newPassword));
            }

            // Verify the old password
            if (!EncryptionHelper.VerifyPassword(oldPassword, locker.Password))
            {
                Logger.AddEntry($"Failed to change password for {locker.LockerName}. Incorrect old password.", LogLevel.Error);
                throw new UnauthorizedAccessException("Incorrect old password.");
            }

            // Locker must be unlocked to change password
            if (locker.IsLocked)
            {
                Logger.AddEntry($"Cannot change password for locked locker {locker.LockerName}. Unlock it first.", LogLevel.Error);
                throw new InvalidOperationException("Locker must be unlocked to change password.");
            }

            // Verify directory exists
            if (!Directory.Exists(locker.LockerLocation))
            {
                Logger.AddEntry($"Locker directory not found: {locker.LockerLocation}", LogLevel.Error);
                throw new DirectoryNotFoundException($"Locker directory not found: {locker.LockerLocation}");
            }

            // Update password hash in database
            // Note: Files are already decrypted when locker is unlocked, so no re-encryption needed
            // The new password will be used next time the locker is locked
            Logger.AddEntry($"Updating password for {locker.LockerName}...", LogLevel.Info);
            locker.Password = EncryptionHelper.HashPassword(newPassword);
            LockerRepository.UpdateLocker(locker);

            Logger.AddEntry($"Password changed successfully for {locker.LockerName}.", LogLevel.Success);
        }

        // Method to verify locker integrity and status
        public static LockerVerificationResult Verify(LockerModel locker)
        {
            ArgumentNullException.ThrowIfNull(locker);

            var result = new LockerVerificationResult
            {
                LockerName = locker.LockerName,
                Guid = locker.Guid,
                IsLocked = locker.IsLocked
            };

            // Check if directory exists
            if (!Directory.Exists(locker.LockerLocation))
            {
                result.DirectoryExists = false;
                result.AddError("Directory does not exist at specified location");
                Logger.AddEntry($"Verification failed for {locker.LockerName}: Directory not found.", LogLevel.Warning);
                return result;
            }

            result.DirectoryExists = true;

            try
            {
                // Check directory attributes
                var attributes = File.GetAttributes(locker.LockerLocation);
                bool isHidden = (attributes & FileAttributes.Hidden) == FileAttributes.Hidden;
                bool isSystem = (attributes & FileAttributes.System) == FileAttributes.System;

                if (locker.IsLocked)
                {
                    // Locked locker should be hidden
                    if (!isHidden || !isSystem)
                    {
                        result.AddWarning("Locked locker directory is not properly hidden");
                    }

                    // Check if directory name starts with period
                    string dirName = Path.GetFileName(locker.LockerLocation);
                    if (!dirName.StartsWith('.'))
                    {
                        result.AddWarning("Locked locker directory name should start with period");
                    }
                }
                else
                {
                    // Unlocked locker should not be hidden
                    if (isHidden || isSystem)
                    {
                        result.AddWarning("Unlocked locker directory should not be hidden");
                    }

                    // Check if directory name starts with period
                    string dirName = Path.GetFileName(locker.LockerLocation);
                    if (dirName.StartsWith('.'))
                    {
                        result.AddWarning("Unlocked locker directory name should not start with period");
                    }
                }

                // Count files and directories
                var dirInfo = new DirectoryInfo(locker.LockerLocation);
                result.FileCount = dirInfo.GetFiles("*", SearchOption.AllDirectories).Length;
                result.DirectoryCount = dirInfo.GetDirectories("*", SearchOption.AllDirectories).Length;

                // Check permissions
                try
                {
                    // Try to read directory contents
                    _ = dirInfo.GetFileSystemInfos();
                    result.HasAccess = true;
                }
                catch (UnauthorizedAccessException)
                {
                    result.HasAccess = false;
                    result.AddError("Access denied to locker directory");
                }

                Logger.AddEntry($"Verification completed for {locker.LockerName}. Status: {(result.IsValid ? "Valid" : result.Errors.Count > 0 ? "Invalid" : "Warning")}", LogLevel.Info);
            }
            catch (Exception ex)
            {
                result.AddError($"Verification error: {ex.Message}");
                Logger.AddEntry($"Verification failed for {locker.LockerName}: {ex.Message}", LogLevel.Error);
            }

            return result;
        }
    }

    /// <summary>
    /// Result of locker verification
    /// </summary>
    public class LockerVerificationResult
    {
        public string LockerName { get; set; } = string.Empty;
        public string Guid { get; set; } = string.Empty;
        public bool IsLocked { get; set; }
        public bool DirectoryExists { get; set; }
        public bool HasAccess { get; set; }
        public int FileCount { get; set; }
        public int DirectoryCount { get; set; }
        public List<string> Errors { get; } = [];
        public List<string> Warnings { get; } = [];

        public bool IsValid => Errors.Count == 0 && DirectoryExists && HasAccess;

        public void AddError(string error) => Errors.Add(error);
        public void AddWarning(string warning) => Warnings.Add(warning);
    }
}

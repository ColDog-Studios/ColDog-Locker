using ColDogStudios.ColDogLocker.Application.Validation;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Infrastructure.Data;
using ColDogStudios.ColDogLocker.Infrastructure.Encryption;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Application.Services
{
    public static class LockerService
    {
        public static readonly List<LockerModel> Lockers = [];

        /// <summary>
        ///     Load locker metadata from the database
        /// </summary>
        public static void LoadLockers()
        {
            try
            {
                Logger.Log(LogLevel.Debug, "Loading lockers.");
                Lockers.Clear();
                Lockers.AddRange(LockerRepository.GetAllLockers());
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "An error occurred while loading lockers from database. Starting with empty locker list", ex);
                Lockers.Clear(); // Ensure we have a clean state
            }
        }

        /// <summary>
        ///     Save locker metadata to the database (updates existing locker)
        /// </summary>
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
                Logger.Log(LogLevel.Error, "An error occurred while saving lockers to database", ex);
                throw;
            }
        }

        /// <summary>
        ///     Add a new locker to the metadata
        /// </summary>
        /// <param name="locker"></param>
        public static void AddLocker(LockerModel locker)
        {
            // Create locker directory if it does not exist
            if (Directory.Exists(locker.LockerLocation))
            {
                Logger.Log(LogLevel.Debug, $"{locker.LockerName} already exists. Skipping directory creation");
            }
            else
            {
                Directory.CreateDirectory(locker.LockerLocation);
                Logger.Log(LogLevel.Info, $"Created directory: {locker.LockerLocation}");
            }

            // Add the locker to the database and in-memory list
            LockerRepository.InsertLocker(locker);
            Lockers.Add(locker);

            Logger.Log(LogLevel.Info, $"{locker.LockerName} created successfully");
        }

        /// <summary>
        ///     Remove a locker from the metadata
        /// </summary>
        /// <param name="locker"></param>
        public static void RemoveLocker(LockerModel locker)
        {
            // Remove the locker from the database and in-memory list
            LockerRepository.DeleteLocker(locker.Guid);
            Lockers.Remove(locker);

            Logger.Log(LogLevel.Info, $"{locker.LockerName} removed successfully");
        }

        /// <summary>
        ///     Method to lock the locker
        /// </summary>
        /// <param name="locker"></param>
        /// <param name="password"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="UnauthorizedAccessException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        public static void Lock(LockerModel locker, string password)
        {
            ArgumentNullException.ThrowIfNull(locker);
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

            // Safety check: Validate path is not protected (in case database was tampered with)
            var pathValidationError = LockerPathValidator.ValidatePath(locker.LockerLocation);
            if (pathValidationError != null)
            {
                Logger.Log(LogLevel.Fatal, $"Security violation: Attempted to lock protected directory {locker.LockerLocation}");
                throw new UnauthorizedAccessException($"Cannot lock this directory for security reasons: {pathValidationError}");
            }

            // Verify the password against the stored hash using bcrypt
            if (!EncryptionHelper.VerifyPassword(password, locker.Password))
            {
                Logger.Log(LogLevel.Error, $"Failed to lock locker {locker.LockerName}. Incorrect password");
                throw new UnauthorizedAccessException("Incorrect password.");
            }

            // Rename the locker directory to be prefixed with a period
            var lockerDirectory = Path.GetDirectoryName(locker.LockerLocation);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.Log(LogLevel.Error, $"Invalid locker location: {locker.LockerLocation}");
                throw new InvalidOperationException("Invalid locker location.");
            }

            var newLockerLocation = Path.Combine(lockerDirectory, $".{locker.LockerName}");
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
            Logger.Log(LogLevel.Info, $"Locker {locker.LockerName} locked successfully");
        }

        /// <summary>
        ///     Method to unlock the locker
        /// </summary>
        /// <param name="locker"></param>
        /// <param name="password"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="UnauthorizedAccessException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
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
                Logger.Log(LogLevel.Error, $"Failed to unlock locker {locker.LockerName}. Incorrect password");
                throw new UnauthorizedAccessException("Incorrect password.");
            }

            // Rename the locker directory to remove the period prefix and verify it is not null
            var lockerDirectory = Path.GetDirectoryName(locker.LockerLocation);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.Log(LogLevel.Error, $"Invalid locker location: {locker.LockerLocation}");
                throw new InvalidOperationException("Invalid locker location.");
            }

            var newLockerLocation = Path.Combine(lockerDirectory, locker.LockerName);
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
            Logger.Log(LogLevel.Info, $"{locker.LockerName} unlocked successfully");
        }

        /// <summary>
        ///     Method to change a locker's password
        /// </summary>
        /// <param name="locker"></param>
        /// <param name="oldPassword"></param>
        /// <param name="newPassword"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="UnauthorizedAccessException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="DirectoryNotFoundException"></exception>
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
                Logger.Log(LogLevel.Error, $"Failed to change password for {locker.LockerName}. Incorrect old password");
                throw new UnauthorizedAccessException("Incorrect old password.");
            }

            // Locker must be unlocked to change password
            if (locker.IsLocked)
            {
                Logger.Log(LogLevel.Error, $"Cannot change password for locked locker {locker.LockerName}. Unlock it first");
                throw new InvalidOperationException("Locker must be unlocked to change password.");
            }

            // Verify directory exists
            if (!Directory.Exists(locker.LockerLocation))
            {
                Logger.Log(LogLevel.Error, $"Locker directory not found: {locker.LockerLocation}");
                throw new DirectoryNotFoundException($"Locker directory not found: {locker.LockerLocation}");
            }

            // Update password hash in database
            // Note: Files are already decrypted when locker is unlocked, so no re-encryption needed
            // The new password will be used next time the locker is locked
            Logger.Log(LogLevel.Info, $"Updating password for {locker.LockerName}...");
            locker.Password = EncryptionHelper.HashPassword(newPassword);
            LockerRepository.UpdateLocker(locker);

            Logger.Log(LogLevel.Info, $"Password changed successfully for {locker.LockerName}");
        }

        /// <summary>
        ///     Method to verify locker integrity and status
        /// </summary>
        /// <param name="locker"></param>
        /// <returns></returns>
        public static LockerVerificationResult Verify(LockerModel locker)
        {
            ArgumentNullException.ThrowIfNull(locker);

            var result = new LockerVerificationResult { LockerName = locker.LockerName, Guid = locker.Guid, IsLocked = locker.IsLocked };

            // Check if directory exists
            if (!Directory.Exists(locker.LockerLocation))
            {
                result.DirectoryExists = false;
                result.AddError("Directory does not exist at specified location");
                Logger.Log(LogLevel.Warning, $"Verification failed for {locker.LockerName}: Directory not found.");
                return result;
            }

            result.DirectoryExists = true;

            try
            {
                // Check directory attributes
                var attributes = File.GetAttributes(locker.LockerLocation);
                var isHidden = (attributes & FileAttributes.Hidden) == FileAttributes.Hidden;
                var isSystem = (attributes & FileAttributes.System) == FileAttributes.System;

                if (locker.IsLocked)
                {
                    // Locked locker should be hidden
                    if (!isHidden || !isSystem)
                    {
                        result.AddWarning("Locked locker directory is not properly hidden");
                    }

                    // Check if directory name starts with period
                    var dirName = Path.GetFileName(locker.LockerLocation);
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
                    var dirName = Path.GetFileName(locker.LockerLocation);
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

                Logger.Log(LogLevel.Info,
                    $"Verification completed for {locker.LockerName}. Status: {(result.IsValid ? "Valid" : result.Errors.Count > 0 ? "Invalid" : "Warning")}");
            }
            catch (Exception ex)
            {
                result.AddError($"Verification error: {ex.Message}");
                Logger.Log(LogLevel.Error, $"Verification failed for {locker.LockerName}: {ex.Message}");
            }

            return result;
        }
    }

    /// <summary>
    ///     Result of locker verification
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

        public void AddError(string error)
        {
            Errors.Add(error);
        }

        public void AddWarning(string warning)
        {
            Warnings.Add(warning);
        }
    }
}

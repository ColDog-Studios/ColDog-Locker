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

using ColDogStudios.ColDogLocker.Services.Security;
using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Core.Validation;

namespace ColDogStudios.ColDogLocker.Services.Lockers
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
                    UpdateLocker(locker);
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
            ArgumentNullException.ThrowIfNull(locker);
            ValidateLockerDefinition(locker);

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
        ///     Update a locker's persisted metadata after validating path and name safety.
        /// </summary>
        public static void UpdateLocker(LockerModel locker)
        {
            ArgumentNullException.ThrowIfNull(locker);
            ValidateLockerDefinition(locker);
            LockerRepository.UpdateLocker(locker);
        }

        /// <summary>
        ///     Update mutable locker metadata while preserving the previous in-memory values on failure.
        /// </summary>
        public static void UpdateLockerMetadata(LockerModel locker, string lockerName, string lockerLocation)
        {
            ArgumentNullException.ThrowIfNull(locker);

            var previousName = locker.LockerName;
            var previousLocation = locker.LockerLocation;

            try
            {
                locker.LockerName = lockerName;
                locker.LockerLocation = lockerLocation;
                UpdateLocker(locker);
            }
            catch
            {
                locker.LockerName = previousName;
                locker.LockerLocation = previousLocation;
                throw;
            }
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
            ValidateLockerDefinition(locker);
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

            var lockerDirectory = Path.GetDirectoryName(locker.LockerLocation);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.Log(LogLevel.Error, $"Invalid locker location: {locker.LockerLocation}");
                throw new InvalidOperationException("Invalid locker location.");
            }

            var newLockerLocation = Path.Combine(lockerDirectory, $".{locker.LockerName}");
            if (Directory.Exists(newLockerLocation))
            {
                throw new IOException($"Target locked locker directory already exists: {newLockerLocation}");
            }

            var previousLocation = locker.LockerLocation;
            try
            {
                // Encrypt before renaming so a rename failure does not leave the database pointing at a plaintext directory.
                EncryptionHelper.EncryptDirectory(previousLocation, password);
                Directory.Move(previousLocation, newLockerLocation);

                // Set Hidden and System attributes to the locker directory
                File.SetAttributes(newLockerLocation, File.GetAttributes(newLockerLocation) | FileAttributes.Hidden | FileAttributes.System);

                // Update the locker status
                locker.IsLocked = true;
                locker.LockerLocation = newLockerLocation;

                // Save the updated locker to database
                UpdateLocker(locker);
            }
            catch
            {
                RollBackLockFailure(locker, previousLocation, newLockerLocation, password);
                throw;
            }

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
            ValidateLockerDefinition(locker);
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
            if (Directory.Exists(newLockerLocation))
            {
                throw new IOException($"Target unlocked locker directory already exists: {newLockerLocation}");
            }

            var previousLocation = locker.LockerLocation;
            try
            {
                // Decrypt before renaming; EncryptionHelper rolls back files if a decrypt operation fails.
                EncryptionHelper.DecryptDirectory(previousLocation, password);

                // Remove Hidden and System attributes from the locker directory
                File.SetAttributes(previousLocation, File.GetAttributes(previousLocation) & ~FileAttributes.Hidden & ~FileAttributes.System);
                Directory.Move(previousLocation, newLockerLocation);

                // Update the locker status
                locker.IsLocked = false;
                locker.LockerLocation = newLockerLocation;

                // Save the updated locker to database
                UpdateLocker(locker);
            }
            catch
            {
                RollBackUnlockFailure(locker, previousLocation, newLockerLocation, password);
                throw;
            }

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
            UpdateLocker(locker);

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

        /// <summary>
        ///     Delete an unlocked locker directory after validating the persisted locker metadata.
        /// </summary>
        public static void DeleteLockerDirectory(LockerModel locker)
        {
            ArgumentNullException.ThrowIfNull(locker);
            ValidateLockerDefinition(locker);

            if (locker.IsLocked)
            {
                throw new InvalidOperationException("Cannot delete a locked locker directory.");
            }

            if (!Directory.Exists(locker.LockerLocation))
            {
                return;
            }

            var directoryName = Path.GetFileName(locker.LockerLocation.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if (!directoryName.Equals(locker.LockerName, StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException("Locker directory name does not match locker metadata.");
            }

            Directory.Delete(locker.LockerLocation, recursive: true);
        }

        private static void ValidateLockerDefinition(LockerModel locker)
        {
            var nameValidationError = ValidateLockerName(locker.LockerName);
            if (nameValidationError != null)
            {
                throw new ArgumentException(nameValidationError, nameof(locker));
            }

            var pathValidationError = LockerPathValidator.ValidatePath(locker.LockerLocation);
            if (pathValidationError != null)
            {
                Logger.Log(LogLevel.Fatal, $"Security violation: Unsafe locker path rejected: {locker.LockerLocation}");
                throw new UnauthorizedAccessException($"Cannot use this directory for security reasons: {pathValidationError}");
            }
        }

        private static string? ValidateLockerName(string lockerName)
        {
            if (string.IsNullOrWhiteSpace(lockerName))
            {
                return "Locker name cannot be empty.";
            }

            var trimmedName = lockerName.Trim();
            if (Path.IsPathRooted(trimmedName) ||
                trimmedName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                trimmedName.Contains(Path.DirectorySeparatorChar) ||
                trimmedName.Contains(Path.AltDirectorySeparatorChar) ||
                trimmedName is "." or "..")
            {
                return "Locker name must be a valid file name, not a path.";
            }

            return null;
        }

        private static void RollBackLockFailure(LockerModel locker, string previousLocation, string newLockerLocation, string password)
        {
            try
            {
                if (Directory.Exists(newLockerLocation) && !Directory.Exists(previousLocation))
                {
                    File.SetAttributes(newLockerLocation, File.GetAttributes(newLockerLocation) & ~FileAttributes.Hidden & ~FileAttributes.System);
                    Directory.Move(newLockerLocation, previousLocation);
                }

                if (Directory.Exists(previousLocation))
                {
                    EncryptionHelper.DecryptDirectory(previousLocation, password);
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, $"Failed to fully roll back lock operation for {locker.LockerName}", ex);
            }

            locker.IsLocked = false;
            locker.LockerLocation = previousLocation;
        }

        private static void RollBackUnlockFailure(LockerModel locker, string previousLocation, string newLockerLocation, string password)
        {
            try
            {
                var rollbackLocation = Directory.Exists(newLockerLocation) && !Directory.Exists(previousLocation)
                    ? newLockerLocation
                    : previousLocation;

                if (Directory.Exists(rollbackLocation))
                {
                    EncryptionHelper.EncryptDirectory(rollbackLocation, password);
                    if (rollbackLocation == newLockerLocation)
                    {
                        Directory.Move(newLockerLocation, previousLocation);
                    }

                    File.SetAttributes(previousLocation, File.GetAttributes(previousLocation) | FileAttributes.Hidden | FileAttributes.System);
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, $"Failed to fully roll back unlock operation for {locker.LockerName}", ex);
            }

            locker.IsLocked = true;
            locker.LockerLocation = previousLocation;
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

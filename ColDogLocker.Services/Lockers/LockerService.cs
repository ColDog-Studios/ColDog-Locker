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

using System.Security.Cryptography;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Services.Security;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public static class LockerService
    {
        private static readonly object _lockerStateLock = new();
        private static readonly List<LockerModel> _lockers = [];

        public static IReadOnlyList<LockerModel> Lockers => GetLockersSnapshot();

        public static List<LockerModel> GetLockersSnapshot()
        {
            lock (_lockerStateLock)
            {
                return _lockers.Select(locker => locker.Copy()).ToList();
            }
        }

        public static LockerModel? FindLockerByName(string lockerName)
        {
            lock (_lockerStateLock)
            {
                return _lockers.FirstOrDefault(locker =>
                    locker.LockerName.Equals(lockerName, StringComparison.OrdinalIgnoreCase))?.Copy();
            }
        }

        public static LockerModel? FindLockerByGuid(string guid)
        {
            lock (_lockerStateLock)
            {
                return _lockers.FirstOrDefault(locker => locker.Guid == guid)?.Copy();
            }
        }

        public static bool LockerExistsInMemory(string lockerName)
        {
            return FindLockerByName(lockerName) is not null;
        }

        internal static void ReplaceLockersForTesting(IEnumerable<LockerModel> lockers)
        {
            lock (_lockerStateLock)
            {
                _lockers.Clear();
                _lockers.AddRange(lockers.Select(locker => locker.Copy()));
            }
        }

        internal static void ClearLockersForTesting()
        {
            ReplaceLockersForTesting([]);
        }

        /// <summary>
        ///     Load locker metadata from the database
        /// </summary>
        public static void LoadLockers() => LoadLockers(LockerRepository.GetAllLockers, LockerRepository.GetPendingOperations);

        internal static void LoadLockers(
            Func<List<LockerModel>> loadLockers,
            Func<IReadOnlyList<PendingLockerOperation>> loadPendingOperations)
        {
            ArgumentNullException.ThrowIfNull(loadLockers);
            ArgumentNullException.ThrowIfNull(loadPendingOperations);
            try
            {
                Logger.Log(LogLevel.Debug, "Loading lockers.");
                var loadedLockers = loadLockers();
                foreach (var pending in loadPendingOperations())
                {
                    Logger.Log(LogLevel.Warning, $"Unfinished {pending.Kind} operation for locker {pending.LockerGuid}: {pending.Phase}. Run 'cdlocker recovery-list'. Staging: {pending.StagingPath}");
                }

                lock (_lockerStateLock)
                {
                    _lockers.Clear();
                    _lockers.AddRange(loadedLockers);
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "An error occurred while loading lockers from database. Keeping existing locker list.", ex);
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
            using var operationLease = LockerOperationLease.Acquire(locker.Guid);
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

            _ = FileSystemPathIdentity.CaptureDirectory(locker.LockerLocation);
            ValidateLockerDefinition(locker);

            // Add the locker to the database and in-memory list
            LockerRepository.InsertLocker(locker);
            lock (_lockerStateLock)
            {
                _lockers.Add(locker.Copy());
            }

            Logger.Log(LogLevel.Info, $"{locker.LockerName} created successfully");
        }

        /// <summary>
        ///     Update a locker's persisted metadata after validating path and name safety.
        /// </summary>
        public static void UpdateLocker(LockerModel locker) => PersistLocker(locker, operationCommit: false);

        private static void CommitLockerOperation(LockerModel locker) => PersistLocker(locker, operationCommit: true);

        private static void PersistLocker(LockerModel locker, bool operationCommit)
        {
            ArgumentNullException.ThrowIfNull(locker);
            using var operationLease = LockerOperationLease.Acquire(locker.Guid);
            ValidateLockerDefinition(locker);
            if (operationCommit)
            {
                LockerRepository.CommitOperation(locker);
            }
            else
            {
                LockerRepository.UpdateLocker(locker);
            }

            lock (_lockerStateLock)
            {
                var index = _lockers.FindIndex(existing => existing.Guid == locker.Guid);
                if (index >= 0)
                {
                    _lockers[index] = locker.Copy();
                }
            }
        }

        /// <summary>
        ///     Update mutable locker metadata while preserving the previous in-memory values on failure.
        /// </summary>
        public static void UpdateLockerMetadata(LockerModel locker, string lockerName, string lockerLocation)
        {
            ArgumentNullException.ThrowIfNull(locker);
            using var operationLease = LockerOperationLease.Acquire(locker.Guid);

            if (locker.IsLocked &&
                (!string.Equals(locker.LockerName, lockerName, StringComparison.Ordinal) ||
                 !string.Equals(locker.LockerLocation, lockerLocation, StringComparison.Ordinal)))
            {
                throw new InvalidOperationException("Unlock the locker before changing its name or location.");
            }

            var previousName = locker.LockerName;
            var previousLocation = locker.LockerLocation;

            try
            {
                locker.LockerName = lockerName;
                locker.LockerLocation = lockerLocation;
                UpdateLocker(locker);
            }
            catch (Exception)
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
        public static void RemoveLocker(LockerModel locker, bool deleteDirectory = false)
        {
            ArgumentNullException.ThrowIfNull(locker);
            using var operationLease = LockerOperationLease.Acquire(locker.Guid);

            if (locker.IsLocked)
            {
                throw new InvalidOperationException("Unlock the locker before removing it.");
            }

            // Remove the locker from the database and in-memory list
            LockerRepository.EnsureCurrent(locker);
            if (deleteDirectory)
            {
                DeleteLockerDirectory(locker);
            }

            LockerRepository.DeleteLocker(locker.Guid, locker.Revision);
            lock (_lockerStateLock)
            {
                _lockers.RemoveAll(existing => existing.Guid == locker.Guid);
            }

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
            Lock(locker, password, progress: null, CancellationToken.None);
        }

        public static void Lock(LockerModel locker, string password,
            IProgress<LockerOperationProgress>? progress, CancellationToken cancellationToken)
        {
            Lock(locker, password, CommitLockerOperation, path => Directory.Delete(path, true),
                LockerRepository.EnsureCurrent, LockerRepository.CreateOperationJournal(),
                progress: progress, cancellationToken: cancellationToken);
        }

        internal static void Lock(
            LockerModel locker,
            string password,
            Action<LockerModel> persistLocker,
            Action<string> deleteSource,
            Action<LockerModel>? validateCurrent = null,
            LockerOperationJournal? journal = null,
            Action<string>? beforeSourceClaim = null,
            Action<string>? afterSourceClaim = null,
            IProgress<LockerOperationProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(persistLocker);
            ArgumentNullException.ThrowIfNull(deleteSource);
            ArgumentNullException.ThrowIfNull(locker);
            using var operationLease = LockerOperationLease.Acquire(locker.Guid);
            cancellationToken.ThrowIfCancellationRequested();
            Report(progress, "Preparing", "Preparing locker for encryption", 0, canCancel: true);
            ValidateLockerDefinition(locker);
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

            // Safety check: Validate path is not protected (in case database was tampered with)
            var pathValidationError = LockerPathFilter.ValidatePath(locker.LockerLocation);
            if (pathValidationError != null)
            {
                Logger.Log(LogLevel.Fatal, $"Security violation: Attempted to lock protected directory {locker.LockerLocation}");
                throw new UnauthorizedAccessException($"Cannot lock this directory for security reasons: {pathValidationError}");
            }

            // Verify the complete password before selecting its encryption key.
            if (!EncryptionHelper.VerifyPassword(password, locker.Password))
            {
                Logger.Log(LogLevel.Error, $"Failed to lock locker {locker.LockerName}. Incorrect password");
                throw new UnauthorizedAccessException("Incorrect password.");
            }

            validateCurrent?.Invoke(locker);
            var sourcePathIdentity = FileSystemPathIdentity.CaptureDirectory(locker.LockerLocation);
            var lockerDirectory = Path.GetDirectoryName(locker.LockerLocation);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.Log(LogLevel.Error, $"Invalid locker location: {locker.LockerLocation}");
                throw new InvalidOperationException("Invalid locker location.");
            }

            var newLockerLocation = Path.Join(lockerDirectory, $".{locker.LockerName}");
            if (Directory.Exists(newLockerLocation))
            {
                throw new IOException($"Target locked locker directory already exists: {newLockerLocation}");
            }

            if (locker.IsLocked)
            {
                throw new InvalidOperationException("Locker is already locked.");
            }

            var previousLocation = locker.LockerLocation;
            string? sourceRootWindowsAccessControl = null;
            if (OperatingSystem.IsWindows())
            {
                var sourceRoot = new DirectoryInfo(previousLocation);
                FileSystemMetadataPolicy.EnsureSupported(sourceRoot);
                sourceRootWindowsAccessControl = FileSystemMetadataPolicy.CaptureWindowsAccessControl(sourceRoot);
            }

            var tempLockedLocation = Path.Join(lockerDirectory, $".{locker.LockerName}.{Guid.NewGuid():N}.locking");
            var claimedSourceLocation = Path.Join(tempLockedLocation, "source");
            journal?.Begin(locker, "Lock", newLockerLocation, tempLockedLocation);
            LockerOperationBoundary.Reached("Lock.JournalPrepared");
            var sourceDeletionStarted = false;
            var sourceClaimed = false;
            var archivePublished = false;
            FileStream? sourceSentinel = null;
            byte[]? sourceSentinelToken = null;
            try
            {
                LockerArchiveService.CreatePrivateDirectory(tempLockedLocation);
                var privateStagingWindowsAccessControl = OperatingSystem.IsWindows()
                    ? FileSystemMetadataPolicy.CaptureWindowsAccessControl(new DirectoryInfo(tempLockedLocation))
                    : null;
                var archivePath = LockerArchiveService.GetArchivePath(tempLockedLocation);
                var archive = LockerArchiveService.CreateFromDirectory(previousLocation, archivePath, locker, password,
                    maxExtractedBytes: LockerArchiveService.MaxExtractedBytes,
                    cancellationToken: cancellationToken,
                    reportProgress: (message, percent) =>
                        Report(progress, "Archiving", message, percent, canCancel: true));
                if (OperatingSystem.IsWindows() && !string.Equals(
                    FileSystemMetadataPolicy.CaptureWindowsAccessControl(new DirectoryInfo(previousLocation)),
                    sourceRootWindowsAccessControl,
                    StringComparison.Ordinal))
                {
                    throw new IOException("The locker root access-control list changed while the archive was being created.");
                }

                DurableFileSystem.FlushDirectory(tempLockedLocation);
                LockerOperationBoundary.Reached("Lock.ArchiveDurable");

                journal?.Advance("ArchiveReady");
                LockerOperationBoundary.Reached("Lock.ArchiveReady");
                beforeSourceClaim?.Invoke(previousLocation);
                cancellationToken.ThrowIfCancellationRequested();
                sourcePathIdentity.EnsureUnchanged();
                if (OperatingSystem.IsWindows())
                {
                    FileSystemMetadataPolicy.EnsureExpectedRootSupported(
                        new DirectoryInfo(previousLocation),
                        sourceRootWindowsAccessControl!);
                    FileSystemMetadataPolicy.EnsureExpectedRootSupported(
                        new DirectoryInfo(tempLockedLocation),
                        privateStagingWindowsAccessControl!);
                }

                Report(progress, "Publishing", "Publishing the encrypted locker; cancellation is no longer safe", 85, canCancel: false);
                journal?.Advance("SourceRemovalStarted");
                LockerOperationBoundary.Reached("Lock.SourceRemovalStarted");
                DurableFileSystem.MoveDirectory(previousLocation, claimedSourceLocation);
                sourceClaimed = true;
                if (FileSystemIdentity.CaptureDirectory(claimedSourceLocation) != sourcePathIdentity.LeafIdentity)
                {
                    throw new IOException("The claimed source directory does not match the directory inspected before locking.");
                }

                LockerOperationBoundary.Reached("Lock.SourceClaimed");
                sourceSentinel = CreateSourceSentinel(previousLocation, out sourceSentinelToken);
                LockerOperationBoundary.Reached("Lock.SourceSentinelDurable");
                afterSourceClaim?.Invoke(previousLocation);
                var claimedTreeSha256 = OperatingSystem.IsWindows()
                    ? LockerTreeDigest.ComputeClaimedWindowsSource(
                        claimedSourceLocation,
                        tempLockedLocation,
                        privateStagingWindowsAccessControl!)
                    : LockerTreeDigest.Compute(claimedSourceLocation);
                if (!claimedTreeSha256.Equals(archive.SourceTreeSha256, StringComparison.Ordinal))
                {
                    throw new IOException("Locker contents changed while the archive was being created. Locking was refused and the changed source was preserved.");
                }

                sourceDeletionStarted = true;
                deleteSource(claimedSourceLocation);
                if (Directory.Exists(claimedSourceLocation))
                {
                    throw new IOException("Source removal did not remove the complete claimed locker tree.");
                }

                DurableFileSystem.FlushDirectory(tempLockedLocation);
                LockerOperationBoundary.Reached("Lock.SourceDeleted");

                sourceClaimed = false;
                DurableFileSystem.MoveDirectory(tempLockedLocation, newLockerLocation);
                archivePublished = true;
                LockerOperationBoundary.Reached("Lock.ArchivePublished");
                journal?.Advance("Published");
                LockerOperationBoundary.Reached("Lock.Published");
                ReleaseSourceSentinel(ref sourceSentinel, ref sourceSentinelToken, previousLocation);

                // Set Hidden and System attributes to the locker directory
                File.SetAttributes(newLockerLocation, File.GetAttributes(newLockerLocation) | FileAttributes.Hidden | FileAttributes.System);

                // Update the locker status
                locker.IsLocked = true;
                locker.LockerLocation = newLockerLocation;
                locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
                locker.LockedArchiveSha256 = archive.Sha256;
                locker.LockedAtUtc = archive.LockedAtUtc;

                // Save the updated locker to database
                persistLocker(locker);
                LockerOperationBoundary.Reached("Lock.MetadataCommitted");
            }
            catch (Exception ex)
            {
                try
                {
                    ReleaseSourceSentinel(ref sourceSentinel, ref sourceSentinelToken, previousLocation);
                }
                catch (Exception sentinelException) when (sentinelException is IOException
                    or UnauthorizedAccessException
                    or InvalidOperationException)
                {
                    Logger.Log(LogLevel.Warning, $"Failed to release source sentinel '{previousLocation}'.", sentinelException);
                }

                if (sourceClaimed && Directory.Exists(claimedSourceLocation) && !Path.Exists(previousLocation))
                {
                    try
                    {
                        DurableFileSystem.MoveDirectory(claimedSourceLocation, previousLocation);
                        sourceClaimed = false;
                    }
                    catch (Exception restoreException) when (restoreException is IOException
                        or UnauthorizedAccessException)
                    {
                        Logger.Log(LogLevel.Error, $"Failed to restore claimed source '{claimedSourceLocation}' to '{previousLocation}'.", restoreException);
                    }
                }

                locker.IsLocked = false;
                locker.LockerLocation = previousLocation;
                locker.StorageFormatVersion = null;
                locker.LockedArchiveSha256 = null;
                locker.LockedAtUtc = null;
                if (sourceClaimed)
                {
                    var retainedArchive = LockerArchiveService.GetArchivePath(tempLockedLocation);
                    Logger.Log(LogLevel.Error,
                        $"Lock failed after claiming the source. Preserve source '{claimedSourceLocation}' and archive '{retainedArchive}'.", ex);
                    throw new LockerRecoveryRequiredException(retainedArchive, claimedSourceLocation, ex);
                }

                if (sourceDeletionStarted)
                {
                    // The source may be partially deleted even if its root still exists.
                    // Never discard the completed archive or touch an unowned destination.
                    var retainedArchive = LockerArchiveService.GetArchivePath(archivePublished ? newLockerLocation : tempLockedLocation);
                    Logger.Log(LogLevel.Error, $"Lock failed after source deletion began. Preserve recovery archive '{retainedArchive}'.", ex);
                    throw new LockerRecoveryRequiredException(retainedArchive, ex);
                }

                LockerArchiveService.TryDeleteDirectory(tempLockedLocation);
                if (!Directory.Exists(tempLockedLocation))
                {
                    journal?.End();
                }

                throw;
            }

            journal?.End();
            LockerOperationBoundary.Reached("Lock.JournalCleared");
            Report(progress, "Completed", "Locker encrypted successfully", 100, canCancel: false);

            // Log and display success message
            Logger.Log(LogLevel.Info, $"Locker {locker.LockerName} locked successfully");
        }

        private static FileStream CreateSourceSentinel(string path, out byte[] token)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            var stream = new FileStream(path, options);
            try
            {
                token = RandomNumberGenerator.GetBytes(32);
                stream.Write(token);
                stream.Flush(flushToDisk: true);
                var parent = Path.GetDirectoryName(Path.GetFullPath(path))
                    ?? throw new IOException($"Source sentinel '{path}' has no parent directory.");
                DurableFileSystem.FlushDirectory(parent);
                return stream;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        private static void ReleaseSourceSentinel(
            ref FileStream? sentinel,
            ref byte[]? token,
            string path)
        {
            if (sentinel == null)
            {
                return;
            }

            sentinel.Dispose();
            sentinel = null;
            var expected = token ?? throw new InvalidOperationException("Source sentinel identity is missing.");
            token = null;
            var quarantine = path + $".cdl-sentinel-{Guid.NewGuid():N}";
            DurableFileSystem.MoveFile(path, quarantine);
            try
            {
                var matches = false;
                using (var input = FileSystemEntryPolicy.OpenRead(quarantine, rejectHardLinks: true))
                {
                    var actual = new byte[expected.Length];
                    input.ReadExactly(actual);
                    matches = input.ReadByte() == -1 && CryptographicOperations.FixedTimeEquals(actual, expected);
                }

                if (!matches)
                {
                    throw new IOException("The source sentinel was replaced. Lock completion was refused and the replacement was preserved.");
                }

                DurableFileSystem.DeleteFile(quarantine);
            }
            catch
            {
                if (File.Exists(quarantine) && !Path.Exists(path))
                {
                    DurableFileSystem.MoveFile(quarantine, path);
                }

                throw;
            }
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
            Unlock(locker, password, progress: null, CancellationToken.None);
        }

        public static void Unlock(LockerModel locker, string password,
            IProgress<LockerOperationProgress>? progress, CancellationToken cancellationToken)
        {
            Unlock(locker, password, CommitLockerOperation, validateCurrent: LockerRepository.EnsureCurrent,
                journal: LockerRepository.CreateOperationJournal(), progress: progress,
                cancellationToken: cancellationToken);
        }

        internal static void Unlock(LockerModel locker, string password, Action<LockerModel> persistLocker,
            Action<string, string>? publishDirectory = null, Action<LockerModel>? validateCurrent = null,
            LockerOperationJournal? journal = null, IProgress<LockerOperationProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(locker);
            using var operationLease = LockerOperationLease.Acquire(locker.Guid);
            cancellationToken.ThrowIfCancellationRequested();
            Report(progress, "Preparing", "Verifying encrypted locker", 0, canCancel: true);
            ArgumentNullException.ThrowIfNull(persistLocker);
            ValidateLockerDefinition(locker);
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

            // Verify the password against the current versioned verifier.
            if (!EncryptionHelper.VerifyPassword(password, locker.Password))
            {
                Logger.Log(LogLevel.Error, $"Failed to unlock locker {locker.LockerName}. Incorrect password");
                throw new UnauthorizedAccessException("Incorrect password.");
            }

            // Rename the locker directory to remove the period prefix and verify it is not null
            validateCurrent?.Invoke(locker);
            var lockerDirectory = Path.GetDirectoryName(locker.LockerLocation);
            if (string.IsNullOrEmpty(lockerDirectory))
            {
                Logger.Log(LogLevel.Error, $"Invalid locker location: {locker.LockerLocation}");
                throw new InvalidOperationException("Invalid locker location.");
            }

            var newLockerLocation = Path.Join(lockerDirectory, locker.LockerName);
            if (Directory.Exists(newLockerLocation))
            {
                throw new IOException($"Target unlocked locker directory already exists: {newLockerLocation}");
            }

            var previousLocation = locker.LockerLocation;
            var previousStorageFormatVersion = locker.StorageFormatVersion;
            var previousLockedArchiveSha256 = locker.LockedArchiveSha256;
            var previousLockedAtUtc = locker.LockedAtUtc;
            var stagingLocation = Path.Join(lockerDirectory, $"{locker.LockerName}.{Guid.NewGuid():N}.unlocking");
            var archivePath = LockerArchiveService.GetArchivePath(previousLocation);
            var archivePathIdentity = FileSystemPathIdentity.CaptureDirectory(previousLocation);
            Report(progress, "Preparing",
                $"Verifying encrypted locker; {LockerArchiveService.DescribeAvailableSpace(newLockerLocation)}. " +
                "The exact restored size is authenticated while files are restored.",
                5, canCancel: true);
            var archiveVerification = LockerArchiveService.VerifyArchive(archivePath, locker, locker.LockedArchiveSha256);
            if (!archiveVerification.IsValid)
            {
                throw new InvalidDataException(string.Join(" ", archiveVerification.Errors));
            }

            journal?.Begin(locker, "Unlock", newLockerLocation, stagingLocation);
            LockerOperationBoundary.Reached("Unlock.JournalPrepared");
            var plaintextPublished = false;
            FileSystemIdentity? plaintextIdentity = null;
            try
            {
                var stagingWindowsAccessControl = LockerArchiveService.ExtractToDirectory(
                    archivePath, stagingLocation, locker, password,
                    cancellationToken, (message, percent) =>
                        Report(progress, "Restoring", message, percent, canCancel: true));
                DurableFileSystem.FlushDirectoryTree(stagingLocation);
                plaintextIdentity = FileSystemIdentity.CaptureDirectory(stagingLocation);
                LockerOperationBoundary.Reached("Unlock.ExtractionDurable");

                string? outputTreeSha256 = null;
                if (journal != null)
                {
                    outputTreeSha256 = LockerTreeDigest.Compute(stagingLocation, stagingWindowsAccessControl);
                    journal.Advance("ExtractionReady", outputTreeSha256);
                }

                LockerOperationBoundary.Reached("Unlock.ExtractionReady");

                cancellationToken.ThrowIfCancellationRequested();
                archivePathIdentity.EnsureUnchanged();
                Report(progress, "Publishing", "Publishing restored files; cancellation is no longer safe", 90, canCancel: false);
                (publishDirectory ?? DurableFileSystem.MoveDirectory)(stagingLocation, newLockerLocation);
                plaintextPublished = true;
                if (FileSystemIdentity.CaptureDirectory(newLockerLocation) != plaintextIdentity)
                {
                    throw new IOException("The published plaintext directory does not match the authenticated staging directory. Recovery files were preserved.");
                }

                FileSystemMetadataPolicy.NormalizePublishedTree(newLockerLocation);
                if (outputTreeSha256 != null && LockerTreeDigest.Compute(newLockerLocation) != outputTreeSha256)
                {
                    throw new IOException("The published plaintext tree changed while its Windows access control was normalized. Recovery files were preserved.");
                }

                LockerOperationBoundary.Reached("Unlock.PlaintextPublished");
                journal?.Advance("Published");
                LockerOperationBoundary.Reached("Unlock.Published");

                // Update the locker status
                locker.IsLocked = false;
                locker.LockerLocation = newLockerLocation;
                locker.StorageFormatVersion = null;
                locker.LockedArchiveSha256 = null;
                locker.LockedAtUtc = null;

                // Save the updated locker to database
                persistLocker(locker);
                LockerOperationBoundary.Reached("Unlock.MetadataCommitted");
            }
            catch (OperationCanceledException) when (!plaintextPublished)
            {
                LockerArchiveService.TryDeleteDirectory(stagingLocation);
                if (!Directory.Exists(stagingLocation))
                {
                    journal?.End();
                }

                throw;
            }
            catch (Exception ex)
            {
                if (journal != null)
                {
                    throw new IOException("Unlock did not complete. Its operation journal and recovery files were retained. Run 'cdlocker recovery-list' before making further changes.", ex);
                }

                RollBackUnlockFailure(
                    locker,
                    previousLocation,
                    newLockerLocation,
                    stagingLocation,
                    previousStorageFormatVersion,
                    previousLockedArchiveSha256,
                    previousLockedAtUtc,
                    plaintextPublished,
                    plaintextIdentity);
                throw;
            }

            try
            {
                DurableFileSystem.DeleteOwnedDirectory(previousLocation, archivePathIdentity.LeafIdentity, recursive: true);
                LockerOperationBoundary.Reached("Unlock.ArchiveDeleted");
                journal?.End();
                LockerOperationBoundary.Reached("Unlock.JournalCleared");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Unlocked {locker.LockerName}, but failed to remove locked archive directory '{previousLocation}'.", ex);
            }

            // Log and display success message
            Report(progress, "Completed", "Locker restored successfully", 100, canCancel: false);
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
            ChangePassword(locker, oldPassword, newPassword, UpdateLocker, LockerRepository.EnsureCurrent);
        }

        internal static void ChangePassword(LockerModel locker, string oldPassword, string newPassword, Action<LockerModel> persistLocker, Action<LockerModel>? validateCurrent = null)
        {
            ArgumentNullException.ThrowIfNull(locker);
            using var operationLease = LockerOperationLease.Acquire(locker.Guid);
            ArgumentNullException.ThrowIfNull(persistLocker);
            if (string.IsNullOrEmpty(oldPassword))
            {
                throw new ArgumentException("Old password cannot be null or empty.", nameof(oldPassword));
            }

            if (string.IsNullOrEmpty(newPassword))
            {
                throw new ArgumentException("New password cannot be null or empty.", nameof(newPassword));
            }

            var passwordError = PasswordFilter.ValidatePassword(newPassword);
            if (passwordError != null)
            {
                throw new ArgumentException(passwordError, nameof(newPassword));
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
            validateCurrent?.Invoke(locker);
            var proposed = locker.Copy();
            proposed.Password = EncryptionHelper.HashPassword(newPassword);
            persistLocker(proposed);
            locker.Password = proposed.Password;
            locker.Revision = proposed.Revision;

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
                var counts = DirectoryContentScanner.Count(locker.LockerLocation);
                result.FileCount = counts.Files;
                result.DirectoryCount = counts.Directories;
                result.CountsComplete = true;
                result.HasAccess = true;

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

                    var hasUnexpectedEntries = new DirectoryInfo(locker.LockerLocation)
                        .EnumerateFileSystemInfos()
                        .Any(entry => !entry.Name.Equals(LockerArchiveService.ArchiveFileName, StringComparison.Ordinal));
                    if (hasUnexpectedEntries)
                    {
                        result.AddError("Locked locker directory contains unexpected entries beside locker.cdl.");
                    }

                    var archivePath = LockerArchiveService.GetArchivePath(locker.LockerLocation);
                    var archiveVerification = LockerArchiveService.VerifyArchive(archivePath, locker, locker.LockedArchiveSha256);
                    result.ArchiveExists = archiveVerification.ArchiveExists;
                    result.ArchiveHashMatches = archiveVerification.HashMatches;
                    result.ArchiveMetadataReadable = archiveVerification.MetadataReadable;
                    result.ArchiveMetadataMatches = archiveVerification.MetadataMatches;
                    result.ArchiveSha256 = archiveVerification.ActualSha256;
                    result.LockedAtUtc = archiveVerification.Metadata?.LockedAtUtc ?? locker.LockedAtUtc;
                    foreach (var error in archiveVerification.Errors)
                    {
                        result.AddError(error);
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

                    var lockedSibling = Path.Join(
                        Path.GetDirectoryName(locker.LockerLocation) ?? string.Empty,
                        $".{locker.LockerName}");
                    var leftoverArchivePath = LockerArchiveService.GetArchivePath(lockedSibling);
                    if (File.Exists(leftoverArchivePath))
                    {
                        result.ArchiveExists = true;
                        result.AddError("Unlocked locker has a leftover locked archive sibling.");
                    }
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
            using var operationLease = LockerOperationLease.Acquire(locker.Guid);
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

            var pathIdentity = FileSystemPathIdentity.CaptureDirectory(locker.LockerLocation);
            LockerRepository.EnsureCurrent(locker);
            pathIdentity.EnsureUnchanged();
            DurableFileSystem.DeleteOwnedDirectory(locker.LockerLocation, pathIdentity.LeafIdentity, recursive: true);
        }

        private static void ValidateLockerDefinition(LockerModel locker)
        {
            var nameValidationError = ValidateLockerName(locker.LockerName);
            if (nameValidationError != null)
            {
                throw new ArgumentException(nameValidationError, nameof(locker));
            }

            var pathValidationError = LockerPathFilter.ValidatePath(locker.LockerLocation);
            if (pathValidationError != null)
            {
                Logger.Log(LogLevel.Fatal, $"Security violation: Unsafe locker path rejected: {locker.LockerLocation}");
                throw new UnauthorizedAccessException($"Cannot use this directory for security reasons: {pathValidationError}");
            }
        }

        internal static string? ValidateLockerName(string lockerName)
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

        private static void RollBackUnlockFailure(
            LockerModel locker,
            string previousLocation,
            string newLockerLocation,
            string stagingLocation,
            int? previousStorageFormatVersion,
            string? previousLockedArchiveSha256,
            DateTime? previousLockedAtUtc,
            bool plaintextPublished,
            FileSystemIdentity? plaintextIdentity)
        {
            var lockedArchiveStillExists = Directory.Exists(previousLocation);

            try
            {
                if (Directory.Exists(stagingLocation))
                {
                    LockerArchiveService.TryDeleteDirectory(stagingLocation);
                }

                if (plaintextPublished && plaintextIdentity is { } identity && lockedArchiveStillExists && Directory.Exists(newLockerLocation))
                {
                    DurableFileSystem.DeleteOwnedDirectory(newLockerLocation, identity, recursive: true);
                }

                if (lockedArchiveStillExists)
                {
                    File.SetAttributes(previousLocation, File.GetAttributes(previousLocation) | FileAttributes.Hidden | FileAttributes.System);
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, $"Failed to fully roll back unlock operation for {locker.LockerName}", ex);
            }

            if (lockedArchiveStillExists)
            {
                locker.IsLocked = true;
                locker.LockerLocation = previousLocation;
                locker.StorageFormatVersion = previousStorageFormatVersion;
                locker.LockedArchiveSha256 = previousLockedArchiveSha256;
                locker.LockedAtUtc = previousLockedAtUtc;
            }
            else if (plaintextPublished && Directory.Exists(newLockerLocation))
            {
                locker.IsLocked = false;
                locker.LockerLocation = newLockerLocation;
                locker.StorageFormatVersion = null;
                locker.LockedArchiveSha256 = null;
                locker.LockedAtUtc = null;
            }
        }

        private static void Report(IProgress<LockerOperationProgress>? progress, string stage, string message,
            int? percent, bool canCancel)
        {
            progress?.Report(new LockerOperationProgress(stage, message, percent, canCancel));
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
        public bool CountsComplete { get; set; }
        public int FileCount { get; set; }
        public int DirectoryCount { get; set; }
        public bool ArchiveExists { get; set; }
        public bool ArchiveHashMatches { get; set; }
        public bool ArchiveMetadataReadable { get; set; }
        public bool ArchiveMetadataMatches { get; set; }
        public string? ArchiveSha256 { get; set; }
        public DateTime? LockedAtUtc { get; set; }
        public List<string> Errors { get; } = [];
        public List<string> Warnings { get; } = [];

        public bool IsValid => Errors.Count == 0 && DirectoryExists && HasAccess && CountsComplete;

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

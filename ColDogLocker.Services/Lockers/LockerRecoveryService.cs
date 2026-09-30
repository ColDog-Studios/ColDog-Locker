using System.Text.Json;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Security;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    /// <summary>Authenticated extraction without a database or stored password verifier.</summary>
    public static class LockerRecoveryService
    {
        public static PendingLockerOperation FinishCommittedOperation(string operationId)
            => FinishCommittedOperation(operationId, LockerRepository.RecoveryConnectionString);

        internal static PendingLockerOperation FinishCommittedOperation(string operationId, string connectionString)
        {
            var operation = LockerRepository.GetPendingOperations(connectionString).SingleOrDefault(item => item.OperationId == operationId)
                ?? throw new InvalidOperationException("Pending operation not found.");
            using var lease = LockerOperationLease.Acquire(operation.LockerGuid);
            operation = LockerRepository.GetPendingOperations(connectionString).SingleOrDefault(item => item.OperationId == operationId)
                ?? throw new InvalidOperationException("Operation changed before reconciliation.");
            if (operation.Phase != "MetadataCommitted")
            {
                throw new InvalidOperationException("This operation did not commit metadata. Use verified recovery instead.");
            }

            var current = LockerRepository.GetLockerByGuid(operation.LockerGuid, connectionString)
                ?? throw new InvalidOperationException("Locker registration is missing.");
            using var before = JsonDocument.Parse(operation.BeforeJson);
            var snapshot = before.RootElement;
            if (current.Revision != checked(snapshot.GetProperty("Revision").GetInt64() + 1) ||
                current.Guid != snapshot.GetProperty("Guid").GetString() ||
                current.LockerName != snapshot.GetProperty("LockerName").GetString() ||
                current.Password != snapshot.GetProperty("Password").GetString() ||
                current.LockerLocation != operation.TargetPath || operation.SourcePath != snapshot.GetProperty("LockerLocation").GetString())
            {
                throw new InvalidOperationException("Committed metadata does not match the operation. Records were preserved.");
            }

            var validation = LockerPathFilter.ValidatePath(current.LockerLocation);
            if (validation != null || !Directory.Exists(current.LockerLocation))
            {
                throw new InvalidDataException("The committed destination is missing or unsafe. Records were preserved.");
            }

            if (operation.Kind == "Lock" && !snapshot.GetProperty("IsLocked").GetBoolean() && current.IsLocked)
            {
                var archivePath = LockerArchiveService.GetArchivePath(current.LockerLocation);
                var archiveInfo = new FileInfo(archivePath);
                if (current.LockedArchiveSha256 == null || archiveInfo.LinkTarget != null ||
                    (archiveInfo.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    Directory.EnumerateFileSystemEntries(current.LockerLocation).Take(2).Count() != 1)
                {
                    throw new InvalidDataException("Locked destination is not the expected archive-only directory.");
                }

                var verified = LockerArchiveService.VerifyArchive(archivePath, current, current.LockedArchiveSha256);
                if (!verified.IsValid || verified.Metadata?.FormatVersion != current.StorageFormatVersion ||
                    verified.Metadata?.LockedAtUtc != current.LockedAtUtc)
                {
                    throw new InvalidDataException("Committed archive failed verification. Records were preserved.");
                }
            }
            else if (operation.Kind == "Unlock" && snapshot.GetProperty("IsLocked").GetBoolean() && !current.IsLocked)
            {
                if (current.StorageFormatVersion != null || current.LockedArchiveSha256 != null || current.LockedAtUtc != null ||
                    operation.OutputTreeSha256 == null || LockerTreeDigest.Compute(current.LockerLocation) != operation.OutputTreeSha256)
                {
                    throw new InvalidDataException("Restored contents changed or cannot be verified against the journal. Files and records were preserved.");
                }
            }
            else
            {
                throw new InvalidDataException("Committed locker state is inconsistent with its operation.");
            }

            LockerRepository.ArchiveCommittedOperation(operation, current.Revision, connectionString);
            return operation;
        }

        public static LockerModel RecoverOperation(string operationId, string archivePath, string destinationDirectory, string password)
            => RecoverOperation(operationId, archivePath, destinationDirectory, password, LockerRepository.RecoveryConnectionString);

        internal static LockerModel RecoverOperation(
            string operationId,
            string archivePath,
            string destinationDirectory,
            string password,
            string connectionString,
            Action<string, string, LockerModel, string>? extractArchive = null)
        {
            var operation = LockerRepository.GetPendingOperations(connectionString).SingleOrDefault(item => item.OperationId == operationId)
                ?? throw new InvalidOperationException("Pending operation not found.");
            using var lease = LockerOperationLease.Acquire(operation.LockerGuid);
            operation = LockerRepository.GetPendingOperations(connectionString).SingleOrDefault(item => item.OperationId == operationId)
                ?? throw new InvalidOperationException("Operation changed before recovery started.");
            var current = LockerRepository.GetLockerByGuid(operation.LockerGuid, connectionString)
                ?? throw new InvalidOperationException("Locker registration is missing. Use standalone recover to preserve its files.");
            using var before = JsonDocument.Parse(operation.BeforeJson);
            var originalName = before.RootElement.GetProperty("LockerName").GetString();
            var metadata = LockerArchiveService.ReadMetadata(archivePath);
            if (metadata.LockerGuid != operation.LockerGuid || metadata.LockerName != originalName || current.LockerName != originalName)
            {
                throw new InvalidDataException("Archive identity does not match this operation.");
            }

            var destination = Path.GetFullPath(destinationDirectory);
            var validation = LockerPathFilter.ValidatePath(destination);
            if (validation != null)
            {
                throw new UnauthorizedAccessException(validation);
            }

            if (Path.Exists(destination) || Path.GetFileName(destination) != originalName)
            {
                throw new IOException("Choose a new destination directory whose final component is the original locker name.");
            }

            var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            var artifactPaths = new[] { operation.SourcePath, operation.TargetPath, operation.StagingPath };
            foreach (var artifact in artifactPaths)
            {
                var path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(artifact));
                if (destination.Equals(path, comparison) || destination.StartsWith(path + Path.DirectorySeparatorChar, comparison) ||
                    path.StartsWith(destination + Path.DirectorySeparatorChar, comparison))
                {
                    throw new IOException("Recovery destination must be separate from all recorded operation directories.");
                }
            }

            var archive = Path.GetFullPath(archivePath);
            var candidates = operation.Kind switch
            {
                "Lock" => new[] { operation.StagingPath, operation.TargetPath },
                "Unlock" => new[] { operation.SourcePath },
                _ => throw new InvalidDataException("Unsupported journal operation kind.")
            };
            if (!candidates.Any(path => Path.GetFullPath(LockerArchiveService.GetArchivePath(path)).Equals(archive, comparison)))
            {
                throw new InvalidDataException("Select an archive from this operation's recorded recovery paths.");
            }

            var sha = LockerArchiveService.ComputeSha256(archive);
            var expectedSha = current.IsLocked ? current.LockedArchiveSha256 : null;
            if (operation.Kind == "Unlock" && before.RootElement.TryGetProperty("LockedArchiveSha256", out var recordedHash) && recordedHash.ValueKind == JsonValueKind.String)
            {
                expectedSha = recordedHash.GetString();
            }

            if (expectedSha != null && !sha.Equals(expectedSha, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Retained archive does not match the registered archive hash.");
            }

            var destinationParent = Path.GetDirectoryName(destination)!;
            Directory.CreateDirectory(destinationParent);
            var destinationParentIdentity = FileSystemPathIdentity.CaptureDirectory(destinationParent);
            var staging = Path.Join(destinationParent, $".cdl-recovery-{Guid.NewGuid():N}");
            var attempt = new LockerRecoveryAttempt(Guid.NewGuid().ToString("N"), operationId, current.Guid,
                archive, sha, destination, staging, "Restoring");
            LockerRepository.BeginRecoveryAttempt(attempt, current, connectionString);
            LockerOperationBoundary.Reached("Recovery.AttemptPrepared");
            var identity = new LockerModel(metadata.LockerName, string.Empty, destination)
            {
                Guid = metadata.LockerGuid,
                LockedAtUtc = metadata.LockedAtUtc
            };
            // The attempt is durable before plaintext creation. Never remove any original artifacts.
            (extractArchive ?? LockerArchiveService.ExtractToDirectory)(archive, staging, identity, password);
            DurableFileSystem.FlushDirectoryTree(staging);
            LockerOperationBoundary.Reached("Recovery.ExtractionDurable");
            if (LockerArchiveService.ComputeSha256(archive) != sha)
            {
                throw new InvalidDataException("Archive changed during recovery. Recorded staging was retained for inspection.");
            }

            var stagingIdentity = FileSystemIdentity.CaptureDirectory(staging);
            destinationParentIdentity.EnsureUnchanged();
            DurableFileSystem.MoveDirectory(staging, destination);
            if (FileSystemIdentity.CaptureDirectory(destination) != stagingIdentity)
            {
                throw new IOException("The published recovery directory does not match authenticated staging. Recovery records were preserved.");
            }

            FileSystemMetadataPolicy.NormalizePublishedTree(destination);

            LockerOperationBoundary.Reached("Recovery.PlaintextPublished");
            var restored = current.Copy();
            restored.LockerLocation = destination;
            restored.IsLocked = false;
            restored.StorageFormatVersion = null;
            restored.LockedArchiveSha256 = null;
            restored.LockedAtUtc = null;
            restored.Password = EncryptionHelper.HashPassword(password);
            LockerRepository.CommitRecoveredOperation(attempt, restored, connectionString);
            LockerOperationBoundary.Reached("Recovery.MetadataCommitted");
            return restored;
        }

        public static void RecoverArchive(string archivePath, string destinationDirectory, string password)
        {
            var destination = Path.GetFullPath(destinationDirectory);
            var pathError = LockerPathFilter.ValidatePath(destination);
            if (pathError != null)
            {
                throw new UnauthorizedAccessException(pathError);
            }

            if (Path.Exists(destination))
            {
                throw new IOException("Recovery requires a new destination directory. Existing data will not be overwritten.");
            }

            var metadata = LockerArchiveService.ReadMetadata(archivePath);
            var locker = new LockerModel(metadata.LockerName, string.Empty, destination)
            {
                Guid = metadata.LockerGuid,
                LockedAtUtc = metadata.LockedAtUtc
            };
            var parent = Path.GetDirectoryName(destination) ?? throw new IOException("Invalid recovery destination.");
            Directory.CreateDirectory(parent);
            var parentIdentity = FileSystemPathIdentity.CaptureDirectory(parent);
            var staging = Path.Join(parent, $".cdl-recovery-{Guid.NewGuid():N}");
            try
            {
                LockerArchiveService.ExtractToDirectory(archivePath, staging, locker, password);
                DurableFileSystem.FlushDirectoryTree(staging);
                var stagingIdentity = FileSystemIdentity.CaptureDirectory(staging);
                parentIdentity.EnsureUnchanged();
                DurableFileSystem.MoveDirectory(staging, destination);
                if (FileSystemIdentity.CaptureDirectory(destination) != stagingIdentity)
                {
                    throw new IOException("The published recovery directory does not match authenticated staging.");
                }

                FileSystemMetadataPolicy.NormalizePublishedTree(destination);
            }
            catch
            {
                LockerArchiveService.TryDeleteDirectory(staging);
                throw;
            }
        }
    }
}

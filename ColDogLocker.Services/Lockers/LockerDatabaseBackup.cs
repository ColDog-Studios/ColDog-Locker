using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using Microsoft.Data.Sqlite;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public static partial class LockerRepository
    {
        /// <summary>Restores a compatible snapshot only when the application's registry is absent.</summary>
        public static string RestoreDatabase(string backupPath) => RestoreDatabase(backupPath, _databasePath);

        internal static string RestoreDatabase(string backupPath, string databasePath)
        {
            var target = Path.GetFullPath(databasePath);
            var parent = Path.GetDirectoryName(target) ?? throw new IOException("Invalid registry path.");
            if (LockerPathFilter.FindLinkedAncestor(parent) is { } linkedParent)
            {
                throw new UnauthorizedAccessException($"Registry destination contains a link or reparse point: {linkedParent}");
            }

            EnsureRestoreDestinationAbsent(target);
            LockerArchiveService.CreatePrivateDirectory(parent);
            var staging = Path.Join(parent, $".cdl-db-restore-{Guid.NewGuid():N}");
            try
            {
                var backupOptions = new SqliteConnectionStringBuilder { DataSource = Path.GetFullPath(backupPath), Pooling = false };
                var copiedPath = CreateDatabaseSnapshot(staging, backupOptions.ToString(), appOwnedDestination: true);
                var copiedOptions = new SqliteConnectionStringBuilder { DataSource = copiedPath, Pooling = false };
                var connectionString = copiedOptions.ToString();
                var pending = GetPendingOperations(connectionString).Select(operation => operation.LockerGuid).ToHashSet(StringComparer.Ordinal);
                foreach (var locker in GetAllLockers(connectionString))
                {
                    var locationError = LockerPathFilter.ValidatePath(locker.LockerLocation);
                    if (locationError != null || LockerService.ValidateLockerName(locker.LockerName) != null)
                    {
                        throw new InvalidDataException($"Backup contains an unsafe locker location: {locker.LockerName}.");
                    }

                    // Interrupted operations intentionally retain possibly incomplete filesystem state.
                    // Their journals must survive restoration and continue blocking ordinary mutations.
                    if (pending.Contains(locker.Guid))
                    {
                        continue;
                    }

                    EnsureCurrent(locker, connectionString);
                    if (!Directory.Exists(locker.LockerLocation))
                    {
                        throw new InvalidDataException($"Locker location is missing: {locker.LockerName}. Recover its archive separately.");
                    }

                    if (locker.IsLocked)
                    {
                        var archivePath = LockerArchiveService.GetArchivePath(locker.LockerLocation);
                        var archive = new FileInfo(archivePath);
                        if (!archive.Exists || archive.LinkTarget != null || (archive.Attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            throw new InvalidDataException($"Archive is missing, a link or a reparse point: {locker.LockerName}.");
                        }

                        var verification = LockerArchiveService.VerifyArchive(archivePath, locker, locker.LockedArchiveSha256);
                        if (!verification.IsValid || verification.Metadata?.FormatVersion != locker.StorageFormatVersion ||
                            verification.Metadata?.LockedAtUtc != locker.LockedAtUtc)
                        {
                            throw new InvalidDataException($"Archive does not match the backup: {locker.LockerName}. Recover its archive separately.");
                        }
                    }
                    else if (locker.StorageFormatVersion != null || locker.LockedArchiveSha256 != null || locker.LockedAtUtc != null)
                    {
                        throw new InvalidDataException($"Inconsistent unlocked metadata: {locker.LockerName}.");
                    }
                }

                EnsureRestoreDestinationAbsent(target);
                DurableFileSystem.FlushDirectory(staging);
                DurableFileSystem.MoveFile(copiedPath, target);
                return target;
            }
            finally
            {
                LockerArchiveService.TryDeleteDirectory(staging);
            }
        }

        private static void EnsureRestoreDestinationAbsent(string path)
        {
            if (new[] { path, path + "-wal", path + "-shm", path + "-journal" }.Any(Path.Exists))
            {
                throw new IOException("Database restore requires an absent registry and no SQLite sidecar files. Existing state will not be replaced.");
            }
        }

        /// <summary>Creates a verified database snapshot in a new private directory. Does not copy locker contents.</summary>
        public static string BackupDatabase(string destinationDirectory) => BackupDatabase(destinationDirectory, _connectionString);

        internal static string BackupDatabase(string destinationDirectory, string connectionString)
            => CreateDatabaseSnapshot(destinationDirectory, connectionString, appOwnedDestination: false);

        private static string CreateDatabaseSnapshot(string destinationDirectory, string connectionString, bool appOwnedDestination)
        {
            var destination = Path.GetFullPath(destinationDirectory);
            var pathError = appOwnedDestination
                ? LockerPathFilter.FindLinkedAncestor(destination) is { } link ? $"Registry staging contains a link or reparse point: {link}" : null
                : LockerPathFilter.ValidatePath(destination);
            if (pathError != null)
            {
                throw new UnauthorizedAccessException(pathError);
            }

            if (Path.Exists(destination))
            {
                throw new IOException("Database backup requires a new destination directory. Existing files will not be overwritten.");
            }

            var parent = Path.GetDirectoryName(destination) ?? throw new IOException("Invalid backup destination.");
            if (!Directory.Exists(parent))
            {
                throw new DirectoryNotFoundException("Create the backup parent directory first.");
            }

            var sourceOptions = new SqliteConnectionStringBuilder(connectionString)
            {
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false
            };
            using var source = OpenConnection(sourceOptions.ToString());
            if (GetSchemaVersion(source) != CurrentSchemaVersion)
            {
                throw new InvalidDataException("Open this database with the compatible application version before backing it up.");
            }

            var staging = Path.Join(parent, $".cdl-db-backup-{Guid.NewGuid():N}");
            var stagedDatabase = Path.Join(staging, "lockers.db");
            try
            {
                LockerArchiveService.CreatePrivateDirectory(staging);
                var fileOptions = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                if (!OperatingSystem.IsWindows())
                {
                    fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                }

                using (new FileStream(stagedDatabase, fileOptions))
                { }

                var targetOptions = new SqliteConnectionStringBuilder { DataSource = stagedDatabase, Pooling = false };
                using (var target = OpenConnection(targetOptions.ToString()))
                {
                    source.BackupDatabase(target);
                    using var check = target.CreateCommand();
                    check.CommandText = "PRAGMA integrity_check";
                    using var reader = check.ExecuteReader();
                    if (!reader.Read() || reader.GetString(0) != "ok" || reader.Read())
                    {
                        throw new InvalidDataException("Database backup failed its integrity check.");
                    }
                }

                using (var durable = new FileStream(stagedDatabase, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    durable.Flush(flushToDisk: true);
                }

                DurableFileSystem.FlushDirectory(staging);
                DurableFileSystem.MoveDirectory(staging, destination);
                return Path.Join(destination, "lockers.db");
            }
            catch
            {
                LockerArchiveService.TryDeleteDirectory(staging);
                throw;
            }
        }
    }
}

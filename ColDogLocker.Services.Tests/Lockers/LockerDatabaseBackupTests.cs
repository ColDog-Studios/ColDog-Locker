using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;
using Microsoft.Data.Sqlite;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public sealed class LockerDatabaseBackupTests : IDisposable
    {
        private readonly string _root = Directory.CreateDirectory(Path.Join(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), $"cdl-backup-tests-{Guid.NewGuid():N}")).FullName;

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RestoreRejectsMissingLocationOrFutureSchema(bool futureSchema)
        {
            var source = Connection(Path.Join(_root, "source.db"));
            LockerRepository.InitializeDatabase(source);
            var location = Path.Join(_root, "missing");
            LockerRepository.InsertLocker(new LockerModel("Missing", "verifier", location), source);
            var backup = LockerRepository.BackupDatabase(Path.Join(_root, "backup"), source);
            if (futureSchema)
            {
                using var connection = new SqliteConnection(Connection(backup));
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = $"PRAGMA user_version = {LockerRepository.CurrentSchemaVersion + 1}";
                command.ExecuteNonQuery();
            }

            var hash = LockerArchiveService.ComputeSha256(backup);
            var target = Path.Join(_root, "fresh-profile", "lockers.db");
            Assert.Throws<InvalidDataException>(() => LockerRepository.RestoreDatabase(backup, target));
            Assert.False(File.Exists(target));
            Assert.Equal(hash, LockerArchiveService.ComputeSha256(backup));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RestorePreservesRegistrationAndPendingRecovery(bool interrupted)
        {
            var source = Connection(Path.Join(_root, "source.db"));
            LockerRepository.InitializeDatabase(source);
            var location = Path.Join(_root, "Vault");
            if (!interrupted)
            {
                Directory.CreateDirectory(location);
                File.WriteAllText(Path.Join(location, "original"), "unchanged");
            }

            var locker = new LockerModel("Vault", "verifier", location);
            LockerRepository.InsertLocker(locker, source);
            if (interrupted)
            {
                var journal = new LockerOperationJournal(source);
                journal.Begin(locker, "Lock", Path.Join(_root, ".Vault"), Path.Join(_root, "staging"));
                journal.Advance("ArchiveReady");
                journal.Advance("SourceRemovalStarted");
            }

            var backup = LockerRepository.BackupDatabase(Path.Join(_root, "backup"), source);
            var hash = LockerArchiveService.ComputeSha256(backup);
            var target = Path.Join(_root, "fresh-profile", "lockers.db");
            Assert.Equal(target, LockerRepository.RestoreDatabase(backup, target));
            var restored = LockerRepository.GetLockerByGuid(locker.Guid, Connection(target))!;
            Assert.Equal(locker.LockerLocation, restored.LockerLocation);
            Assert.Equal(locker.Password, restored.Password);
            Assert.Equal(hash, LockerArchiveService.ComputeSha256(backup));
            if (interrupted)
            {
                Assert.Equal("SourceRemovalStarted", Assert.Single(LockerRepository.GetPendingOperations(Connection(target))).Phase);
                Assert.Throws<InvalidOperationException>(() => LockerRepository.EnsureCurrent(restored, Connection(target)));
            }
            else
            {
                Assert.Equal("unchanged", File.ReadAllText(Path.Join(location, "original")));
                LockerRepository.EnsureCurrent(restored, Connection(target));
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RestoreRequiresLockedArchiveToMatchBackup(bool tamper)
        {
            var source = Connection(Path.Join(_root, "source.db"));
            LockerRepository.InitializeDatabase(source);
            var location = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            File.WriteAllText(Path.Join(location, "original"), "unchanged");
            const string Password = "Violet!River9Moon";
            var locker = new LockerModel("Vault", ColDogStudios.ColDogLocker.Services.Security.EncryptionHelper.HashPassword(Password), location);
            LockerRepository.InsertLocker(locker, source);
            LockerService.Lock(locker, Password, value => LockerRepository.UpdateLocker(value, source), path => Directory.Delete(path, true));
            var backup = LockerRepository.BackupDatabase(Path.Join(_root, "backup"), source);
            var archive = LockerArchiveService.GetArchivePath(locker.LockerLocation);
            if (tamper)
            {
                File.SetAttributes(archive, FileAttributes.Normal);
                using var append = new FileStream(archive, FileMode.Append);
                append.WriteByte(42);
            }

            var hash = LockerArchiveService.ComputeSha256(archive);
            var target = Path.Join(_root, "fresh-profile", "lockers.db");
            if (tamper)
            {
                Assert.Throws<InvalidDataException>(() => LockerRepository.RestoreDatabase(backup, target));
                Assert.False(File.Exists(target));
            }
            else
            {
                LockerRepository.RestoreDatabase(backup, target);
                Assert.True(LockerRepository.GetLockerByGuid(locker.Guid, Connection(target))!.IsLocked);
            }

            Assert.Equal(hash, LockerArchiveService.ComputeSha256(archive));
        }

        [Theory]
        [InlineData("")]
        [InlineData("-wal")]
        [InlineData("-shm")]
        [InlineData("-journal")]
        public void RestoreNeverReplacesRegistryOrSidecars(string suffix)
        {
            var target = Path.Join(_root, "lockers.db");
            File.WriteAllText(target + suffix, "existing state");
            Assert.Throws<IOException>(() => LockerRepository.RestoreDatabase(Path.Join(_root, "missing-backup.db"), target));
            Assert.Equal("existing state", File.ReadAllText(target + suffix));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void BackupIncludesCommittedRowsAndPendingRecoveryRecords(bool useWal)
        {
            var source = Connection(Path.Join(_root, "source.db"));
            LockerRepository.InitializeDatabase(source);
            using var writer = new SqliteConnection(source);
            writer.Open();
            if (useWal)
            {
                using var wal = writer.CreateCommand();
                wal.CommandText = "PRAGMA journal_mode=WAL";
                Assert.Equal("wal", wal.ExecuteScalar());
                wal.CommandText = "PRAGMA wal_autocheckpoint=0";
                wal.ExecuteNonQuery();
            }

            var locker = new LockerModel("Vault", "password verifier", Path.Join(_root, "Vault"));
            LockerRepository.InsertLocker(locker, source);
            var journal = new LockerOperationJournal(source);
            journal.Begin(locker, "Lock", Path.Join(_root, ".Vault"), Path.Join(_root, "staging"));
            var pending = Assert.Single(LockerRepository.GetPendingOperations(source));
            if (useWal)
            {
                writer.CreateCollation("CDL_NAME", (left, right) => StringComparer.OrdinalIgnoreCase.Compare(left, right));
                using var update = writer.CreateCommand();
                update.CommandText = "UPDATE Lockers SET Password = 'committed WAL verifier'";
                update.ExecuteNonQuery();
                locker.Password = "committed WAL verifier";
                Assert.True(new FileInfo(Path.Join(_root, "source.db-wal")).Length > 32);
            }

            var result = LockerRepository.BackupDatabase(Path.Join(_root, "backup"), source);
            var backup = Connection(result);
            var restored = LockerRepository.GetLockerByGuid(locker.Guid, backup)!;
            Assert.Equal(locker.Password, restored.Password);
            Assert.Equal(locker.Revision, restored.Revision);
            Assert.Equal(pending, Assert.Single(LockerRepository.GetPendingOperations(backup)));
            Assert.Equal(pending, Assert.Single(LockerRepository.GetPendingOperations(source)));
            Assert.Single(Directory.GetFiles(Path.GetDirectoryName(result)!));
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(result));
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                    File.GetUnixFileMode(Path.GetDirectoryName(result)!));
            }

            var subsequent = new LockerModel("Later", "another verifier", Path.Join(_root, "Later"));
            LockerRepository.InsertLocker(subsequent, source);
            Assert.Null(LockerRepository.GetLockerByGuid(subsequent.Guid, backup));
        }

        [Fact]
        public void ExistingDestinationAndSourceAreNotOverwritten()
        {
            var source = Connection(Path.Join(_root, "source.db"));
            LockerRepository.InitializeDatabase(source);
            var existing = Directory.CreateDirectory(Path.Join(_root, "existing")).FullName;
            File.WriteAllText(Path.Join(existing, "keep"), "original");
            Assert.Throws<IOException>(() => LockerRepository.BackupDatabase(existing, source));
            Assert.Equal("original", File.ReadAllText(Path.Join(existing, "keep")));
            Assert.Throws<IOException>(() => LockerRepository.BackupDatabase(_root, source));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void MissingOrCorruptSourceDoesNotProduceBackup(bool corrupt)
        {
            var sourcePath = Path.Join(_root, "source.db");
            if (corrupt)
            {
                File.WriteAllText(sourcePath, "not a database");
            }

            var target = Path.Join(_root, "backup");
            Assert.Throws<SqliteException>(() => LockerRepository.BackupDatabase(target, Connection(sourcePath)));
            Assert.False(Directory.Exists(target));
            Assert.Empty(Directory.GetDirectories(_root));
            Assert.Equal(corrupt, File.Exists(sourcePath));
        }

        private static string Connection(string path) => new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString();

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            foreach (var file in Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(file, FileAttributes.Normal);
            }

            foreach (var directory in Directory.EnumerateDirectories(_root, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(directory, FileAttributes.Normal);
            }

            Directory.Delete(_root, true);
        }
    }
}

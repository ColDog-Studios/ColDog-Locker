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

using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Tests.FileSystem;
using Microsoft.Data.Sqlite;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public class LockerRepositoryTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Registration_CannotClaimActiveOperationOrRecoveryStaging(bool recovery)
        {
            using var database = TestDatabase.CreateInitialized();
            var root = Path.GetDirectoryName(database.Path)!;
            var owner = CreateLocker("Owner");
            owner.LockerLocation = Path.Join(root, "Owner");
            LockerRepository.InsertLocker(owner, database.ConnectionString);
            var staging = Path.Join(root, ".operation-staging");
            new LockerOperationJournal(database.ConnectionString).Begin(owner, "Lock", Path.Join(root, ".Owner"), staging);
            var operation = Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString));
            if (recovery)
            {
                staging = Path.Join(root, "recovery", "Owner");
                var attempt = new LockerRecoveryAttempt(Guid.NewGuid().ToString(), operation.OperationId, owner.Guid,
                    Path.Join(root, "archive.cdl"), "hash", staging, Path.Join(root, ".recovery-staging"), "Restoring");
                LockerRepository.BeginRecoveryAttempt(attempt, owner, database.ConnectionString);
            }

            var contender = CreateLocker("Other");
            contender.LockerLocation = Path.Join(staging, "child");
            Assert.Throws<InvalidOperationException>(() => LockerRepository.InsertLocker(contender, database.ConnectionString));
            Assert.Single(LockerRepository.GetAllLockers(database.ConnectionString));
        }

        [Fact]
        public void CancelPreparation_RejectsAnOperationOwnedByAnotherThread()
        {
            using var database = TestDatabase.CreateInitialized();
            var parent = Path.GetDirectoryName(database.Path)!;
            var locker = CreateLocker("Owned");
            locker.LockerLocation = Directory.CreateDirectory(Path.Join(parent, "source")).FullName;
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            var journal = new LockerOperationJournal(database.ConnectionString);
            journal.Begin(locker, "Lock", Path.Join(parent, "target"), Path.Join(parent, "stage"));
            var operation = Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString));
            using var lease = LockerOperationLease.Acquire(locker.Guid);
            Exception? error = null;
            var contender = new Thread(() => error = Record.Exception(() => LockerRepository.CancelPreparedOperation(operation.OperationId, database.ConnectionString)));
            contender.Start();
            Assert.True(contender.Join(TimeSpan.FromSeconds(10)));
            Assert.IsType<InvalidOperationException>(error);
            Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString));
            Assert.Empty(LockerRepository.GetOperationHistory(database.ConnectionString));
        }

        [Theory]
        [InlineData("source-missing")]
        [InlineData("target-exists")]
        [InlineData("metadata-changed")]
        public void CancelPreparation_RejectsAmbiguousState(string change)
        {
            using var database = TestDatabase.CreateInitialized();
            var parent = Path.GetDirectoryName(database.Path)!;
            var source = Directory.CreateDirectory(Path.Join(parent, "source")).FullName;
            var target = Path.Join(parent, "target");
            var locker = CreateLocker("Journal");
            locker.LockerLocation = source;
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            new LockerOperationJournal(database.ConnectionString).Begin(locker, "Lock", target, Path.Join(parent, "stage"));
            var operation = Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString));
            if (change == "source-missing")
            {
                Directory.Delete(source);
            }
            else if (change == "target-exists")
            {
                Directory.CreateDirectory(target);
            }
            else
            {
                using var connection = new SqliteConnection(database.ConnectionString);
                connection.Open();
                connection.CreateCollation("CDL_NAME", (left, right) => StringComparer.OrdinalIgnoreCase.Compare(left, right));
                using var command = connection.CreateCommand();
                command.CommandText = "UPDATE Lockers SET Revision = Revision + 1";
                command.ExecuteNonQuery();
            }

            Assert.Throws<InvalidOperationException>(() => LockerRepository.CancelPreparedOperation(operation.OperationId, database.ConnectionString));
            Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString));
            Assert.Empty(LockerRepository.GetOperationHistory(database.ConnectionString));
        }

        [Theory]
        [InlineData("Lock", "Preparing")]
        [InlineData("Lock", "ArchiveReady")]
        [InlineData("Unlock", "Preparing")]
        public void CancelPreparation_RetainsFilesAndArchivesRecoveryPaths(string kind, string phase)
        {
            using var database = TestDatabase.CreateInitialized();
            var parent = Path.GetDirectoryName(database.Path)!;
            var source = Directory.CreateDirectory(Path.Join(parent, "source")).FullName;
            var staging = Directory.CreateDirectory(Path.Join(parent, "staging")).FullName;
            File.WriteAllText(Path.Join(source, "original.txt"), "original");
            File.WriteAllText(Path.Join(staging, "retained.txt"), "retained");
            var locker = CreateLocker("Journal", kind == "Unlock");
            locker.LockerLocation = source;
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            var journal = new LockerOperationJournal(database.ConnectionString);
            journal.Begin(locker, kind, Path.Join(parent, "target"), staging);
            if (phase != "Preparing")
            {
                journal.Advance(phase);
            }

            var pending = Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString));
            LockerRepository.CancelPreparedOperation(pending.OperationId, database.ConnectionString);
            Assert.Empty(LockerRepository.GetPendingOperations(database.ConnectionString));
            var history = Assert.Single(LockerRepository.GetOperationHistory(database.ConnectionString));
            Assert.Equal(pending, history);
            Assert.Equal("original", File.ReadAllText(Path.Join(source, "original.txt")));
            Assert.Equal("retained", File.ReadAllText(Path.Join(staging, "retained.txt")));
            LockerRepository.EnsureCurrent(locker, database.ConnectionString);
        }

        [Theory]
        [InlineData("SourceRemovalStarted")]
        [InlineData("Published")]
        [InlineData("MetadataCommitted")]
        public void CancelPreparation_RejectsPotentiallyDestructivePhases(string phase)
        {
            using var database = TestDatabase.CreateInitialized();
            var parent = Path.GetDirectoryName(database.Path)!;
            var source = Directory.CreateDirectory(Path.Join(parent, "source")).FullName;
            var locker = CreateLocker("Journal");
            locker.LockerLocation = source;
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            var journal = new LockerOperationJournal(database.ConnectionString);
            journal.Begin(locker, "Lock", Path.Join(parent, "target"), Path.Join(parent, "staging"));
            journal.Advance(phase);
            var pending = Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString));

            Assert.Throws<InvalidOperationException>(() => LockerRepository.CancelPreparedOperation(pending.OperationId, database.ConnectionString));
            Assert.Equal(pending, Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString)));
            Assert.Empty(LockerRepository.GetOperationHistory(database.ConnectionString));
        }

        [Fact]
        public void Journal_SurvivesReinitializationAndBlocksRetry()
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker("Journal");
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            var journal = new LockerOperationJournal(database.ConnectionString);
            journal.Begin(locker, "Lock", "/tmp/.Journal", "/tmp/.Journal.staging");
            journal.Advance("ArchiveReady");
            journal.Advance("SourceRemovalStarted");

            LockerRepository.InitializeDatabase(database.ConnectionString);
            var pending = Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString));
            Assert.Equal("SourceRemovalStarted", pending.Phase);
            Assert.Equal(locker.LockerLocation, pending.SourcePath);
            Assert.Equal("/tmp/.Journal.staging", pending.StagingPath);
            Assert.Contains(locker.Guid, pending.BeforeJson);
            Assert.Throws<InvalidOperationException>(() => LockerRepository.EnsureCurrent(locker, database.ConnectionString));
            Assert.Throws<InvalidOperationException>(() => LockerRepository.UpdateLocker(locker, database.ConnectionString));
            Assert.Throws<InvalidOperationException>(() => new LockerOperationJournal(database.ConnectionString).Begin(locker, "Lock", "/other", "/stage"));
        }

        [Fact]
        public void CommitOperation_UpdatesMetadataAndJournalTogether()
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker("Journal");
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            var journal = new LockerOperationJournal(database.ConnectionString);
            journal.Begin(locker, "Lock", "/tmp/.Journal", "/tmp/.Journal.staging");
            journal.Advance("ArchiveReady");
            journal.Advance("SourceRemovalStarted");
            journal.Advance("Published");
            locker.IsLocked = true;
            locker.LockerLocation = "/tmp/.Journal";
            LockerRepository.UpdateLocker(locker, database.ConnectionString, commitOperation: true);

            Assert.True(LockerRepository.GetLockerByGuid(locker.Guid, database.ConnectionString)!.IsLocked);
            Assert.Equal(1, locker.Revision);
            Assert.Equal("MetadataCommitted", Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString)).Phase);
            journal.End();
            Assert.Empty(LockerRepository.GetPendingOperations(database.ConnectionString));
            LockerRepository.EnsureCurrent(locker, database.ConnectionString);
        }

        [Fact]
        public void CommitOperation_MissingPublicationRollsBackMetadataWrite()
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker("Journal");
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            var journal = new LockerOperationJournal(database.ConnectionString);
            journal.Begin(locker, "Lock", "/tmp/.Journal", "/tmp/.Journal.staging");
            locker.IsLocked = true;
            Assert.Throws<InvalidOperationException>(() => LockerRepository.UpdateLocker(locker, database.ConnectionString, commitOperation: true));
            Assert.False(LockerRepository.GetLockerByGuid(locker.Guid, database.ConnectionString)!.IsLocked);
            Assert.Equal(0, locker.Revision);
            Assert.Equal("Preparing", Assert.Single(LockerRepository.GetPendingOperations(database.ConnectionString)).Phase);
        }

        [Fact]
        public void EnsureCurrent_RejectsOverlapsInheritedFromOlderDatabase()
        {
            using var database = TestDatabase.CreateInitialized();
            var parent = CreateLocker("Parent");
            LockerRepository.InsertLocker(parent, database.ConnectionString);
            using (var connection = new SqliteConnection(database.ConnectionString))
            {
                connection.Open();
                connection.CreateCollation("CDL_NAME", (left, right) => StringComparer.OrdinalIgnoreCase.Compare(left, right));
                using var command = connection.CreateCommand();
                command.CommandText = "INSERT INTO Lockers (Guid, LockerName, Password, LockerLocation) VALUES ('legacy-child', 'Child', 'hash', $path)";
                command.Parameters.AddWithValue("$path", Path.Join(parent.LockerLocation, "Child"));
                command.ExecuteNonQuery();
            }

            Assert.Throws<InvalidOperationException>(() => LockerRepository.EnsureCurrent(parent, database.ConnectionString));
            Assert.Equal(2, LockerRepository.GetAllLockers(database.ConnectionString).Count);
        }

        [Fact]
        public void DeleteLocker_StaleRevisionDoesNotRemoveCurrentRecord()
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker("Retained");
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            LockerRepository.UpdateLocker(locker, database.ConnectionString);
            Assert.Throws<InvalidOperationException>(() => LockerRepository.DeleteLocker(locker.Guid, database.ConnectionString, 0));
            Assert.Equal(1, LockerRepository.GetLockerByGuid(locker.Guid, database.ConnectionString)!.Revision);
            LockerRepository.DeleteLocker(locker.Guid, database.ConnectionString, 1);
            Assert.Null(LockerRepository.GetLockerByGuid(locker.Guid, database.ConnectionString));
        }

        [Fact]
        public void EnsureCurrent_RejectsChangedFieldsEvenWhenRevisionMatches()
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker("Retained");
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            LockerRepository.EnsureCurrent(locker, database.ConnectionString);
            var altered = locker.Copy();
            altered.LockerLocation += "-other";
            Assert.Throws<InvalidOperationException>(() => LockerRepository.EnsureCurrent(altered, database.ConnectionString));
        }

        [Fact]
        public void UpdateLocker_StaleSnapshotCannotOverwriteCommittedState()
        {
            using var database = TestDatabase.CreateInitialized();
            var original = CreateLocker("Original");
            LockerRepository.InsertLocker(original, database.ConnectionString);
            var stale = LockerRepository.GetLockerByGuid(original.Guid, database.ConnectionString)!;
            original.Password = "new verifier";
            LockerRepository.UpdateLocker(original, database.ConnectionString);
            Assert.Equal(1, original.Revision);
            stale.Password = "stale verifier";

            Assert.Throws<InvalidOperationException>(() => LockerRepository.UpdateLocker(stale, database.ConnectionString));
            var persisted = LockerRepository.GetLockerByGuid(original.Guid, database.ConnectionString)!;
            Assert.Equal("new verifier", persisted.Password);
            Assert.Equal(1, persisted.Revision);
            Assert.Equal(0, stale.Revision);
        }

        [Theory]
        [InlineData("Vault", "Vault")]
        [InlineData("Vault", "Vault/Child")]
        [InlineData("Vault/Child", "Vault")]
        [InlineData("Vault", ".Vault/Child")]
        [InlineData("Vault", "Other/../Vault")]
        public void InsertLocker_RejectsOverlappingLocations(string firstPath, string secondPath)
        {
            using var database = TestDatabase.CreateInitialized();
            var root = Path.GetDirectoryName(database.Path)!;
            var first = CreateLocker("Vault");
            first.LockerLocation = Path.Join(root, firstPath);
            LockerRepository.InsertLocker(first, database.ConnectionString);
            var second = CreateLocker("Second");
            second.LockerLocation = Path.Join(root, secondPath);

            Assert.Throws<InvalidOperationException>(() => LockerRepository.InsertLocker(second, database.ConnectionString));
            Assert.Single(LockerRepository.GetAllLockers(database.ConnectionString));
        }

        [Fact]
        public void UpdateLocker_OverlapFailurePreservesPersistedLocation()
        {
            using var database = TestDatabase.CreateInitialized();
            var root = Path.GetDirectoryName(database.Path)!;
            var first = CreateLocker("First");
            first.LockerLocation = Path.Join(root, "First");
            var second = CreateLocker("Second");
            second.LockerLocation = Path.Join(root, "Second");
            LockerRepository.InsertLocker(first, database.ConnectionString);
            LockerRepository.InsertLocker(second, database.ConnectionString);
            var previous = second.LockerLocation;
            second.LockerLocation = Path.Join(first.LockerLocation, "Child");

            Assert.Throws<InvalidOperationException>(() => LockerRepository.UpdateLocker(second, database.ConnectionString));
            Assert.Equal(previous, LockerRepository.GetLockerByGuid(second.Guid, database.ConnectionString)!.LockerLocation);
        }

        [Fact]
        public void InsertLocker_AllowsSiblingWithCommonPrefix()
        {
            using var database = TestDatabase.CreateInitialized();
            LockerRepository.InsertLocker(CreateLocker("Vault"), database.ConnectionString);
            LockerRepository.InsertLocker(CreateLocker("VaultTwo"), database.ConnectionString);
            Assert.Equal(2, LockerRepository.GetAllLockers(database.ConnectionString).Count);
        }

        [UnixFact]
        public void InsertLocker_RejectsSymlinkAliasOfRegisteredDirectory()
        {
            using var database = TestDatabase.CreateInitialized();
            var root = Path.GetDirectoryName(database.Path)!;
            var owned = Directory.CreateDirectory(Path.Join(root, "Owned")).FullName;
            var alias = Path.Join(root, "Alias");
            Directory.CreateSymbolicLink(alias, owned);
            var first = CreateLocker("First");
            first.LockerLocation = owned;
            LockerRepository.InsertLocker(first, database.ConnectionString);
            var second = CreateLocker("Second");
            second.LockerLocation = alias;

            Assert.Throws<InvalidDataException>(() => LockerRepository.InsertLocker(second, database.ConnectionString));
            Assert.Single(LockerRepository.GetAllLockers(database.ConnectionString));
        }

        [Fact]
        public void InsertLocker_LinuxCaseDistinctDirectoriesRemainDistinct()
        {
            if (!OperatingSystem.IsLinux())
            {
                return;
            }

            using var database = TestDatabase.CreateInitialized();
            var root = Path.GetDirectoryName(database.Path)!;
            var upperPath = Directory.CreateDirectory(Path.Join(root, "Vault")).FullName;
            var lowerPath = Directory.CreateDirectory(Path.Join(root, "vault")).FullName;
            var upper = CreateLocker("Upper");
            upper.LockerLocation = upperPath;
            var lower = CreateLocker("Lower");
            lower.LockerLocation = lowerPath;

            LockerRepository.InsertLocker(upper, database.ConnectionString);
            LockerRepository.InsertLocker(lower, database.ConnectionString);

            Assert.Equal(2, LockerRepository.GetAllLockers(database.ConnectionString).Count);
        }

        [Fact]
        public async Task ConcurrentInsert_OnlyOneOverlappingRegistrationCommits()
        {
            using var database = TestDatabase.CreateInitialized();
            var first = CreateLocker("First");
            var second = CreateLocker("Second");
            first.LockerLocation = second.LockerLocation = Path.Join(Path.GetDirectoryName(database.Path)!, "Shared");
            using var ready = new Barrier(2);
            Task<Exception?> Insert(LockerModel locker) => Task.Run<Exception?>(() =>
            {
                Assert.True(ready.SignalAndWait(TimeSpan.FromSeconds(10)));
                return Record.Exception(() => LockerRepository.InsertLocker(locker, database.ConnectionString));
            });

            var results = await Task.WhenAll(Insert(first), Insert(second));
            Assert.Single(results, result => result == null);
            Assert.Single(results, result => result is InvalidOperationException);
            Assert.Single(LockerRepository.GetAllLockers(database.ConnectionString));
        }

        [Theory]
        [InlineData("Vault", "vault")]
        [InlineData("Äpfel", "äpfel")]
        public void NameUniquenessMatchesCaseInsensitiveLookup(string first, string second)
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker(first);
            LockerRepository.InsertLocker(locker, database.ConnectionString);
            Assert.Equal(locker.Guid, LockerRepository.GetLockerByName(second, database.ConnectionString)!.Guid);
            Assert.Throws<InvalidOperationException>(() =>
                LockerRepository.InsertLocker(CreateLocker(second), database.ConnectionString));
            Assert.Single(LockerRepository.GetAllLockers(database.ConnectionString));
        }

        [Fact]
        public void Migration_DuplicateCaseNamesFailsWithoutDeletingEitherLocker()
        {
            using var database = TestDatabase.Create();
            using (var connection = new SqliteConnection(database.ConnectionString))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE Lockers (Guid TEXT PRIMARY KEY, LockerName TEXT NOT NULL UNIQUE,
                        Password TEXT NOT NULL, LockerLocation TEXT NOT NULL, IsLocked INTEGER NOT NULL DEFAULT 0);
                    INSERT INTO Lockers VALUES ('one', 'Vault', 'hash', '/one', 0);
                    INSERT INTO Lockers VALUES ('two', 'vault', 'hash', '/two', 0);
                    """;
                command.ExecuteNonQuery();
            }

            Assert.Throws<InvalidOperationException>(() => LockerRepository.InitializeDatabase(database.ConnectionString));
            using var inspection = new SqliteConnection(database.ConnectionString);
            inspection.Open();
            using var count = inspection.CreateCommand();
            count.CommandText = "SELECT COUNT(*) FROM Lockers";
            Assert.Equal(2L, count.ExecuteScalar());
            Assert.Equal(1, GetSchemaVersion(database.ConnectionString));
        }

        [Fact]
        public void InitializeDatabase_ShouldCreateEmptyLockerTable()
        {
            using var database = TestDatabase.Create();

            LockerRepository.InitializeDatabase(database.ConnectionString);

            Assert.True(File.Exists(database.Path));
            Assert.Empty(LockerRepository.GetAllLockers(database.ConnectionString));
            Assert.Equal(LockerRepository.CurrentSchemaVersion, GetSchemaVersion(database.ConnectionString));
        }

        [Fact]
        public void InsertAndReadMethods_ShouldPersistLockerData()
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker("Beta", true);

            LockerRepository.InsertLocker(locker, database.ConnectionString);

            var byGuid = LockerRepository.GetLockerByGuid(locker.Guid, database.ConnectionString);
            var byName = LockerRepository.GetLockerByName("beta", database.ConnectionString);

            Assert.NotNull(byGuid);
            Assert.Equal(locker.Guid, byGuid.Guid);
            Assert.Equal("Beta", byGuid.LockerName);
            Assert.Equal("hashed-password", byGuid.Password);
            Assert.Equal("/tmp/Beta", byGuid.LockerLocation);
            Assert.True(byGuid.IsLocked);
            Assert.Equal(LockerArchiveService.CurrentStorageFormatVersion, byGuid.StorageFormatVersion);
            Assert.Equal("abc123", byGuid.LockedArchiveSha256);
            Assert.NotNull(byGuid.LockedAtUtc);
            Assert.NotNull(byName);
            Assert.Equal(locker.Guid, byName.Guid);
            Assert.True(LockerRepository.LockerExists("BETA", database.ConnectionString));
            Assert.False(LockerRepository.LockerExists("Missing", database.ConnectionString));
        }

        [Fact]
        public void GetAllLockers_ShouldReturnLockersOrderedByName()
        {
            using var database = TestDatabase.CreateInitialized();
            LockerRepository.InsertLocker(CreateLocker("Zulu"), database.ConnectionString);
            LockerRepository.InsertLocker(CreateLocker("Alpha"), database.ConnectionString);

            var lockers = LockerRepository.GetAllLockers(database.ConnectionString);

            Assert.Collection(lockers,
                locker => Assert.Equal("Alpha", locker.LockerName),
                locker => Assert.Equal("Zulu", locker.LockerName));
        }

        [Fact]
        public void InsertLocker_DuplicateName_ShouldThrowInvalidOperationException()
        {
            using var database = TestDatabase.CreateInitialized();
            LockerRepository.InsertLocker(CreateLocker("Duplicate"), database.ConnectionString);

            var exception = Assert.Throws<InvalidOperationException>(() =>
                LockerRepository.InsertLocker(CreateLocker("Duplicate"), database.ConnectionString));

            Assert.Contains("already exists", exception.Message);
        }

        [Fact]
        public void UpdateLocker_ShouldPersistChanges()
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker("Original");
            LockerRepository.InsertLocker(locker, database.ConnectionString);

            locker.LockerName = "Updated";
            locker.Password = "new-hash";
            locker.LockerLocation = "/tmp/Updated";
            locker.IsLocked = true;
            locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
            locker.LockedArchiveSha256 = "def456";
            locker.LockedAtUtc = DateTime.UtcNow;
            LockerRepository.UpdateLocker(locker, database.ConnectionString);

            var updated = LockerRepository.GetLockerByGuid(locker.Guid, database.ConnectionString);

            Assert.NotNull(updated);
            Assert.Equal("Updated", updated.LockerName);
            Assert.Equal("new-hash", updated.Password);
            Assert.Equal("/tmp/Updated", updated.LockerLocation);
            Assert.True(updated.IsLocked);
            Assert.Equal(LockerArchiveService.CurrentStorageFormatVersion, updated.StorageFormatVersion);
            Assert.Equal("def456", updated.LockedArchiveSha256);
            Assert.NotNull(updated.LockedAtUtc);
        }

        [Fact]
        public void InitializeDatabase_ShouldMigrateArchiveMetadataColumns()
        {
            using var database = TestDatabase.Create();
            using (var connection = new SqliteConnection(database.ConnectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    CREATE TABLE Lockers (
                        Guid TEXT PRIMARY KEY,
                        LockerName TEXT NOT NULL UNIQUE,
                        Password TEXT NOT NULL,
                        LockerLocation TEXT NOT NULL,
                        IsLocked INTEGER NOT NULL DEFAULT 0,
                        CreatedAt TEXT NOT NULL DEFAULT (datetime('now')),
                        UpdatedAt TEXT NOT NULL DEFAULT (datetime('now'))
                    )";
                command.ExecuteNonQuery();
            }

            LockerRepository.InitializeDatabase(database.ConnectionString);

            using var migratedConnection = new SqliteConnection(database.ConnectionString);
            migratedConnection.Open();
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var migratedCommand = migratedConnection.CreateCommand();
            migratedCommand.CommandText = "PRAGMA table_info(Lockers)";
            using var reader = migratedCommand.ExecuteReader();
            while (reader.Read())
            {
                columns.Add(reader.GetString(1));
            }

            Assert.Contains("StorageFormatVersion", columns);
            Assert.Contains("LockedArchiveSha256", columns);
            Assert.Contains("LockedAtUtc", columns);
            Assert.Equal(LockerRepository.CurrentSchemaVersion, GetSchemaVersion(database.ConnectionString));
        }

        [Fact]
        public void InitializeDatabase_WithNewerSchemaVersion_ShouldThrowInvalidOperationException()
        {
            using var database = TestDatabase.Create();
            using (var connection = new SqliteConnection(database.ConnectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = $"PRAGMA user_version = {LockerRepository.CurrentSchemaVersion + 1}";
                command.ExecuteNonQuery();
            }

            var exception = Assert.Throws<InvalidOperationException>(() =>
                LockerRepository.InitializeDatabase(database.ConnectionString));

            Assert.Contains("newer than this application supports", exception.Message);
        }

        [Fact]
        public void UpdateLocker_MissingGuid_ShouldThrowInvalidOperationException()
        {
            using var database = TestDatabase.CreateInitialized();

            var exception = Assert.Throws<InvalidOperationException>(() =>
                LockerRepository.UpdateLocker(CreateLocker("Missing"), database.ConnectionString));

            Assert.Contains("not found", exception.Message);
        }

        [Fact]
        public void DeleteLocker_ShouldRemoveExistingLocker()
        {
            using var database = TestDatabase.CreateInitialized();
            var locker = CreateLocker("DeleteMe");
            LockerRepository.InsertLocker(locker, database.ConnectionString);

            LockerRepository.DeleteLocker(locker.Guid, database.ConnectionString);

            Assert.Null(LockerRepository.GetLockerByGuid(locker.Guid, database.ConnectionString));
            Assert.False(LockerRepository.LockerExists("DeleteMe", database.ConnectionString));
        }

        [Fact]
        public void DeleteLocker_MissingGuid_ShouldThrowInvalidOperationException()
        {
            using var database = TestDatabase.CreateInitialized();

            var exception = Assert.Throws<InvalidOperationException>(() =>
                LockerRepository.DeleteLocker(Guid.NewGuid().ToString(), database.ConnectionString));

            Assert.Contains("not found", exception.Message);
        }

        [Fact]
        public void GetDatabaseInfo_ShouldReturnFileStatsAndIntegrity()
        {
            using var database = TestDatabase.CreateInitialized();
            LockerRepository.InsertLocker(CreateLocker("Info"), database.ConnectionString);

            var info = LockerRepository.GetDatabaseInfo(database.Path, database.ConnectionString);

            Assert.Equal(database.Path, info.Path);
            Assert.True(info.Exists);
            Assert.True(info.SizeBytes > 0);
            Assert.Equal(1, info.LockerCount);
            Assert.NotEmpty(info.SqliteVersion);
            Assert.True(info.IntegrityOk);
        }

        [Fact]
        public void GetDatabaseInfo_MissingDatabase_ShouldReturnNonExistingInfo()
        {
            using var database = TestDatabase.Create();

            var info = LockerRepository.GetDatabaseInfo(database.Path, database.ConnectionString);

            Assert.Equal(database.Path, info.Path);
            Assert.False(info.Exists);
            Assert.Equal(0, info.SizeBytes);
            Assert.Equal(0, info.LockerCount);
            Assert.Equal(string.Empty, info.SqliteVersion);
            Assert.False(info.IntegrityOk);
        }

        [Fact]
        public void VacuumDatabase_ShouldReturnReclaimedByteCount()
        {
            using var database = TestDatabase.CreateInitialized();
            LockerRepository.InsertLocker(CreateLocker("Vacuum"), database.ConnectionString);

            var reclaimed = LockerRepository.VacuumDatabase(database.Path, database.ConnectionString);

            Assert.True(reclaimed >= 0);
        }

        private static LockerModel CreateLocker(string name, bool isLocked = false)
        {
            return new LockerModel(name, "hashed-password", $"/tmp/{name}")
            {
                Guid = Guid.NewGuid().ToString(),
                IsLocked = isLocked,
                StorageFormatVersion = isLocked ? LockerArchiveService.CurrentStorageFormatVersion : null,
                LockedArchiveSha256 = isLocked ? "abc123" : null,
                LockedAtUtc = isLocked ? DateTime.UtcNow : null
            };
        }

        private static int GetSchemaVersion(string connectionString)
        {
            using var connection = new SqliteConnection(connectionString);
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version";
            return Convert.ToInt32(command.ExecuteScalar());
        }

        private sealed class TestDatabase : IDisposable
        {
            private TestDatabase(string directory)
            {
                Directory = directory;
                Path = System.IO.Path.Join(directory, "lockers.db");
                ConnectionString = $"Data Source={Path};Pooling=False";
                System.IO.Directory.CreateDirectory(directory);
            }

            public string Directory { get; }
            public string Path { get; }
            public string ConnectionString { get; }

            public void Dispose()
            {
                SqliteConnection.ClearAllPools();

                for (var attempt = 1; attempt <= 5; attempt++)
                {
                    try
                    {
                        if (System.IO.Directory.Exists(Directory))
                        {
                            System.IO.Directory.Delete(Directory, true);
                        }

                        return;
                    }
                    catch (IOException) when (attempt < 5)
                    {
                        Thread.Sleep(100);
                    }
                    catch (UnauthorizedAccessException) when (attempt < 5)
                    {
                        Thread.Sleep(100);
                    }
                }
            }

            public static TestDatabase Create()
            {
                return new TestDatabase(System.IO.Path.Join(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), $"cdlocker-tests-{Guid.NewGuid():N}"));
            }

            public static TestDatabase CreateInitialized()
            {
                var database = Create();
                LockerRepository.InitializeDatabase(database.ConnectionString);
                return database;
            }
        }
    }
}

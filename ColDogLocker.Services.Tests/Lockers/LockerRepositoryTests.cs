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
using Microsoft.Data.Sqlite;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public class LockerRepositoryTests
    {
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
                Path = System.IO.Path.Combine(directory, "lockers.db");
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
                return new TestDatabase(System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"cdlocker-tests-{Guid.NewGuid():N}"));
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

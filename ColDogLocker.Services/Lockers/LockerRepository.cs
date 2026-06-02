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

using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Core.Models;
using Microsoft.Data.Sqlite;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public static class LockerRepository
    {
        private static readonly string _databasePath = Path.Join(AppPaths.LocalConfig, Path.GetFileName("lockers.db"));
        private static readonly string _connectionString = $"Data Source={_databasePath}";

        /// <summary>
        ///     Initialize the database and create the lockers table if it doesn't exist
        /// </summary>
        public static void InitializeDatabase()
        {
            try
            {
                Logger.Log(LogLevel.Debug, "Initializing database");

                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    CREATE TABLE IF NOT EXISTS Lockers (
                        Guid TEXT PRIMARY KEY,
                        LockerName TEXT NOT NULL UNIQUE,
                        Password TEXT NOT NULL,
                        LockerLocation TEXT NOT NULL,
                        IsLocked INTEGER NOT NULL DEFAULT 0,
                        CreatedAt TEXT NOT NULL DEFAULT (datetime('now')),
                        UpdatedAt TEXT NOT NULL DEFAULT (datetime('now'))
                    )";
                command.ExecuteNonQuery();

                Logger.Log(LogLevel.Debug, "Database initialized successfully");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to initialize database", ex);
                throw;
            }
        }

        /// <summary>
        ///     Get all lockers from the database
        /// </summary>
        public static List<LockerModel> GetAllLockers()
        {
            var lockers = new List<LockerModel>();

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT Guid, LockerName, Password, LockerLocation, IsLocked FROM Lockers ORDER BY LockerName";

                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    var locker = new LockerModel(
                        reader.GetString(1), // LockerName
                        reader.GetString(2), // Password
                        reader.GetString(3) // LockerLocation
                    ) { Guid = reader.GetString(0), IsLocked = reader.GetInt32(4) == 1 };
                    lockers.Add(locker);
                }

                Logger.Log(LogLevel.Info, $"Loaded {lockers.Count} lockers from database");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to load lockers from database", ex);
                throw;
            }

            return lockers;
        }

        /// <summary>
        ///     Get a single locker by GUID
        /// </summary>
        public static LockerModel? GetLockerByGuid(string guid)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT Guid, LockerName, Password, LockerLocation, IsLocked FROM Lockers WHERE Guid = $guid";
                command.Parameters.AddWithValue("$guid", guid);

                using var reader = command.ExecuteReader();
                if (reader.Read())
                {
                    return new LockerModel(
                        reader.GetString(1), // LockerName
                        reader.GetString(2), // Password
                        reader.GetString(3) // LockerLocation
                    ) { Guid = reader.GetString(0), IsLocked = reader.GetInt32(4) == 1 };
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to get locker by GUID", ex);
                throw;
            }

            return null;
        }

        /// <summary>
        ///     Get a single locker by name
        /// </summary>
        public static LockerModel? GetLockerByName(string name)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT Guid, LockerName, Password, LockerLocation, IsLocked FROM Lockers WHERE LockerName = $name COLLATE NOCASE";
                command.Parameters.AddWithValue("$name", name);

                using var reader = command.ExecuteReader();
                if (reader.Read())
                {
                    return new LockerModel(
                        reader.GetString(1), // LockerName
                        reader.GetString(2), // Password
                        reader.GetString(3) // LockerLocation
                    ) { Guid = reader.GetString(0), IsLocked = reader.GetInt32(4) == 1 };
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to get locker by name", ex);
                throw;
            }

            return null;
        }

        /// <summary>
        ///     Insert a new locker into the database
        /// </summary>
        public static void InsertLocker(LockerModel locker)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO Lockers (Guid, LockerName, Password, LockerLocation, IsLocked)
                    VALUES ($guid, $name, $password, $location, $isLocked)";

                command.Parameters.AddWithValue("$guid", locker.Guid);
                command.Parameters.AddWithValue("$name", locker.LockerName);
                command.Parameters.AddWithValue("$password", locker.Password);
                command.Parameters.AddWithValue("$location", locker.LockerLocation);
                command.Parameters.AddWithValue("$isLocked", locker.IsLocked ? 1 : 0);

                command.ExecuteNonQuery();

                Logger.Log(LogLevel.Debug, $"Inserted locker '{locker.LockerName}' into database");
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT
            {
                Logger.Log(LogLevel.Warning, $"Locker with name '{locker.LockerName}' already exists");
                throw new InvalidOperationException($"Locker with name '{locker.LockerName}' already exists.", ex);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to insert locker", ex);
                throw;
            }
        }

        /// <summary>
        ///     Update an existing locker in the database
        /// </summary>
        public static void UpdateLocker(LockerModel locker)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    UPDATE Lockers
                    SET LockerName = $name,
                        Password = $password,
                        LockerLocation = $location,
                        IsLocked = $isLocked,
                        UpdatedAt = datetime('now')
                    WHERE Guid = $guid";

                command.Parameters.AddWithValue("$guid", locker.Guid);
                command.Parameters.AddWithValue("$name", locker.LockerName);
                command.Parameters.AddWithValue("$password", locker.Password);
                command.Parameters.AddWithValue("$location", locker.LockerLocation);
                command.Parameters.AddWithValue("$isLocked", locker.IsLocked ? 1 : 0);

                var rowsAffected = command.ExecuteNonQuery();

                if (rowsAffected == 0)
                {
                    Logger.Log(LogLevel.Warning, $"Locker with GUID '{locker.Guid}' not found for update");
                    throw new InvalidOperationException($"Locker with GUID '{locker.Guid}' not found.");
                }

                Logger.Log(LogLevel.Debug, $"Updated locker '{locker.LockerName}' in database");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to update locker", ex);
                throw;
            }
        }

        /// <summary>
        ///     Delete a locker from the database
        /// </summary>
        public static void DeleteLocker(string guid)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "DELETE FROM Lockers WHERE Guid = $guid";
                command.Parameters.AddWithValue("$guid", guid);

                var rowsAffected = command.ExecuteNonQuery();

                if (rowsAffected == 0)
                {
                    Logger.Log(LogLevel.Warning, $"Locker with GUID '{guid}' not found for deletion");
                    throw new InvalidOperationException($"Locker with GUID '{guid}' not found.");
                }

                Logger.Log(LogLevel.Info, $"Deleted locker with GUID '{guid}' from database");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to delete locker", ex);
                throw;
            }
        }

        /// <summary>
        ///     Check if a locker with the given name exists
        /// </summary>
        public static bool LockerExists(string name)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT COUNT(*) FROM Lockers WHERE LockerName = $name COLLATE NOCASE";
                command.Parameters.AddWithValue("$name", name);

                var count = (long)command.ExecuteScalar()!;
                return count > 0;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to check locker existence", ex);
                throw;
            }
        }

        /// <summary>
        ///     Vacuum the database to reclaim space and optimize performance
        /// </summary>
        public static long VacuumDatabase()
        {
            try
            {
                long sizeBefore = 0;
                long sizeAfter = 0;

                if (File.Exists(_databasePath))
                {
                    sizeBefore = new FileInfo(_databasePath).Length;
                }

                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "VACUUM";
                command.ExecuteNonQuery();

                if (File.Exists(_databasePath))
                {
                    sizeAfter = new FileInfo(_databasePath).Length;
                }

                var reclaimed = sizeBefore - sizeAfter;
                Logger.Log(LogLevel.Info, $"Database vacuumed. Size before: {sizeBefore} bytes, after: {sizeAfter} bytes. Reclaimed: {reclaimed} bytes");

                return reclaimed;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to vacuum database", ex);
                throw;
            }
        }

        /// <summary>
        ///     Get database information and statistics
        /// </summary>
        public static DatabaseInfo GetDatabaseInfo()
        {
            try
            {
                var info = new DatabaseInfo { Path = _databasePath, Exists = File.Exists(_databasePath) };

                if (!info.Exists)
                {
                    return info;
                }

                var fileInfo = new FileInfo(_databasePath);
                info.SizeBytes = fileInfo.Length;
                info.Created = fileInfo.CreationTime;
                info.LastModified = fileInfo.LastWriteTime;

                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                // Get locker count
                var countCommand = connection.CreateCommand();
                countCommand.CommandText = "SELECT COUNT(*) FROM Lockers";
                info.LockerCount = (int)(long)countCommand.ExecuteScalar()!;

                // Get SQLite version
                var versionCommand = connection.CreateCommand();
                versionCommand.CommandText = "SELECT sqlite_version()";
                info.SqliteVersion = versionCommand.ExecuteScalar()?.ToString() ?? "Unknown";

                // Check integrity
                var integrityCommand = connection.CreateCommand();
                integrityCommand.CommandText = "PRAGMA integrity_check";
                var integrityResult = integrityCommand.ExecuteScalar()?.ToString();
                info.IntegrityOk = integrityResult?.Equals("ok", StringComparison.OrdinalIgnoreCase) ?? false;

                Logger.Log(LogLevel.Debug, "Database info retrieved successfully");
                return info;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, $"Failed to get database info: {ex.Message}", ex);
                throw;
            }
        }
    }

    /// <summary>
    ///     Database information class
    /// </summary>
    public class DatabaseInfo
    {
        public string Path { get; set; } = string.Empty;
        public bool Exists { get; set; }
        public long SizeBytes { get; set; }
        public DateTime Created { get; set; }
        public DateTime LastModified { get; set; }
        public int LockerCount { get; set; }
        public string SqliteVersion { get; set; } = string.Empty;
        public bool IntegrityOk { get; set; }
    }
}

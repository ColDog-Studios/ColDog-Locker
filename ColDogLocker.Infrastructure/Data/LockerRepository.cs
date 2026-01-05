using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
using Microsoft.Data.Sqlite;

namespace ColDogStudios.ColDogLocker.Infrastructure.Data
{
    public static class LockerRepository
    {
        private static readonly string DatabasePath = Path.Combine(Variables.localConfig, "lockers.db");
        private static readonly string ConnectionString = $"Data Source={DatabasePath}";

        /// <summary>
        /// Initialize the database and create the lockers table if it doesn't exist
        /// </summary>
        public static void InitializeDatabase()
        {
            try
            {
                using var connection = new SqliteConnection(ConnectionString);
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

                Logger.AddEntry("Database initialized successfully.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to initialize database: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Get all lockers from the database
        /// </summary>
        public static List<LockerModel> GetAllLockers()
        {
            var lockers = new List<LockerModel>();

            try
            {
                using var connection = new SqliteConnection(ConnectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT Guid, LockerName, Password, LockerLocation, IsLocked FROM Lockers ORDER BY LockerName";

                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    var locker = new LockerModel(
                        reader.GetString(1), // LockerName
                        reader.GetString(2), // Password
                        reader.GetString(3)  // LockerLocation
                    )
                    {
                        Guid = reader.GetString(0),
                        IsLocked = reader.GetInt32(4) == 1
                    };
                    lockers.Add(locker);
                }

                Logger.AddEntry($"Loaded {lockers.Count} lockers from database.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to load lockers from database: {ex.Message}", LogLevel.Error);
                throw;
            }

            return lockers;
        }

        /// <summary>
        /// Get a single locker by GUID
        /// </summary>
        public static LockerModel? GetLockerByGuid(string guid)
        {
            try
            {
                using var connection = new SqliteConnection(ConnectionString);
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
                        reader.GetString(3)  // LockerLocation
                    )
                    {
                        Guid = reader.GetString(0),
                        IsLocked = reader.GetInt32(4) == 1
                    };
                }
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to get locker by GUID: {ex.Message}", LogLevel.Error);
                throw;
            }

            return null;
        }

        /// <summary>
        /// Get a single locker by name
        /// </summary>
        public static LockerModel? GetLockerByName(string name)
        {
            try
            {
                using var connection = new SqliteConnection(ConnectionString);
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
                        reader.GetString(3)  // LockerLocation
                    )
                    {
                        Guid = reader.GetString(0),
                        IsLocked = reader.GetInt32(4) == 1
                    };
                }
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to get locker by name: {ex.Message}", LogLevel.Error);
                throw;
            }

            return null;
        }

        /// <summary>
        /// Insert a new locker into the database
        /// </summary>
        public static void InsertLocker(LockerModel locker)
        {
            try
            {
                using var connection = new SqliteConnection(ConnectionString);
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

                Logger.AddEntry($"Inserted locker '{locker.LockerName}' into database.", LogLevel.Info);
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT
            {
                Logger.AddEntry($"Locker with name '{locker.LockerName}' already exists.", LogLevel.Warning);
                throw new InvalidOperationException($"Locker with name '{locker.LockerName}' already exists.", ex);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to insert locker: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Update an existing locker in the database
        /// </summary>
        public static void UpdateLocker(LockerModel locker)
        {
            try
            {
                using var connection = new SqliteConnection(ConnectionString);
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
                    Logger.AddEntry($"Locker with GUID '{locker.Guid}' not found for update.", LogLevel.Warning);
                    throw new InvalidOperationException($"Locker with GUID '{locker.Guid}' not found.");
                }

                Logger.AddEntry($"Updated locker '{locker.LockerName}' in database.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to update locker: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Delete a locker from the database
        /// </summary>
        public static void DeleteLocker(string guid)
        {
            try
            {
                using var connection = new SqliteConnection(ConnectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "DELETE FROM Lockers WHERE Guid = $guid";
                command.Parameters.AddWithValue("$guid", guid);

                var rowsAffected = command.ExecuteNonQuery();

                if (rowsAffected == 0)
                {
                    Logger.AddEntry($"Locker with GUID '{guid}' not found for deletion.", LogLevel.Warning);
                    throw new InvalidOperationException($"Locker with GUID '{guid}' not found.");
                }

                Logger.AddEntry($"Deleted locker with GUID '{guid}' from database.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to delete locker: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Check if a locker with the given name exists
        /// </summary>
        public static bool LockerExists(string name)
        {
            try
            {
                using var connection = new SqliteConnection(ConnectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT COUNT(*) FROM Lockers WHERE LockerName = $name COLLATE NOCASE";
                command.Parameters.AddWithValue("$name", name);

                var count = (long)command.ExecuteScalar()!;
                return count > 0;
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to check locker existence: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Vacuum the database to reclaim space and optimize performance
        /// </summary>
        public static long VacuumDatabase()
        {
            try
            {
                long sizeBefore = 0;
                long sizeAfter = 0;

                if (File.Exists(DatabasePath))
                {
                    sizeBefore = new FileInfo(DatabasePath).Length;
                }

                using var connection = new SqliteConnection(ConnectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "VACUUM";
                command.ExecuteNonQuery();

                if (File.Exists(DatabasePath))
                {
                    sizeAfter = new FileInfo(DatabasePath).Length;
                }

                long reclaimed = sizeBefore - sizeAfter;
                Logger.AddEntry($"Database vacuumed. Size before: {sizeBefore} bytes, after: {sizeAfter} bytes. Reclaimed: {reclaimed} bytes.", LogLevel.Info);

                return reclaimed;
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to vacuum database: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Get database information and statistics
        /// </summary>
        public static DatabaseInfo GetDatabaseInfo()
        {
            try
            {
                var info = new DatabaseInfo
                {
                    Path = DatabasePath,
                    Exists = File.Exists(DatabasePath)
                };

                if (!info.Exists)
                {
                    return info;
                }

                var fileInfo = new FileInfo(DatabasePath);
                info.SizeBytes = fileInfo.Length;
                info.Created = fileInfo.CreationTime;
                info.LastModified = fileInfo.LastWriteTime;

                using var connection = new SqliteConnection(ConnectionString);
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

                Logger.AddEntry("Database info retrieved successfully.", LogLevel.Info);
                return info;
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to get database info: {ex.Message}", LogLevel.Error);
                throw;
            }
        }
    }

    /// <summary>
    /// Database information class
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

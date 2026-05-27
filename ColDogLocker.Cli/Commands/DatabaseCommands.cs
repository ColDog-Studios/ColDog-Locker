using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Data;

namespace ColDogStudios.ColDogLocker.Cli.Commands
{
    /// <summary>
    /// Handlers for database-related CLI commands (db-vacuum, db-info).
    /// </summary>
    public static class DatabaseCommands
    {
        public static int DbVacuum(string[] args)
        {
            // Usage: cdlocker db-vacuum

            try
            {
                Console.WriteLine("Vacuuming database...");
                var reclaimed = LockerRepository.VacuumDatabase();

                // Update last vacuum time
                SettingsManager.Settings.LastDatabaseVacuum = DateTime.Now;
                SettingsManager.SaveSettings();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Database vacuumed successfully.");
                Console.ResetColor();
                Console.WriteLine($"Reclaimed: {reclaimed:N0} bytes ({reclaimed / 1024.0:F2} KB)");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error vacuuming database: {ex.Message}");
                return 1;
            }
        }

        public static int DbInfo(string[] args)
        {
            // Usage: cdlocker db-info

            try
            {
                var info = LockerRepository.GetDatabaseInfo();

                Console.WriteLine();
                Console.WriteLine("Database Information:");
                Console.WriteLine($"  Path: {info.Path}");
                Console.WriteLine($"  Exists: {info.Exists}");

                if (info.Exists)
                {
                    Console.WriteLine($"  Size: {info.SizeBytes:N0} bytes ({info.SizeBytes / 1024.0:F2} KB)");
                    Console.WriteLine($"  Created: {info.Created:yyyy-MM-dd HH:mm:ss}");
                    Console.WriteLine($"  Last Modified: {info.LastModified:yyyy-MM-dd HH:mm:ss}");
                    Console.WriteLine($"  Lockers: {info.LockerCount}");
                    Console.WriteLine($"  SQLite Version: {info.SqliteVersion}");
                    Console.WriteLine($"  Integrity: {(info.IntegrityOk ? "OK" : "FAILED")}");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error getting database info: {ex.Message}");
                return 1;
            }
        }
    }
}

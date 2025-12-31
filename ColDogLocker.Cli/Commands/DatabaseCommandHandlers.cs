using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Data;

namespace ColDogStudios.ColDogLocker.Cli.Commands;

/// <summary>
/// Handlers for database-related CLI commands (db-vacuum, db-info).
/// </summary>
public static class DatabaseCommandHandlers
{
    public static int HandleDbVacuum(string[] args)
    {
        // Usage: ColDogLocker.exe db-vacuum

        try
        {
            System.Console.WriteLine("Vacuuming database...");
            long reclaimed = LockerRepository.VacuumDatabase();

            // Update last vacuum time
            SettingsManager.Settings.LastDatabaseVacuum = DateTime.Now;
            SettingsManager.SaveSettings();

            System.Console.ForegroundColor = ConsoleColor.Green;
            System.Console.WriteLine($"Database vacuumed successfully.");
            System.Console.ResetColor();
            System.Console.WriteLine($"Reclaimed: {reclaimed:N0} bytes ({reclaimed / 1024.0:F2} KB)");
            return 0;
        }
        catch (Exception ex)
        {
            System.Console.Error.WriteLine($"Error vacuuming database: {ex.Message}");
            return 1;
        }
    }

    public static int HandleDbInfo(string[] args)
    {
        // Usage: ColDogLocker.exe db-info

        try
        {
            var info = LockerRepository.GetDatabaseInfo();

            System.Console.WriteLine();
            System.Console.WriteLine("Database Information:");
            System.Console.WriteLine($"  Path: {info.Path}");
            System.Console.WriteLine($"  Exists: {info.Exists}");

            if (info.Exists)
            {
                System.Console.WriteLine($"  Size: {info.SizeBytes:N0} bytes ({info.SizeBytes / 1024.0:F2} KB)");
                System.Console.WriteLine($"  Created: {info.Created:yyyy-MM-dd HH:mm:ss}");
                System.Console.WriteLine($"  Last Modified: {info.LastModified:yyyy-MM-dd HH:mm:ss}");
                System.Console.WriteLine($"  Lockers: {info.LockerCount}");
                System.Console.WriteLine($"  SQLite Version: {info.SqliteVersion}");
                System.Console.WriteLine($"  Integrity: {(info.IntegrityOk ? "OK" : "FAILED")}");
            }

            return 0;
        }
        catch (Exception ex)
        {
            System.Console.Error.WriteLine($"Error getting database info: {ex.Message}");
            return 1;
        }
    }
}

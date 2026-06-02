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

using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Cli.Commands
{
    /// <summary>
    ///     Handlers for database-related CLI commands (db-vacuum, db-info).
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
                Console.WriteLine("Database vacuumed successfully.");
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

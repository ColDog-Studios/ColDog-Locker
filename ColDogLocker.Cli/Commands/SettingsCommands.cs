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
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Cli.Commands
{
    /// <summary>
    ///     Handlers for settings-related CLI commands.
    /// </summary>
    public static class SettingsCommands
    {
        public static int Settings(string[] args)
        {
            // Usage: cdlocker settings [<key> [<value>]]

            // No arguments - show all settings
            if (args.Length == 1)
            {
                // Show current settings
                Console.WriteLine("Current Settings:");
                Console.WriteLine($"  Dev Mode: {SettingsManager.Settings.DevMode}");
                Console.WriteLine($"  Log Level: {SettingsManager.Settings.LogLevel}");
                Console.WriteLine($"  Log Format: {SettingsManager.Settings.LogFormat}");
                Console.WriteLine($"  Max File Size: {SettingsManager.Settings.MaxFileSizeMb} MB");
                Console.WriteLine($"  File Logging: {(SettingsManager.Settings.EnableFileLogging ? "Enabled" : "Disabled")}");
                Console.WriteLine("  Log Retention: Active log plus 4 rotated files");
                Console.WriteLine("  Timestamps: UTC ISO-8601");
                Console.WriteLine("  Async Logging: Enabled");
                Console.WriteLine("  Thread IDs: Enabled with Dev Mode");
                Console.WriteLine($"  Auto Update: {SettingsManager.Settings.AutoUpdate}");
                Console.WriteLine($"  Update Channel: {SettingsManager.Settings.UpdateChannel}");
                Console.WriteLine($"  Database Vacuum Interval: {SettingsManager.Settings.DatabaseVacuumInterval} days");
                Console.WriteLine($"  Last Database Vacuum: {SettingsManager.Settings.LastDatabaseVacuum?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");
                return 0;
            }

            // Show specific setting or update setting
            if (args.Length == 2)
            {
                // Show specific setting
                var key = args[1].ToLowerInvariant();
                switch (key)
                {
                    case "debug":
                        Console.WriteLine($"Dev Mode: {SettingsManager.Settings.DevMode}");
                        return 0;
                    case "log-level":
                        Console.WriteLine($"Log Level: {SettingsManager.Settings.LogLevel}");
                        return 0;
                    case "log-format":
                        Console.WriteLine($"Log Format: {SettingsManager.Settings.LogFormat}");
                        return 0;
                    case "max-file-size":
                        Console.WriteLine($"Max File Size: {SettingsManager.Settings.MaxFileSizeMb} MB");
                        return 0;
                    case "file-logging":
                        Console.WriteLine($"File Logging: {(SettingsManager.Settings.EnableFileLogging ? "Enabled" : "Disabled")}");
                        return 0;
                    case "auto-update" or "autoupdate":
                        Console.WriteLine($"Auto Update: {SettingsManager.Settings.AutoUpdate}");
                        return 0;
                    case "update-channel" or "updatechannel":
                        Console.WriteLine($"Update Channel: {SettingsManager.Settings.UpdateChannel}");
                        return 0;
                    case "db-vacuum-interval" or "vacuuminterval":
                        Console.WriteLine($"Database Vacuum Interval: {SettingsManager.Settings.DatabaseVacuumInterval} days");
                        return 0;
                    default:
                        Console.Error.WriteLine($"Error: Unknown setting '{key}'.");
                        Console.WriteLine(
                            "Available settings: debug, auto-update, update-channel, db-vacuum-interval, log-level, log-format, max-file-size, file-logging");
                        return 1;
                }
            }

            if (args.Length == 3)
            {
                var key = args[1].ToLowerInvariant();
                var value = args[2].ToLowerInvariant();

                switch (key)
                {
                    case "debug":
                        if (bool.TryParse(value, out var devMode))
                        {
                            SettingsManager.Settings.DevMode = devMode;
                            Logger.SetDevMode(devMode);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Dev mode set to: {devMode}");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                        return 1;

                    case "log-level":
                        SettingsManager.Settings.LogLevel = value;
                        Logger.SetLogLevel(Enum.TryParse(value, true, out LogLevel lvl) ? lvl : LogLevel.Info);
                        SettingsManager.SaveSettings();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"Log level set to: {value}");
                        Console.ResetColor();
                        return 0;
                    case "log-format":
                        SettingsManager.Settings.LogFormat = value;
                        Logger.SetLogFormat(value);
                        SettingsManager.SaveSettings();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"Log format set to: {value}");
                        Console.ResetColor();
                        return 0;
                    case "max-file-size":
                        if (int.TryParse(value, out var maxSize) && maxSize > 0)
                        {
                            SettingsManager.Settings.MaxFileSizeMb = maxSize;
                            Logger.SetMaxFileSizeMb(maxSize);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Max file size set to: {maxSize} MB");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Must be a positive integer.");
                        return 1;
                    case "file-logging":
                        if (bool.TryParse(value, out var fileLogging))
                        {
                            SettingsManager.Settings.EnableFileLogging = fileLogging;
                            Logger.SetEnableFileLogging(fileLogging);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"File logging set to: {fileLogging}");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                        return 1;

                    case "auto-update" or "autoupdate":
                        if (bool.TryParse(value, out var autoUpdate))
                        {
                            SettingsManager.Settings.AutoUpdate = autoUpdate;
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Auto update set to: {autoUpdate}");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                        return 1;

                    case "db-vacuum-interval" or "vacuuminterval":
                        if (int.TryParse(value, out var interval) && interval is >= 0 and <= 365)
                        {
                            SettingsManager.Settings.DatabaseVacuumInterval = interval;
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Database vacuum interval set to: {interval} days (0 = disabled)");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Must be between 0 and 365 days.");
                        return 1;

                    case "update-channel" or "updatechannel":
                        if (value is "stable" or "s")
                        {
                            SettingsManager.Settings.UpdateChannel = UpdateChannel.Stable;
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("Update channel set to: Stable");
                            Console.ResetColor();
                            return 0;
                        }

                        if (value is "unstable" or "u" or "prerelease" or "pre" or "p")
                        {
                            SettingsManager.Settings.UpdateChannel = UpdateChannel.Unstable;
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("Update channel set to: Unstable");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'stable' or 'unstable'.");
                        return 1;

                    default:
                        Console.Error.WriteLine($"Error: Unknown setting '{key}'.");
                        Console.WriteLine(
                            "Available settings: debug, auto-update, update-channel, db-vacuum-interval, log-level, log-format, max-file-size, file-logging");
                        return 1;
                }
            }

            Console.Error.WriteLine("Usage: cdlocker settings [<key> [<value>]]");
            return 1;
        }
    }
}

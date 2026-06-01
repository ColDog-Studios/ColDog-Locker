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
                Console.WriteLine($"  Max Retained Files: {SettingsManager.Settings.MaxRetainedFiles}");
                Console.WriteLine($"  File Logging: {(SettingsManager.Settings.EnableFileLogging ? "Enabled" : "Disabled")}");
                Console.WriteLine($"  Compression: {(SettingsManager.Settings.EnableCompression ? "Enabled" : "Disabled")}");
                Console.WriteLine($"  Include Timestamps: {(SettingsManager.Settings.IncludeTimestamps ? "Yes" : "No")}");
                Console.WriteLine($"  Include Thread ID: {(SettingsManager.Settings.IncludeThreadId ? "Yes" : "No")}");
                Console.WriteLine($"  Date/Time Format: {SettingsManager.Settings.DateTimeFormat}");
                Console.WriteLine($"  Async Logging: {(SettingsManager.Settings.AsyncLogging ? "Enabled" : "Disabled")}");
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
                    case "max-retained-files":
                        Console.WriteLine($"Max Retained Files: {SettingsManager.Settings.MaxRetainedFiles}");
                        return 0;
                    case "file-logging":
                        Console.WriteLine($"File Logging: {(SettingsManager.Settings.EnableFileLogging ? "Enabled" : "Disabled")}");
                        return 0;
                    case "compression":
                        Console.WriteLine($"Compression: {(SettingsManager.Settings.EnableCompression ? "Enabled" : "Disabled")}");
                        return 0;
                    case "include-timestamps":
                        Console.WriteLine($"Include Timestamps: {(SettingsManager.Settings.IncludeTimestamps ? "Yes" : "No")}");
                        return 0;
                    case "include-thread-id":
                        Console.WriteLine($"Include Thread ID: {(SettingsManager.Settings.IncludeThreadId ? "Yes" : "No")}");
                        return 0;
                    case "date-time-format":
                        Console.WriteLine($"Date/Time Format: {SettingsManager.Settings.DateTimeFormat}");
                        return 0;
                    case "async-logging":
                        Console.WriteLine($"Async Logging: {(SettingsManager.Settings.AsyncLogging ? "Enabled" : "Disabled")}");
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
                        Console.WriteLine("Available settings: debug, auto-update, update-channel, db-vacuum-interval");
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
                    case "max-retained-files":
                        if (int.TryParse(value, out var maxRetained) && maxRetained > 0)
                        {
                            SettingsManager.Settings.MaxRetainedFiles = maxRetained;
                            Logger.SetMaxRetainedFiles(maxRetained);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Max retained files set to: {maxRetained}");
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
                    case "compression":
                        if (bool.TryParse(value, out var compression))
                        {
                            SettingsManager.Settings.EnableCompression = compression;
                            Logger.SetEnableCompression(compression);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Compression set to: {compression}");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                        return 1;
                    case "include-timestamps":
                        if (bool.TryParse(value, out var timestamps))
                        {
                            SettingsManager.Settings.IncludeTimestamps = timestamps;
                            Logger.SetIncludeTimestamps(timestamps);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Include timestamps set to: {timestamps}");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                        return 1;
                    case "include-thread-id":
                        if (bool.TryParse(value, out var threadId))
                        {
                            SettingsManager.Settings.IncludeThreadId = threadId;
                            Logger.SetIncludeThreadId(threadId);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Include thread ID set to: {threadId}");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                        return 1;
                    case "date-time-format":
                        SettingsManager.Settings.DateTimeFormat = value;
                        Logger.SetDateTimeFormat(value);
                        SettingsManager.SaveSettings();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"Date/time format set to: {value}");
                        Console.ResetColor();
                        return 0;
                    case "async-logging":
                        if (bool.TryParse(value, out var asyncLogging))
                        {
                            SettingsManager.Settings.AsyncLogging = asyncLogging;
                            Logger.SetAsyncLogging(asyncLogging);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Async logging set to: {asyncLogging}");
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

                        if (value is "prerelease" or "pre" or "p")
                        {
                            SettingsManager.Settings.UpdateChannel = UpdateChannel.Prerelease;
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("Update channel set to: Prerelease");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'stable' or 'prerelease'.");
                        return 1;

                    default:
                        Console.Error.WriteLine($"Error: Unknown setting '{key}'.");
                        Console.WriteLine(
                            "Available settings: debug, auto-update, update-channel, db-vacuum-interval, log-level, log-format, max-file-size, max-retained-files, file-logging, compression, include-timestamps, include-thread-id, date-time-format, async-logging");
                        return 1;
                }
            }

            Console.Error.WriteLine("Usage: cdlocker settings [<key> [<value>]]");
            return 1;
        }
    }
}

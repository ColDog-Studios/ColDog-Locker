using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Cli.Commands
{
    /// <summary>
    /// Handlers for settings-related CLI commands.
    /// </summary>
    public static class SettingsCommandHandlers
    {
        public static int HandleSettings(string[] args)
        {
            // Usage: ColDogLocker.exe settings [<key> [<value>]]

            if (args.Length == 1)
            {
                // Show current settings
                Console.WriteLine("Current Settings:");
                Console.WriteLine($"  Debug Mode: {SettingsManager.Settings.DebugMode}");
                Console.WriteLine($"  Log Retention Days: {SettingsManager.Settings.LogRetentionDays}");
                Console.WriteLine($"  Auto Update: {SettingsManager.Settings.AutoUpdate}");
                Console.WriteLine($"  Update Channel: {SettingsManager.Settings.UpdateChannel}");
                Console.WriteLine($"  Database Vacuum Interval: {SettingsManager.Settings.DatabaseVacuumInterval} days");
                Console.WriteLine($"  Last Database Vacuum: {SettingsManager.Settings.LastDatabaseVacuum?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");
                return 0;
            }

            if (args.Length == 2)
            {
                // Show specific setting
                var key = args[1].ToLowerInvariant();
                switch (key)
                {
                    case "debug":
                        Console.WriteLine($"Debug Mode: {SettingsManager.Settings.DebugMode}");
                        return 0;
                    case "log-retention" or "logretention":
                        Console.WriteLine($"Log Retention Days: {SettingsManager.Settings.LogRetentionDays}");
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
                        Console.WriteLine("Available settings: debug, log-retention, auto-update, update-channel, db-vacuum-interval");
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
                        if (bool.TryParse(value, out var debugMode))
                        {
                            SettingsManager.Settings.DebugMode = debugMode;
                            Logger.SetDebugMode(debugMode);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Debug mode set to: {debugMode}");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                        return 1;

                    case "log-retention" or "logretention":
                        if (int.TryParse(value, out var retention) && retention > 0 && retention <= 3650)
                        {
                            SettingsManager.Settings.LogRetentionDays = retention;
                            Logger.SetLogRetentionDays(retention);
                            SettingsManager.SaveSettings();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Log retention days set to: {retention}");
                            Console.ResetColor();
                            return 0;
                        }

                        Console.Error.WriteLine("Error: Invalid value. Must be between 1 and 3650 days.");
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
                        if (int.TryParse(value, out var interval) && interval >= 0 && interval <= 365)
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
                        else if (value is "prerelease" or "pre" or "p")
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
                        Console.WriteLine("Available settings: debug, log-retention, auto-update, update-channel, db-vacuum-interval");
                        return 1;
                }
            }

            Console.Error.WriteLine("Usage: ColDogLocker settings [<key> [<value>]]");
            return 1;
        }
    }
}

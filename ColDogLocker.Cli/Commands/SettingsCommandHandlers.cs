using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Cli.Commands;

/// <summary>
/// Handlers for settings-related CLI commands.
/// </summary>
public static class SettingsCommandHandlers
{
    public static int HandleSettings(string[] args)
    {
        // Usage: ColDogLocker.exe settings [set <key> <value>]

        if (args.Length == 1)
        {
            // Show current settings
            System.Console.WriteLine("Current Settings:");
            System.Console.WriteLine($"  Debug Mode: {SettingsManager.Settings.DebugMode}");
            System.Console.WriteLine($"  Log Retention Days: {SettingsManager.Settings.LogRetentionDays}");
            System.Console.WriteLine($"  Auto Update: {SettingsManager.Settings.AutoUpdate}");
            System.Console.WriteLine($"  Database Vacuum Interval: {SettingsManager.Settings.DatabaseVacuumInterval} days");
            System.Console.WriteLine($"  Last Database Vacuum: {SettingsManager.Settings.LastDatabaseVacuum?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");
            return 0;
        }

        if (args.Length >= 3 && args[1].ToLowerInvariant() == "set")
        {
            var key = args[2].ToLowerInvariant();
            
            if (args.Length < 4)
            {
                System.Console.Error.WriteLine("Error: Value is required.");
                return 1;
            }

            var value = args[3].ToLowerInvariant();

            switch (key)
            {
                case "debug":
                case "debugmode":
                    if (bool.TryParse(value, out bool debugMode))
                    {
                        SettingsManager.Settings.DebugMode = debugMode;
                        Logger.SetDebugMode(debugMode);
                        SettingsManager.SaveSettings();
                        System.Console.ForegroundColor = ConsoleColor.Green;
                        System.Console.WriteLine($"Debug mode set to: {debugMode}");
                        System.Console.ResetColor();
                        return 0;
                    }
                    System.Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                    return 1;

                case "log-retention":
                case "logretention":
                    if (int.TryParse(value, out int retention) && retention > 0 && retention <= 3650)
                    {
                        SettingsManager.Settings.LogRetentionDays = retention;
                        Logger.SetLogRetentionDays(retention);
                        SettingsManager.SaveSettings();
                        System.Console.ForegroundColor = ConsoleColor.Green;
                        System.Console.WriteLine($"Log retention days set to: {retention}");
                        System.Console.ResetColor();
                        return 0;
                    }
                    System.Console.Error.WriteLine("Error: Invalid value. Must be between 1 and 3650 days.");
                    return 1;

                case "auto-update":
                case "autoupdate":
                    if (bool.TryParse(value, out bool autoUpdate))
                    {
                        SettingsManager.Settings.AutoUpdate = autoUpdate;
                        SettingsManager.SaveSettings();
                        System.Console.ForegroundColor = ConsoleColor.Green;
                        System.Console.WriteLine($"Auto update set to: {autoUpdate}");
                        System.Console.ResetColor();
                        return 0;
                    }
                    System.Console.Error.WriteLine("Error: Invalid value. Use 'true' or 'false'.");
                    return 1;

                case "db-vacuum-interval":
                case "vacuuminterval":
                    if (int.TryParse(value, out int interval) && interval >= 0 && interval <= 365)
                    {
                        SettingsManager.Settings.DatabaseVacuumInterval = interval;
                        SettingsManager.SaveSettings();
                        System.Console.ForegroundColor = ConsoleColor.Green;
                        System.Console.WriteLine($"Database vacuum interval set to: {interval} days (0 = disabled)");
                        System.Console.ResetColor();
                        return 0;
                    }
                    System.Console.Error.WriteLine("Error: Invalid value. Must be between 0 and 365 days.");
                    return 1;

                default:
                    System.Console.Error.WriteLine($"Error: Unknown setting '{key}'.");
                    System.Console.WriteLine("Available settings: debug, log-retention, auto-update, db-vacuum-interval");
                    return 1;
            }
        }

        System.Console.Error.WriteLine("Usage: ColDogLocker settings [set <key> <value>]");
        return 1;
    }
}

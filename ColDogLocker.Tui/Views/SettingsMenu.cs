using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Tui.Views
{
    public static class SettingsMenu
    {
        // Update settings based on user input
        public static void UpdateSettings()
        {
            // Show Settings Menu
            MainMenu.MenuTitle("Main Menu > Settings");

            Console.WriteLine("Current Settings Configuration:\n");

            // Prompt the user to enable or disable debug mode
            Console.Write($"Enable Dev Mode (includes source file/line)? (y/N) [Current: {(SettingsManager.Settings.DevMode ? "Yes" : "No")}]: ");
            var devModeInput = Console.ReadLine();
            var devMode = !string.IsNullOrEmpty(devModeInput) && devModeInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            // Logging Settings Prompts
            Console.WriteLine("\nLogging Settings:");
            Console.Write($"Minimum Log Level (Debug/Info/Success/Warning/Error/Fatal) [Current: {SettingsManager.Settings.LogLevel}]: ");
            var logLevelInput = Console.ReadLine();
            var logLevel = string.IsNullOrWhiteSpace(logLevelInput) ? SettingsManager.Settings.LogLevel : logLevelInput;

            Console.Write($"Log Format (json/text) [Current: {SettingsManager.Settings.LogFormat}]: ");
            var logFormatInput = Console.ReadLine();
            var logFormat = string.IsNullOrWhiteSpace(logFormatInput) ? SettingsManager.Settings.LogFormat : logFormatInput;

            Console.Write($"Max Log File Size (MB) [Current: {SettingsManager.Settings.MaxFileSizeMB}]: ");
            var maxFileSizeInput = Console.ReadLine();
            var maxFileSizeMB = SettingsManager.Settings.MaxFileSizeMB;
            if (!string.IsNullOrWhiteSpace(maxFileSizeInput) && int.TryParse(maxFileSizeInput, out var parsedSize) && parsedSize > 0)
            {
                maxFileSizeMB = parsedSize;
            }

            Console.Write($"Max Retained Log Files [Current: {SettingsManager.Settings.MaxRetainedFiles}]: ");
            var maxRetainedInput = Console.ReadLine();
            var maxRetainedFiles = SettingsManager.Settings.MaxRetainedFiles;
            if (!string.IsNullOrWhiteSpace(maxRetainedInput) && int.TryParse(maxRetainedInput, out var parsedRetained) && parsedRetained > 0)
            {
                maxRetainedFiles = parsedRetained;
            }

            Console.Write($"Enable File Logging? (y/N) [Current: {(SettingsManager.Settings.EnableFileLogging ? "Yes" : "No")}] ");
            var enableFileLoggingInput = Console.ReadLine();
            var enableFileLogging = string.IsNullOrWhiteSpace(enableFileLoggingInput) ? SettingsManager.Settings.EnableFileLogging : enableFileLoggingInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            Console.Write($"Enable Compression? (y/N) [Current: {(SettingsManager.Settings.EnableCompression ? "Yes" : "No")}] ");
            var enableCompressionInput = Console.ReadLine();
            var enableCompression = string.IsNullOrWhiteSpace(enableCompressionInput) ? SettingsManager.Settings.EnableCompression : enableCompressionInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            Console.Write($"Include Timestamps? (y/N) [Current: {(SettingsManager.Settings.IncludeTimestamps ? "Yes" : "No")}] ");
            var includeTimestampsInput = Console.ReadLine();
            var includeTimestamps = string.IsNullOrWhiteSpace(includeTimestampsInput) ? SettingsManager.Settings.IncludeTimestamps : includeTimestampsInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            Console.Write($"Include Thread ID? (y/N) [Current: {(SettingsManager.Settings.IncludeThreadId ? "Yes" : "No")}] ");
            var includeThreadIdInput = Console.ReadLine();
            var includeThreadId = string.IsNullOrWhiteSpace(includeThreadIdInput) ? SettingsManager.Settings.IncludeThreadId : includeThreadIdInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            Console.Write($"Date/Time Format (UTC/Local) [Current: {SettingsManager.Settings.DateTimeFormat}]: ");
            var dateTimeFormatInput = Console.ReadLine();
            var dateTimeFormat = string.IsNullOrWhiteSpace(dateTimeFormatInput) ? SettingsManager.Settings.DateTimeFormat : dateTimeFormatInput;

            Console.Write($"Enable Async Logging? (y/N) [Current: {(SettingsManager.Settings.AsyncLogging ? "Yes" : "No")}] ");
            var asyncLoggingInput = Console.ReadLine();
            var asyncLogging = string.IsNullOrWhiteSpace(asyncLoggingInput) ? SettingsManager.Settings.AsyncLogging : asyncLoggingInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            // Prompt the user to enable or disable auto updates
            Console.Write($"Enable Auto Update? (y/N) [Current: {(SettingsManager.Settings.AutoUpdate ? "Yes" : "No")}]: ");
            var autoUpdateInput = Console.ReadLine();
            var autoUpdate = string.IsNullOrEmpty(autoUpdateInput) ? SettingsManager.Settings.AutoUpdate :
                autoUpdateInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            // Prompt the user to select update channel
            Console.Write($"Update Channel (stable/prerelease) [Current: {SettingsManager.Settings.UpdateChannel}]: ");
            var channelInput = Console.ReadLine()?.ToLowerInvariant();
            var updateChannel = SettingsManager.Settings.UpdateChannel;
            if (!string.IsNullOrEmpty(channelInput))
            {
                if (channelInput is "stable" or "s")
                {
                    updateChannel = UpdateChannel.Stable;
                }
                else if (channelInput is "prerelease" or "pre" or "p")
                {
                    updateChannel = UpdateChannel.Prerelease;
                }
                else
                {
                    Console.WriteLine("Invalid input. Keeping current value.");
                }
            }

            // Update the settings object with the new values
            SettingsManager.Settings = new ApplicationSettings
            {
                DevMode = devMode,
                LogLevel = logLevel,
                LogFormat = logFormat,
                MaxFileSizeMB = maxFileSizeMB,
                MaxRetainedFiles = maxRetainedFiles,
                EnableFileLogging = enableFileLogging,
                EnableCompression = enableCompression,
                IncludeTimestamps = includeTimestamps,
                IncludeThreadId = includeThreadId,
                DateTimeFormat = dateTimeFormat,
                AsyncLogging = asyncLogging,
                AutoUpdate = autoUpdate,
                UpdateChannel = updateChannel
            };

            // Save the updated settings to the configuration file
            SettingsManager.SaveSettings();

            // Log the successful update of settings
            Logger.Log(LogLevel.Info, "Settings updated successfully.");

            Console.WriteLine("\nSettings updated successfully!");
            Console.WriteLine("\nNew Configuration:");
            Console.WriteLine($"  Dev Mode: {(SettingsManager.Settings.DevMode ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Log Level: {SettingsManager.Settings.LogLevel}");
            Console.WriteLine($"  Log Format: {SettingsManager.Settings.LogFormat}");
            Console.WriteLine($"  Max File Size: {SettingsManager.Settings.MaxFileSizeMB} MB");
            Console.WriteLine($"  Max Retained Files: {SettingsManager.Settings.MaxRetainedFiles}");
            Console.WriteLine($"  File Logging: {(SettingsManager.Settings.EnableFileLogging ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Compression: {(SettingsManager.Settings.EnableCompression ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Include Timestamps: {(SettingsManager.Settings.IncludeTimestamps ? "Yes" : "No")}");
            Console.WriteLine($"  Include Thread ID: {(SettingsManager.Settings.IncludeThreadId ? "Yes" : "No")}");
            Console.WriteLine($"  Date/Time Format: {SettingsManager.Settings.DateTimeFormat}");
            Console.WriteLine($"  Async Logging: {(SettingsManager.Settings.AsyncLogging ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Auto Update: {(SettingsManager.Settings.AutoUpdate ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Update Channel: {SettingsManager.Settings.UpdateChannel}");

            Console.Write("\nPress Enter to continue...");
            Console.ReadLine();
        }
    }
}

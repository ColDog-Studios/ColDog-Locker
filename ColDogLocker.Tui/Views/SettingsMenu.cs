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
            Console.Write($"Minimum Log Level (Debug/Info/Warning/Error/Fatal) [Current: {SettingsManager.Settings.LogLevel}]: ");
            var logLevelInput = Console.ReadLine();
            var logLevel = string.IsNullOrWhiteSpace(logLevelInput) ? SettingsManager.Settings.LogLevel : logLevelInput;

            Console.Write($"Log Format (json/text) [Current: {SettingsManager.Settings.LogFormat}]: ");
            var logFormatInput = Console.ReadLine();
            var logFormat = string.IsNullOrWhiteSpace(logFormatInput) ? SettingsManager.Settings.LogFormat : logFormatInput;

            Console.Write($"Max Log File Size (MB) [Current: {SettingsManager.Settings.MaxFileSizeMb}]: ");
            var maxFileSizeInput = Console.ReadLine();
            var maxFileSizeMb = SettingsManager.Settings.MaxFileSizeMb;
            if (!string.IsNullOrWhiteSpace(maxFileSizeInput) && int.TryParse(maxFileSizeInput, out var parsedSize) && parsedSize > 0)
            {
                maxFileSizeMb = parsedSize;
            }

            Console.Write($"Enable File Logging? (y/N) [Current: {(SettingsManager.Settings.EnableFileLogging ? "Yes" : "No")}] ");
            var enableFileLoggingInput = Console.ReadLine();
            var enableFileLogging = string.IsNullOrWhiteSpace(enableFileLoggingInput)
                ? SettingsManager.Settings.EnableFileLogging
                : enableFileLoggingInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            Console.WriteLine("Log retention is fixed at the active log plus 4 rotated files.");
            Console.WriteLine("Timestamps use UTC ISO-8601. Async logging is always enabled.");
            Console.WriteLine("Thread IDs are included when Dev Mode is enabled.");

            // Prompt the user to enable or disable auto updates
            Console.Write($"Enable Auto Update? (y/N) [Current: {(SettingsManager.Settings.AutoUpdate ? "Yes" : "No")}]: ");
            var autoUpdateInput = Console.ReadLine();
            var autoUpdate = string.IsNullOrEmpty(autoUpdateInput)
                ? SettingsManager.Settings.AutoUpdate
                : autoUpdateInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            // Prompt the user to select update channel
            Console.Write($"Update Channel (stable/unstable) [Current: {SettingsManager.Settings.UpdateChannel}]: ");
            var channelInput = Console.ReadLine()?.ToLowerInvariant();
            var updateChannel = SettingsManager.Settings.UpdateChannel;
            if (!string.IsNullOrEmpty(channelInput))
            {
                if (channelInput is "stable" or "s")
                {
                    updateChannel = UpdateChannel.Stable;
                }
                else if (channelInput is "unstable" or "u" or "prerelease" or "pre" or "p")
                {
                    updateChannel = UpdateChannel.Unstable;
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
                MaxFileSizeMb = maxFileSizeMb,
                EnableFileLogging = enableFileLogging,
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
            Console.WriteLine($"  Max File Size: {SettingsManager.Settings.MaxFileSizeMb} MB");
            Console.WriteLine($"  File Logging: {(SettingsManager.Settings.EnableFileLogging ? "Enabled" : "Disabled")}");
            Console.WriteLine("  Log Retention: Active log plus 4 rotated files");
            Console.WriteLine("  Timestamps: UTC ISO-8601");
            Console.WriteLine("  Async Logging: Enabled");
            Console.WriteLine("  Thread IDs: Enabled with Dev Mode");
            Console.WriteLine($"  Auto Update: {(SettingsManager.Settings.AutoUpdate ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Update Channel: {SettingsManager.Settings.UpdateChannel}");

            Console.Write("\nPress Enter to continue...");
            Console.ReadLine();
        }
    }
}

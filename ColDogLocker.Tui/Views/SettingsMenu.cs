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
            Console.Write($"Enable Debug Mode? (y/N) [Current: {(SettingsManager.Settings.DebugMode ? "Yes" : "No")}]: ");
            var debugModeInput = Console.ReadLine();
            var debugMode = !string.IsNullOrEmpty(debugModeInput) && debugModeInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            // Prompt the user to enter the log retention period in days
            Console.Write($"Log retention period in days [Current: {SettingsManager.Settings.LogRetentionDays}]: ");
            var retentionInput = Console.ReadLine();

            int logRetentionDays = SettingsManager.Settings.LogRetentionDays;
            if (!string.IsNullOrEmpty(retentionInput))
            {
                if (int.TryParse(retentionInput, out int parsedDays) && parsedDays > 0)
                {
                    logRetentionDays = parsedDays;
                }
                else
                {
                    Console.WriteLine("Invalid input. Log retention must be a positive number. Keeping current value.");
                }
            }

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
                if (channelInput == "stable" || channelInput == "s")
                {
                    updateChannel = UpdateChannel.Stable;
                }
                else if (channelInput == "prerelease" || channelInput == "pre" || channelInput == "p")
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
                DebugMode = debugMode,
                LogRetentionDays = logRetentionDays,
                AutoUpdate = autoUpdate,
                UpdateChannel = updateChannel
            };

            // Save the updated settings to the configuration file
            SettingsManager.SaveSettings();

            // Log the successful update of settings
            Logger.AddEntry("Settings updated successfully.", LogLevel.Success);

            Console.WriteLine("\nSettings updated successfully!");
            Console.WriteLine("\nNew Configuration:");
            Console.WriteLine($"  Debug Mode: {(SettingsManager.Settings.DebugMode ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Log Retention: {SettingsManager.Settings.LogRetentionDays} days");
            Console.WriteLine($"  Auto Update: {(SettingsManager.Settings.AutoUpdate ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Update Channel: {SettingsManager.Settings.UpdateChannel}");

            Console.Write("\nPress Enter to continue...");
            Console.ReadLine();
        }
    }
}

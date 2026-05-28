using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Data;
using ColDogStudios.ColDogLocker.Core.Services;
using ColDogStudios.ColDogLocker.Core.Configuration;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Core.Logging;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Services.Startup
{
    public static class Initialization
    {
        public static async Task InitializeAsync()
        {
            // Load settings immediately to ensure logging is configured correctly from the start
            SettingsManager.LoadSettings();

            Logger.Log(LogLevel.Debug, "ColDog Locker initialization started.");

            // Create CDL directories if they do not already exist
            if (!Directory.Exists(Variables.LocalConfig))
            {
                Directory.CreateDirectory(Variables.LocalConfig);
                Logger.Log(LogLevel.Debug, $"Created directory: {Variables.LocalConfig}");
            }

            // Create logs directory if it does not already exist
            if (!Directory.Exists(Path.Combine(Variables.LocalConfig, "logs")))
            {
                Directory.CreateDirectory(Path.Combine(Variables.LocalConfig, "logs"));
                Logger.Log(LogLevel.Debug, $"Created directory: {Path.Combine(Variables.LocalConfig, "logs")}");
            }

            // Initialize database
            LockerRepository.InitializeDatabase();

            // Load lockers
            LockerService.LoadLockers();

            // Initialize file watchers
            FileWatcherManager.OnSettingsFileChanged = SettingsManager.LoadSettings;
            FileWatcherManager.OnLockersFileChanged = LockerService.LoadLockers;
            FileWatcherManager.InitializeWatchers();

            // Check for updates if auto-update is enabled
            if (SettingsManager.Settings.AutoUpdate)
            {
                Logger.Log(LogLevel.Debug, "Auto-update is enabled. Checking for updates.");
                try
                {
                    await UpdateManager.CheckForUpdatesAsync();
                }
                catch
                {
                    // Silently ignore update check failures during initialization
                    Logger.Log(LogLevel.Debug, "Update check failed during initialization.");
                }
            }

            // Log the end of initialization
            Logger.Log(LogLevel.Debug, "Initialization completed.");
        }
    }
}

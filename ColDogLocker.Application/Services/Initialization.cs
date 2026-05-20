using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Data;
using ColDogStudios.ColDogLocker.Infrastructure.FileSystem;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Application.Services
{
    public static class Initialization
    {
        public static async Task InitializeAsync()
        {
            Logger.Log(LogLevel.Debug, "ColDog Locker initialization started.");

            // Create CDL directories if they do not already exist
            if (!Directory.Exists(Variables.localConfig))
            {
                Directory.CreateDirectory(Variables.localConfig);
                Logger.Log(LogLevel.Debug, $"Created directory: {Variables.localConfig}");
            }

            // Create logs directory if it does not already exist
            if (!Directory.Exists(Path.Combine(Variables.localConfig, "logs")))
            {
                Directory.CreateDirectory(Path.Combine(Variables.localConfig, "logs"));
                Logger.Log(LogLevel.Debug, $"Created directory: {Path.Combine(Variables.localConfig, "logs")}");
            }

            // Initialize database
            LockerRepository.InitializeDatabase();

            // Load settings and lockers
            SettingsManager.LoadSettings();
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

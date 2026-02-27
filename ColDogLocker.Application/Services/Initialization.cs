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
            Logger.AddEntry("ColDog Locker initialization started.", LogLevel.Debug);

            // Create CDL directories if they do not already exist
            if (!Directory.Exists(Variables.localConfig))
            {
                Directory.CreateDirectory(Variables.localConfig);
                Logger.AddEntry($"Created directory: {Variables.localConfig}", LogLevel.Debug);
            }

            // Create logs directory if it does not already exist
            if (!Directory.Exists(Path.Combine(Variables.localConfig, "logs")))
            {
                Directory.CreateDirectory(Path.Combine(Variables.localConfig, "logs"));
                Logger.AddEntry($"Created directory: {Path.Combine(Variables.localConfig, "logs")}", LogLevel.Debug);
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
                Logger.AddEntry("Auto-update is enabled. Checking for updates.", LogLevel.Debug);
                try
                {
                    await UpdateManager.CheckForUpdatesAsync();
                }
                catch
                {
                    // Silently ignore update check failures during initialization
                    Logger.AddEntry("Update check failed during initialization.", LogLevel.Debug);
                }
            }

            // Log the end of initialization
            Logger.AddEntry("Initialization completed.", LogLevel.Debug);
        }
    }
}

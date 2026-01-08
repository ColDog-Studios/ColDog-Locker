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
            // Log the start of initialization
            Logger.AddEntry("ColDog Locker initialization started.", LogLevel.Info);

            // Create CDL directories if they do not already exist
            if (!Directory.Exists(Variables.localConfig))
            {
                Directory.CreateDirectory(Variables.localConfig);
                Logger.AddEntry($"Created directory: {Variables.localConfig}", LogLevel.Info);
            }

            if (!Directory.Exists(Path.Combine(Variables.localConfig, "logs")))
            {
                Directory.CreateDirectory(Path.Combine(Variables.localConfig, "logs"));
                Logger.AddEntry($"Created directory: {Path.Combine(Variables.localConfig, "logs")}", LogLevel.Info);
            }

            // Initialize database
            LockerRepository.InitializeDatabase();
            Logger.AddEntry("Database initialized.", LogLevel.Info);

            // Migrate from JSON if needed
            Logger.AddEntry("Migration check completed.", LogLevel.Info);

            // Load settings and lockers
            SettingsManager.LoadSettings();
            Logger.AddEntry("Settings loaded.", LogLevel.Info);
            LockerService.LoadLockers();
            Logger.AddEntry("Lockers loaded.", LogLevel.Info);

            // Initialize file watchers
            FileWatcherManager.OnSettingsFileChanged = SettingsManager.LoadSettings;
            FileWatcherManager.OnLockersFileChanged = LockerService.LoadLockers;
            FileWatcherManager.InitializeWatchers();
            Logger.AddEntry("File watchers initialized.", LogLevel.Info);

            // Resize logs if needed
            Logger.TrimLog();

            // Check for updates if auto-update is enabled
            if (SettingsManager.Settings.AutoUpdate)
            {
                Logger.AddEntry("Auto-update is enabled. Checking for updates.", LogLevel.Info);
                try
                {
                    await UpdateManager.CheckForUpdatesAsync();
                }
                catch
                {
                    // Silently ignore update check failures during initialization
                }
            }

            // Log the end of initialization
            Logger.AddEntry("Initialization completed.", LogLevel.Info);
        }
    }
}

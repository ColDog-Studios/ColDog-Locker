using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Services.FileSystem;
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
            if (!Directory.Exists(AppPaths.LocalConfig))
            {
                Directory.CreateDirectory(AppPaths.LocalConfig);
                Logger.Log(LogLevel.Debug, $"Created directory: {AppPaths.LocalConfig}");
            }

            // Create logs directory if it does not already exist
            var logsDirectoryName = "logs";
            if (Path.IsPathRooted(logsDirectoryName))
            {
                throw new InvalidOperationException("Logs directory name must be a relative path segment.");
            }

            var logsDirectoryPath = Path.Combine(AppPaths.LocalConfig, logsDirectoryName);
            if (!Directory.Exists(logsDirectoryPath))
            {
                Directory.CreateDirectory(logsDirectoryPath);
                Logger.Log(LogLevel.Debug, $"Created directory: {logsDirectoryPath}");
            }

            // Initialize database
            LockerRepository.InitializeDatabase();

            // Load lockers
            LockerService.LoadLockers();

            // Initialize file watchers
            AppFileWatcher.OnSettingsFileChanged = SettingsManager.LoadSettings;
            AppFileWatcher.OnLockersFileChanged = LockerService.LoadLockers;
            AppFileWatcher.Initialize();

            // Check for updates if auto-update is enabled
            if (SettingsManager.Settings.AutoUpdate)
            {
                Logger.Log(LogLevel.Debug, "Auto-update is enabled. Checking for updates.");
                try
                {
                    await UpdateService.CheckForUpdatesAsync();
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

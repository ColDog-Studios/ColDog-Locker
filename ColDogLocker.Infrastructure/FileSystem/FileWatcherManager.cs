using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Infrastructure.FileSystem
{
    public static class FileWatcherManager
    {
        private static FileSystemWatcher? settingsWatcher;
        private static FileSystemWatcher? lockersWatcher;
        private static DateTime lastSettingsReload = DateTime.MinValue;
        private static readonly TimeSpan ReloadCooldown = TimeSpan.FromMilliseconds(500); // Prevent reload spam

        // Delegates for handling file changes (to avoid circular dependencies)
        public static Action? OnSettingsFileChanged { get; set; }
        public static Action? OnLockersFileChanged { get; set; }

        public static void InitializeWatchers()
        {
            try
            {
                // Ensure the directory exists before creating watchers
                if (!Directory.Exists(Variables.localConfig))
                {
                    Directory.CreateDirectory(Variables.localConfig);
                }

                // Initialize settings file watcher
                settingsWatcher = new FileSystemWatcher
                {
                    Path = Variables.localConfig,
                    Filter = "settings.json",
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    IncludeSubdirectories = false,
                    InternalBufferSize = 64 * 1024 // 64 KB buffer size
                };
                settingsWatcher.Changed += OnSettingsChanged;
                settingsWatcher.Created += OnSettingsChanged;
                settingsWatcher.Deleted += OnSettingsChanged;
                settingsWatcher.Renamed += OnSettingsChanged;
                settingsWatcher.Error += OnWatcherError;
                settingsWatcher.EnableRaisingEvents = true;

                // Initialize lockers file watcher
                lockersWatcher = new FileSystemWatcher
                {
                    Path = Variables.localConfig,
                    Filter = "lockers.json",
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    IncludeSubdirectories = false,
                    InternalBufferSize = 64 * 1024 // 64 KB buffer size
                };
                lockersWatcher.Changed += OnLockersChanged;
                lockersWatcher.Created += OnLockersChanged;
                lockersWatcher.Deleted += OnLockersChanged;
                lockersWatcher.Renamed += OnLockersChanged;
                lockersWatcher.Error += OnWatcherError;
                lockersWatcher.EnableRaisingEvents = true;
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to initialize file watchers: {ex.Message}", LogLevel.Error);
            }
        }

        private static void OnSettingsChanged(object sender, FileSystemEventArgs e)
        {
            // Debounce rapid file changes to prevent infinite reload loops
            DateTime now = DateTime.Now;
            if (now - lastSettingsReload < ReloadCooldown)
            {
                return; // Too soon since last reload, skip this one
            }

            lastSettingsReload = now;
            Logger.AddEntry("Settings file changed. Reloading settings.", LogLevel.Info);
            OnSettingsFileChanged?.Invoke();
        }

        private static void OnLockersChanged(object sender, FileSystemEventArgs e)
        {
            Logger.AddEntry("Lockers file changed. Reloading lockers.", LogLevel.Info);
            OnLockersFileChanged?.Invoke();
        }

        private static void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Logger.AddEntry($"File watcher error: {e.GetException().Message}", LogLevel.Error);
        }

        public static void DisposeWatchers()
        {
            try
            {
                settingsWatcher?.Dispose();
                lockersWatcher?.Dispose();
                Logger.AddEntry("File watchers disposed successfully.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Error disposing file watchers: {ex.Message}", LogLevel.Error);
            }
        }
    }
}

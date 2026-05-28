using ColDogStudios.ColDogLocker.Core.Configuration;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Logging;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    public static class FileWatcherManager
    {
        private static FileSystemWatcher? _settingsWatcher;
        private static FileSystemWatcher? _lockersWatcher;
        private static DateTime _lastSettingsReload = DateTime.MinValue;
        private static readonly TimeSpan _reloadCooldown = TimeSpan.FromMilliseconds(500); // Prevent reload spam

        // Delegates for handling file changes (to avoid circular dependencies)
        public static Action? OnSettingsFileChanged { get; set; }
        public static Action? OnLockersFileChanged { get; set; }

        public static void InitializeWatchers()
        {
            try
            {
                Logger.Log(LogLevel.Debug, "Initializing file watchers");

                // Ensure the directory exists before creating watchers
                if (!Directory.Exists(Variables.LocalConfig))
                {
                    Directory.CreateDirectory(Variables.LocalConfig);
                }

                // Initialize settings file watcher
                _settingsWatcher = new FileSystemWatcher
                {
                    Path = Variables.LocalConfig,
                    Filter = "settings.json",
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    IncludeSubdirectories = false,
                    InternalBufferSize = 64 * 1024 // 64 KB buffer size
                };
                _settingsWatcher.Changed += OnSettingsChanged;
                _settingsWatcher.Created += OnSettingsChanged;
                _settingsWatcher.Deleted += OnSettingsChanged;
                _settingsWatcher.Renamed += OnSettingsChanged;
                _settingsWatcher.Error += OnWatcherError;
                _settingsWatcher.EnableRaisingEvents = true;
                Logger.Log(LogLevel.Debug, "Settings file watcher created and enabled");

                // Initialize lockers DB watcher (lockers.db)
                _lockersWatcher = new FileSystemWatcher
                {
                    Path = Variables.LocalConfig,
                    Filter = "lockers.db",
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    IncludeSubdirectories = false,
                    InternalBufferSize = 64 * 1024 // 64 KB buffer size
                };
                _lockersWatcher.Changed += OnLockersChanged;
                _lockersWatcher.Created += OnLockersChanged;
                _lockersWatcher.Deleted += OnLockersChanged;
                _lockersWatcher.Renamed += OnLockersChanged;
                _lockersWatcher.Error += OnWatcherError;
                _lockersWatcher.EnableRaisingEvents = true;
                Logger.Log(LogLevel.Debug, "Lockers DB watcher created and enabled");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to initialize file watchers", ex);
            }
        }

        private static void OnSettingsChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                // If we just saved the settings ourselves, ignore the ensuing file events
                var now = DateTime.UtcNow;
                if (SettingsManager.LastSaveUtc.HasValue && now - SettingsManager.LastSaveUtc.Value < TimeSpan.FromSeconds(2))
                {
                    Logger.Log(LogLevel.Debug, $"Settings change ignored because it matches recent own save for '{e.FullPath}' ({e.ChangeType})");
                    return;
                }

                // Debounce rapid file changes to prevent infinite reload loops
                var localNow = DateTime.Now;
                if (localNow - _lastSettingsReload < _reloadCooldown)
                {
                    Logger.Log(LogLevel.Debug, $"Settings change ignored due to debounce for '{e.FullPath}' ({e.ChangeType})");
                    return; // Too soon since last reload, skip this one
                }

                _lastSettingsReload = localNow;
                Logger.Log(LogLevel.Debug, $"Settings file changed ({e.ChangeType}) for '{e.FullPath}'. Reloading settings");
                OnSettingsFileChanged?.Invoke();
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Exception in OnSettingsChanged", ex);
            }
        }

        private static void OnLockersChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                Logger.Log(LogLevel.Debug, $"Lockers DB changed ({e.ChangeType}) for '{e.FullPath}'. Reloading lockers");
                OnLockersFileChanged?.Invoke();
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Exception in OnLockersChanged", ex);
            }
        }

        private static void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Logger.Log(LogLevel.Error, "File watcher error", e.GetException());
        }

        public static void DisposeWatchers()
        {
            try
            {
                _settingsWatcher?.Dispose();
                _lockersWatcher?.Dispose();
                Logger.Log(LogLevel.Debug, "File watchers disposed successfully");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Error disposing file watchers", ex);
            }
        }
    }
}

using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Infrastructure.FileSystem
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
                // Ensure the directory exists before creating watchers
                if (!Directory.Exists(Variables.localConfig))
                {
                    Directory.CreateDirectory(Variables.localConfig);
                }

                // Initialize settings file watcher
                _settingsWatcher = new FileSystemWatcher
                {
                    Path = Variables.localConfig,
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

                // Initialize lockers file watcher
                _lockersWatcher = new FileSystemWatcher
                {
                    Path = Variables.localConfig,
                    Filter = "lockers.json",
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
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to initialize file watchers: {ex.Message}", LogLevel.Error);
            }
        }

        private static void OnSettingsChanged(object sender, FileSystemEventArgs e)
        {
            // Debounce rapid file changes to prevent infinite reload loops
            var now = DateTime.Now;
            if (now - _lastSettingsReload < _reloadCooldown)
            {
                return; // Too soon since last reload, skip this one
            }

            _lastSettingsReload = now;
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
                _settingsWatcher?.Dispose();
                _lockersWatcher?.Dispose();
                Logger.AddEntry("File watchers disposed successfully.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Error disposing file watchers: {ex.Message}", LogLevel.Error);
            }
        }
    }
}

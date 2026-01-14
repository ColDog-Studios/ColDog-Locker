using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;

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

                // Initialize lockers DB watcher (lockers.db)
                _lockersWatcher = new FileSystemWatcher
                {
                    Path = Variables.localConfig,
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
                Logger.AddEntry("Lockers DB watcher created and enabled.", LogLevel.Debug);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to initialize file watchers: {ex.Message}", LogLevel.Error);
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
                        Logger.AddEntry($"Settings change ignored because it matches recent own save for '{e.FullPath}' ({e.ChangeType})", LogLevel.Debug);
                        return;
                    }

                    // Debounce rapid file changes to prevent infinite reload loops
                    var localNow = DateTime.Now;
                    if (localNow - _lastSettingsReload < _reloadCooldown)
                    {
                        Logger.AddEntry($"Settings change ignored due to debounce for '{e.FullPath}' ({e.ChangeType})", LogLevel.Debug);
                        return; // Too soon since last reload, skip this one
                    }

                    _lastSettingsReload = localNow;
                    Logger.AddEntry($"Settings file changed ({e.ChangeType}) for '{e.FullPath}'. Reloading settings.", LogLevel.Info);
                    OnSettingsFileChanged?.Invoke();
                }
                catch (Exception ex)
                {
                    Logger.AddEntry($"Exception in OnSettingsChanged: {ex.Message}", LogLevel.Error);
                }
        }

        private static void OnLockersChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                Logger.AddEntry($"Lockers DB changed ({e.ChangeType}) for '{e.FullPath}'. Reloading lockers.", LogLevel.Info);
                OnLockersFileChanged?.Invoke();
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Exception in OnLockersChanged: {ex.Message}", LogLevel.Error);
            }
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
                Logger.AddEntry("File watchers disposed successfully.", LogLevel.Debug);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Error disposing file watchers: {ex.Message}", LogLevel.Error);
            }
        }
    }
}

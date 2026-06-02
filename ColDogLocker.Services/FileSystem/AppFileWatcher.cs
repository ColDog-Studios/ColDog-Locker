/*
**  Copyright (C) 2026 ColDog Studios
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  long with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    public static class AppFileWatcher
    {
        private static FileSystemWatcher? _settingsWatcher;
        private static FileSystemWatcher? _lockersWatcher;
        private static DateTime _lastSettingsReload = DateTime.MinValue;
        private static readonly TimeSpan _reloadCooldown = TimeSpan.FromMilliseconds(500); // Prevent reload spam

        // Delegates for handling file changes (to avoid circular dependencies)
        public static Action? OnSettingsFileChanged { get; set; }
        public static Action? OnLockersFileChanged { get; set; }

        public static void Initialize()
        {
            try
            {
                Logger.Log(LogLevel.Debug, "Initializing file watchers");

                // Ensure the directory exists before creating watchers
                if (!Directory.Exists(AppPaths.LocalConfig))
                {
                    Directory.CreateDirectory(AppPaths.LocalConfig);
                }

                // Initialize settings file watcher
                _settingsWatcher = new FileSystemWatcher
                {
                    Path = AppPaths.LocalConfig,
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
                    Path = AppPaths.LocalConfig,
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
            catch (InvalidOperationException ex)
            {
                Logger.Log(LogLevel.Error, "Invalid operation in OnSettingsChanged", ex);
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

        public static void Dispose()
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

using ColDogStudios.ColDogLocker.Utils;

namespace ColDogStudios.ColDogLocker.Core
{
    public static class FileWatchers
    {
        private static FileSystemWatcher? settingsWatcher;
        private static FileSystemWatcher? lockersWatcher;

        public static void InitializeWatchers()
        {
            // Initialize settings file watcher
            settingsWatcher = new FileSystemWatcher
            {
                Path = Path.GetDirectoryName(Variables.localConfig) ?? string.Empty,
                Filter = "settings.json",
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                IncludeSubdirectories = false,
                InternalBufferSize = 64 * 1024 // 64 KB buffer size
            };
            settingsWatcher.Changed += OnSettingsChanged;
            settingsWatcher.Created += OnSettingsChanged;
            settingsWatcher.Deleted += OnSettingsChanged;
            settingsWatcher.Renamed += OnSettingsChanged;
            settingsWatcher.EnableRaisingEvents = true;

            // Initialize lockers file watcher
            lockersWatcher = new FileSystemWatcher
            {
                Path = Path.GetDirectoryName(Variables.localConfig) ?? string.Empty,
                Filter = "lockers.json",
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                IncludeSubdirectories = false,
                InternalBufferSize = 64 * 1024 // 64 KB buffer size
            };
            lockersWatcher.Changed += OnLockersChanged;
            lockersWatcher.Created += OnLockersChanged;
            lockersWatcher.Deleted += OnLockersChanged;
            lockersWatcher.Renamed += OnLockersChanged;
            lockersWatcher.EnableRaisingEvents = true;
        }

        private static void OnSettingsChanged(object sender, FileSystemEventArgs e)
        {
            Logger.AddEntry("Settings file changed. Reloading settings.", LogLevel.Info);
            SettingsManager.LoadSettings();
        }

        private static void OnLockersChanged(object sender, FileSystemEventArgs e)
        {
            Logger.AddEntry("Lockers file changed. Reloading lockers.", LogLevel.Info);
            Locker.LoadLockers();
        }
    }
}

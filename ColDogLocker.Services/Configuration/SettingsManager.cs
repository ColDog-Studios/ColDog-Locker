using System.Diagnostics.CodeAnalysis;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Logging;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Services.Configuration
{
    public static class SettingsManager
    {
        // Path to the settings file
        private static readonly string _settingsFile = Path.Combine(AppPaths.LocalConfig, "settings.json");

        // Timestamp of the last time the application wrote the settings file (UTC).
        // FileWatcherManager uses this to ignore change events caused by our own saves.
        public static DateTime? LastSaveUtc { get; private set; }

        // Property to hold the application settings
        public static ApplicationSettings Settings { get; set; } = new();

        // Load settings from the configuration file
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for settings persistence")]
        public static void LoadSettings()
        {
            var pendingLogs = new List<(LogLevel level, string message)>();

            if (!File.Exists(_settingsFile))
            {
                pendingLogs.Add((LogLevel.Warning, "Settings file not found."));
                InitializeSettings();
                Logger.ReloadConfig();
                foreach (var (level, message) in pendingLogs)
                {
                    Logger.Log(level, message);
                }

                return;
            }

            const int MaxReadAttempts = 6;
            const int ReadDelayMs = 200;
            string? settingsContent = null;

            for (var attempt = 1; attempt <= MaxReadAttempts; attempt++)
            {
                try
                {
                    using var fs = new FileStream(_settingsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    settingsContent = sr.ReadToEnd();
                    break;
                }
                catch (IOException ioEx)
                {
                    pendingLogs.Add((LogLevel.Debug, $"Attempt {attempt}: Unable to read settings file ({ioEx.Message})"));
                    Thread.Sleep(ReadDelayMs);
                }
                catch (Exception ex)
                {
                    Logger.Log(LogLevel.Error, "Unexpected error reading settings file", ex);
                    return;
                }
            }

            if (settingsContent == null)
            {
                Logger.Log(LogLevel.Error, "Failed to read settings after multiple attempts. Skipping reload to avoid data loss");
                return;
            }

            if (string.IsNullOrWhiteSpace(settingsContent))
            {
                pendingLogs.Add((LogLevel.Warning, "Settings file is empty."));
                InitializeSettings();
                Logger.ReloadConfig();
                foreach (var (level, message) in pendingLogs)
                {
                    Logger.Log(level, message);
                }

                return;
            }

            const int MaxParseAttempts = 4;
            const int ParseDelayMs = 250;
            ApplicationSettings? deserializedSettings = null;

            for (var attempt = 1; attempt <= MaxParseAttempts; attempt++)
            {
                try
                {
                    deserializedSettings = JsonConvert.DeserializeObject<ApplicationSettings>(settingsContent);
                    break;
                }
                catch (JsonException jsonEx)
                {
                    pendingLogs.Add((LogLevel.Debug, $"Attempt {attempt}: JSON parse error: {jsonEx.Message}"));
                    Thread.Sleep(ParseDelayMs);
                    try
                    {
                        using var fs = new FileStream(_settingsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        settingsContent = sr.ReadToEnd();
                    }
                    catch (Exception readEx)
                    {
                        pendingLogs.Add((LogLevel.Debug, $"Attempt {attempt}: Re-read failed: {readEx.Message}"));
                    }
                }
            }

            if (deserializedSettings != null)
            {
                Settings = deserializedSettings;
                ValidateSettings();
                Logger.ReloadConfig();
                foreach (var (level, message) in pendingLogs)
                {
                    Logger.Log(level, message);
                }

                Logger.Log(LogLevel.Info, "Settings loaded successfully");
                return;
            }

            Logger.Log(LogLevel.Error, "Settings file appears malformed after retries. Backing up and initializing defaults");
            BackupCorruptedSettings();
            InitializeSettings();
        }

        // Initialize default settings
        private static void InitializeSettings()
        {
            Logger.Log(LogLevel.Info, "Initializing default settings");

            Settings = new ApplicationSettings { DevMode = false, AutoUpdate = true, UpdateChannel = UpdateChannel.Stable };
            SaveSettings();
        }

        // Validate settings and replace null or illegal values with defaults
        private static void ValidateSettings()
        {
            Logger.Log(LogLevel.Debug, "Validating settings");

            if (Settings == null)
            {
                Logger.Log(LogLevel.Warning, "Settings are null. Initializing default settings");
                InitializeSettings();
                return;
            }

            var settingsChanged = false;

            // Additional validation for any string properties that might be added in the future
            // (Currently we don't have any required string properties)

            // Only save if we actually changed something
            if (settingsChanged)
            {
                SaveSettings();
            }

            Logger.Log(LogLevel.Debug, "Settings validated");
        }

        // Save settings to the configuration file
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for settings persistence")]
        public static void SaveSettings()
        {
            try
            {
                // Mark the time we started saving so watchers can ignore the resulting file events.
                LastSaveUtc = DateTime.UtcNow;

                // Ensure the directory exists
                var directory = Path.GetDirectoryName(_settingsFile);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Create a temporary file first to ensure atomic writes
                var tempFile = _settingsFile + ".tmp";
                var jsonContent = JsonConvert.SerializeObject(Settings, Formatting.Indented);

                // Validate the JSON before writing (extra safety check)
                JsonConvert.DeserializeObject<ApplicationSettings>(jsonContent);

                // Write to temporary file first
                File.WriteAllText(tempFile, jsonContent);

                // Atomic replacement - if this fails, original file is still intact
                if (File.Exists(_settingsFile))
                {
                    File.Replace(tempFile, _settingsFile, null);
                }
                else
                {
                    File.Move(tempFile, _settingsFile);
                }

                Logger.Log(LogLevel.Info, "Settings saved successfully.");
            }
            catch (UnauthorizedAccessException ex)
            {
                Logger.Log(LogLevel.Error, "Access denied when saving settings", ex);
                CleanupTempFile();
            }
            catch (DirectoryNotFoundException ex)
            {
                Logger.Log(LogLevel.Error, "Settings directory not found", ex);
                CleanupTempFile();
            }
            catch (JsonException ex)
            {
                Logger.Log(LogLevel.Error, "Failed to serialize settings to JSON", ex);
                CleanupTempFile();
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, $"Error saving settings: {ex.Message}", ex);
                CleanupTempFile();
            }
        }

        // Clean up temporary files if save operation fails
        private static void CleanupTempFile()
        {
            try
            {
                var tempFile = _settingsFile + ".tmp";
                if (File.Exists(tempFile))
                {
                    File.Delete(tempFile);
                    Logger.Log(LogLevel.Debug, "Temporary settings file cleaned up.");
                }
            }
            catch
            {
                // If we can't clean up the temp file, it's not critical
                Logger.Log(LogLevel.Debug, "Failed to clean up temporary settings file.");
            }
        }

        // Backup a corrupted settings file for debugging
        private static void BackupCorruptedSettings()
        {
            try
            {
                if (File.Exists(_settingsFile))
                {
                    var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    var backupDirectory = Path.GetDirectoryName(_settingsFile) ?? AppPaths.LocalConfig;
                    var backupFileName = $"settings_corrupted_{timestamp}.json.bak";
                    var backupFile = Path.Combine(backupDirectory, backupFileName);
                    File.Copy(_settingsFile, backupFile, true);
                    Logger.Log(LogLevel.Info, $"Corrupted settings file backed up to: {backupFile}");
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Failed to backup corrupted settings file: {ex.Message}", ex);
            }
        }
    }

    // Enum for update channel selection
    public enum UpdateChannel
    {
        Stable,
        Unstable
    }

    // Enum for GUI view mode
    public enum GuiViewMode
    {
        Grid,
        List
    }

    // Class to hold application settings
    public class ApplicationSettings
    {
        // General Application Settings

        /// <summary>
        ///     Gets or sets a value indicating whether development mode is enabled (includes source file and line numbers in logs).
        /// </summary>
        public bool DevMode { get; set; }

        // Update Settings

        /// <summary>
        ///     Gets or sets a value indicating whether auto updates are enabled.
        /// </summary>
        public bool AutoUpdate { get; set; } = true;

        /// <summary>
        ///     Gets or sets the update channel (Stable or Unstable).
        /// </summary>
        public UpdateChannel UpdateChannel { get; set; } = UpdateChannel.Stable;

        // Database Maintenance Settings

        /// <summary>
        ///     Gets or sets the number of days between database vacuum operations (0 = disabled).
        /// </summary>
        public int DatabaseVacuumInterval { get; set; } = 30;

        /// <summary>
        ///     Gets or sets the last time the database was vacuumed.
        /// </summary>
        public DateTime? LastDatabaseVacuum { get; set; }

        // Logging Settings (Overhauled)

        /// <summary>
        ///     Gets or sets the minimum log level to record (Debug, Info, Warning, Error, Fatal).
        /// </summary>
        public string LogLevel { get; set; } = "Info";

        /// <summary>
        ///     Gets or sets the log format ("json" or "text").
        /// </summary>
        public string LogFormat { get; set; } = "json";

        /// <summary>
        ///     Gets or sets the maximum log file size in MB before rotation.
        /// </summary>
        public int MaxFileSizeMb { get; set; } = 10;

        /// <summary>
        ///     Gets or sets the number of rotated log files to keep (not counting current).
        /// </summary>
        public int MaxRetainedFiles { get; set; } = 9;

        /// <summary>
        ///     Gets or sets whether file logging is enabled.
        /// </summary>
        public bool EnableFileLogging { get; set; } = true;

        /// <summary>
        ///     Gets or sets whether to compress rotated log files.
        /// </summary>
        public bool EnableCompression { get; set; } = false;

        /// <summary>
        ///     Gets or sets whether to include timestamps in log entries.
        /// </summary>
        public bool IncludeTimestamps { get; set; } = true;

        /// <summary>
        ///     Gets or sets whether to include thread ID in log entries.
        /// </summary>
        public bool IncludeThreadId { get; set; } = false;

        /// <summary>
        ///     Gets or sets the date/time format for timestamps ("UTC" or "Local").
        /// </summary>
        public string DateTimeFormat { get; set; } = "UTC";

        /// <summary>
        ///     Gets or sets whether to enable asynchronous logging.
        /// </summary>
        public bool AsyncLogging { get; set; } = true;

        // GUI Settings

        /// <summary>
        ///     Gets or sets the application theme name.
        /// </summary>
        public string AppTheme { get; set; } = "Auto";

        /// <summary>
        ///     Gets or sets a value indicating whether animations are enabled in the GUI.
        /// </summary>
        public bool EnableAnimations { get; set; } = true;

        /// <summary>
        ///     Gets or sets the default location for new lockers.
        /// </summary>
        public string DefaultLockerLocation { get; set; } = AppPaths.CdlDir;

        /// <summary>
        ///     Gets or sets a value indicating whether the default view is grid (true) or list (false).
        /// </summary>
        public GuiViewMode DefaultGuiViewMode { get; set; } = GuiViewMode.Grid;
    }
}

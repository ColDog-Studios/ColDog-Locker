using System.Diagnostics.CodeAnalysis;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Infrastructure.Configuration
{
    public static class SettingsManager
    {
        // Timestamp of the last time the application wrote the settings file (UTC).
        // FileWatcherManager uses this to ignore change events caused by our own saves.
        public static DateTime? LastSaveUtc { get; private set; }

        // Path to the settings file
        private static readonly string _settingsFile = Path.Combine(Variables.localConfig, "settings.json");

        // Property to hold the application settings
        public static ApplicationSettings Settings { get; set; } = new ApplicationSettings();

        // Load settings from the configuration file
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for settings persistence")]
        public static void LoadSettings()
        {
            Logger.AddEntry("Loading settings.", LogLevel.Info);

            if (!File.Exists(_settingsFile))
            {
                Logger.AddEntry("Settings file not found. Initializing default settings.", LogLevel.Warning);
                InitializeSettings();
                return;
            }

            // Attempt to read the file with retries to handle editor/save race conditions
            const int maxReadAttempts = 6;
            const int readDelayMs = 200; // total ~1.2s worst-case
            string? settingsContent = null;

            for (var attempt = 1; attempt <= maxReadAttempts; attempt++)
            {
                try
                {
                    // Use a FileStream with shared read access to avoid exclusive locks
                    using var fs = new FileStream(_settingsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    settingsContent = sr.ReadToEnd();
                    break; // success
                }
                catch (IOException ioEx)
                {
                    Logger.AddEntry($"Attempt {attempt}: Unable to read settings file ({ioEx.Message}). Retrying...", LogLevel.Debug);
                    Thread.Sleep(readDelayMs);
                    continue;
                }
                catch (Exception ex)
                {
                    Logger.AddEntry($"Unexpected error reading settings file: {ex.Message}", LogLevel.Error);
                    break;
                }
            }

            if (settingsContent == null)
            {
                Logger.AddEntry("Failed to read settings after multiple attempts. Skipping reload to avoid data loss.", LogLevel.Error);
                return;
            }

            // If file is empty, initialize defaults
            if (string.IsNullOrWhiteSpace(settingsContent))
            {
                Logger.AddEntry("Settings file is empty. Initializing default settings.", LogLevel.Warning);
                InitializeSettings();
                return;
            }

            // Try to parse JSON; if parsing fails, retry a few times because editor may be mid-write
            const int maxParseAttempts = 4;
            const int parseDelayMs = 250;
            ApplicationSettings? deserializedSettings = null;

            for (var attempt = 1; attempt <= maxParseAttempts; attempt++)
            {
                try
                {
                    deserializedSettings = JsonConvert.DeserializeObject<ApplicationSettings>(settingsContent);
                    break; // parsed successfully (or null but not throwing)
                }
                catch (JsonException jsonEx)
                {
                    Logger.AddEntry($"Attempt {attempt}: JSON parse error: {jsonEx.Message}. Retrying...", LogLevel.Debug);
                    Thread.Sleep(parseDelayMs);

                    // Re-read file in case it has finished writing
                    try
                    {
                        using var fs = new FileStream(_settingsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        settingsContent = sr.ReadToEnd();
                    }
                    catch (Exception readEx)
                    {
                        Logger.AddEntry($"Attempt {attempt}: Re-read failed: {readEx.Message}", LogLevel.Debug);
                    }
                    continue;
                }
            }

            if (deserializedSettings != null)
            {
                Settings = deserializedSettings;
                ValidateSettings();
                Logger.SetDevMode(Settings.DevMode);
                return;
            }

            // If we reach here, parsing failed or returned null after retries.
            // Back up the problematic file but do not overwrite it immediately to avoid clobbering user edits.
            Logger.AddEntry("Settings file appears malformed after retries. Backing up and initializing defaults.", LogLevel.Error);
            BackupCorruptedSettings();
            InitializeSettings();
        }

        // Initialize default settings
        private static void InitializeSettings()
        {
            Logger.AddEntry("Initializing default settings.", LogLevel.Info);

            Settings = new ApplicationSettings
            {
                DevMode = false,
                AutoUpdate = true,  // Enabled by default
                UpdateChannel = UpdateChannel.Stable  // Default to stable channel
            };
            SaveSettings();
        }

        // Validate settings and replace null or illegal values with defaults
        private static void ValidateSettings()
        {
            Logger.AddEntry("Validating settings.", LogLevel.Info);

            if (Settings == null)
            {
                Logger.AddEntry("Settings are null. Initializing default settings.", LogLevel.Warning);
                InitializeSettings();
                return;
            }

            var settingsChanged = false;

            // No longer validate LogRetentionDays (removed)

            // Additional validation for any string properties that might be added in the future
            // (Currently we don't have any required string properties)

            // Only save if we actually changed something
            if (settingsChanged)
            {
                SaveSettings();
            }
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

                Logger.AddEntry("Settings saved successfully.", LogLevel.Success);
            }
            catch (UnauthorizedAccessException ex)
            {
                Logger.AddEntry($"Access denied when saving settings: {ex.Message}", LogLevel.Error);
                CleanupTempFile();
            }
            catch (DirectoryNotFoundException ex)
            {
                Logger.AddEntry($"Settings directory not found: {ex.Message}", LogLevel.Error);
                CleanupTempFile();
            }
            catch (JsonException ex)
            {
                Logger.AddEntry($"Failed to serialize settings to JSON: {ex.Message}", LogLevel.Error);
                CleanupTempFile();
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Error saving settings: {ex.Message}", LogLevel.Error);
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
                }
            }
            catch
            {
                // If we can't clean up the temp file, it's not critical
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
                    var backupFile = Path.Combine(Variables.localConfig, $"settings_corrupted_{timestamp}.json.bak");
                    File.Copy(_settingsFile, backupFile, true);
                    Logger.AddEntry($"Corrupted settings file backed up to: {backupFile}", LogLevel.Info);
                }
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Failed to backup corrupted settings file: {ex.Message}", LogLevel.Warning);
            }
        }
    }

    // Enum for update channel selection
    public enum UpdateChannel
    {
        Stable,
        Prerelease
    }

    // Class to hold application settings
    public class ApplicationSettings
    {
        // General Application Settings

        /// <summary>
        /// Gets or sets a value indicating whether development mode is enabled (includes source file and line numbers in logs).
        /// </summary>
        public bool DevMode { get; set; }

        // Update Settings

        /// <summary>
        /// Gets or sets a value indicating whether auto updates are enabled.
        /// </summary>
        public bool AutoUpdate { get; set; } = true;

        /// <summary>
        /// Gets or sets the update channel (Stable or Prerelease).
        /// </summary>
        public UpdateChannel UpdateChannel { get; set; } = UpdateChannel.Stable;

        // Database Maintenance Settings

        /// <summary>
        /// Gets or sets the number of days between database vacuum operations (0 = disabled).
        /// </summary>
        public int DatabaseVacuumInterval { get; set; } = 30;

        /// <summary>
        /// Gets or sets the last time the database was vacuumed.
        /// </summary>
        public DateTime? LastDatabaseVacuum { get; set; }

        // Logging Settings (Overhauled)

        /// <summary>
        /// Gets or sets the minimum log level to record (Debug, Info, Warning, Error, Fatal).
        /// </summary>
        public string LogLevel { get; set; } = "Info";

        /// <summary>
        /// Gets or sets the log format ("json" or "text").
        /// </summary>
        public string LogFormat { get; set; } = "json";

        /// <summary>
        /// Gets or sets the maximum log file size in MB before rotation.
        /// </summary>
        public int MaxFileSizeMB { get; set; } = 10;

        /// <summary>
        /// Gets or sets the number of rotated log files to keep (not counting current).
        /// </summary>
        public int MaxRetainedFiles { get; set; } = 9;

        /// <summary>
        /// Gets or sets whether file logging is enabled.
        /// </summary>
        public bool EnableFileLogging { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to compress rotated log files.
        /// </summary>
        public bool EnableCompression { get; set; } = false;

        /// <summary>
        /// Gets or sets whether to include timestamps in log entries.
        /// </summary>
        public bool IncludeTimestamps { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to include thread ID in log entries.
        /// </summary>
        public bool IncludeThreadId { get; set; } = false;

        /// <summary>
        /// Gets or sets the date/time format for timestamps ("UTC" or "Local").
        /// </summary>
        public string DateTimeFormat { get; set; } = "UTC";

        /// <summary>
        /// Gets or sets whether to enable asynchronous logging.
        /// </summary>
        public bool AsyncLogging { get; set; } = true;

        // GUI Settings

        /// <summary>
        /// Gets or sets the application theme name.
        /// </summary>
        public string AppTheme { get; set; } = "Auto";

        /// <summary>
        /// Gets or sets a value indicating whether animations are enabled in the GUI.
        /// </summary>
        public bool EnableAnimations { get; set; } = true;

        /// <summary>
        /// Gets or sets the default location for new lockers.
        /// </summary>
        public string DefaultLockerLocation { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether the default view is grid (true) or list (false).
        /// </summary>
        public bool DefaultViewIsGrid { get; set; } = true;
    }
}

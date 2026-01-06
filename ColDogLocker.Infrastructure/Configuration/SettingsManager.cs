using System.Diagnostics.CodeAnalysis;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Infrastructure.Configuration
{
    public static class SettingsManager
    {
        // Path to the settings file
        private static readonly string settingsFile = Path.Combine(Variables.localConfig, "settings.json");

        // Property to hold the application settings
        public static ApplicationSettings Settings { get; set; } = new ApplicationSettings();

        // Load settings from the configuration file
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for settings persistence")]
        public static void LoadSettings()
        {
            Logger.AddEntry("Loading settings.", LogLevel.Info);

            if (File.Exists(settingsFile))
            {
                try
                {
                    // Read and deserialize the settings file
                    var settingsContent = File.ReadAllText(settingsFile);

                    // Check if the file is empty or just whitespace
                    if (string.IsNullOrWhiteSpace(settingsContent))
                    {
                        Logger.AddEntry("Settings file is empty. Initializing default settings.", LogLevel.Warning);
                        InitializeSettings();
                        return;
                    }

                    var deserializedSettings = JsonConvert.DeserializeObject<ApplicationSettings>(settingsContent);
                    if (deserializedSettings != null)
                    {
                        Settings = deserializedSettings;
                        ValidateSettings();

                        // Update logger with settings
                        Logger.SetDebugMode(Settings.DebugMode);
                    }
                    else
                    {
                        Logger.AddEntry("Settings file contains invalid JSON. Initializing default settings.", LogLevel.Warning);
                        BackupCorruptedSettings();
                        InitializeSettings();
                    }
                }
                catch (JsonException jsonEx)
                {
                    Logger.AddEntry($"Settings file contains malformed JSON: {jsonEx.Message}. Initializing default settings.", LogLevel.Error);
                    BackupCorruptedSettings();
                    InitializeSettings();
                }
                catch (Exception ex)
                {
                    Logger.AddEntry($"Error loading settings: {ex.Message}. Initializing default settings.", LogLevel.Error);
                    BackupCorruptedSettings();
                    InitializeSettings();
                }
            }
            else
            {
                Logger.AddEntry("Settings file not found. Initializing default settings.", LogLevel.Warning);
                InitializeSettings();
            }
        }

        // Initialize default settings
        private static void InitializeSettings()
        {
            Logger.AddEntry("Initializing default settings.", LogLevel.Info);

            Settings = new ApplicationSettings
            {
                DebugMode = false,
                LogRetentionDays = 30, // Keep logs for 30 days by default
                AutoUpdate = false,  // Will be prompted during first run
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

            bool settingsChanged = false;

            // Validate LogRetentionDays with reasonable bounds
            if (Settings.LogRetentionDays <= 0 || Settings.LogRetentionDays > 3650) // Max 10 years
            {
                Logger.AddEntry($"Invalid LogRetentionDays ({Settings.LogRetentionDays}). Setting to default value (30 days).", LogLevel.Warning);
                Settings.LogRetentionDays = 30;
                settingsChanged = true;
            }

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
                // Ensure the directory exists
                var directory = Path.GetDirectoryName(settingsFile);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Create a temporary file first to ensure atomic writes
                var tempFile = settingsFile + ".tmp";
                var jsonContent = JsonConvert.SerializeObject(Settings, Formatting.Indented);

                // Validate the JSON before writing (extra safety check)
                JsonConvert.DeserializeObject<ApplicationSettings>(jsonContent);

                // Write to temporary file first
                File.WriteAllText(tempFile, jsonContent);

                // Atomic replacement - if this fails, original file is still intact
                if (File.Exists(settingsFile))
                {
                    File.Replace(tempFile, settingsFile, null);
                }
                else
                {
                    File.Move(tempFile, settingsFile);
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
                var tempFile = settingsFile + ".tmp";
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
                if (File.Exists(settingsFile))
                {
                    var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    var backupFile = Path.Combine(Variables.localConfig, $"settings_corrupted_{timestamp}.json.bak");
                    File.Copy(settingsFile, backupFile, true);
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
        /// <summary>
        /// Gets or sets a value indicating whether debug mode is enabled.
        /// </summary>
        public bool DebugMode { get; set; }

        /// <summary>
        /// Gets or sets the number of days to retain log files.
        /// </summary>
        public int LogRetentionDays { get; set; } = 30;

        /// <summary>
        /// Gets or sets a value indicating whether auto updates are enabled.
        /// </summary>
        public bool AutoUpdate { get; set; }

        /// <summary>
        /// Gets or sets the number of days between database vacuum operations (0 = disabled).
        /// </summary>
        public int DatabaseVacuumInterval { get; set; } = 30;

        /// <summary>
        /// Gets or sets the last time the database was vacuumed.
        /// </summary>
        public DateTime? LastDatabaseVacuum { get; set; }

        /// <summary>
        /// Gets or sets the update channel (Stable or Prerelease).
        /// </summary>
        public UpdateChannel UpdateChannel { get; set; } = UpdateChannel.Stable;
    }
}

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

using System.Diagnostics.CodeAnalysis;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Logging;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Services.Configuration
{
    public static class SettingsManager
    {
        // Path to the settings file
        private static readonly string _settingsFile = Path.Join(AppPaths.LocalConfig, "settings.json");

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
                catch (Exception ex) when (ex is UnauthorizedAccessException or NotSupportedException or ArgumentException or System.Security.SecurityException)
                {
                    Logger.Log(LogLevel.Error, "Unexpected error reading settings file", ex);
                    return;
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
                if (!string.IsNullOrEmpty(directory))
                {
                    AppFilePermissions.EnsurePrivateDirectory(directory);
                }

                // Create a temporary file first to ensure atomic writes
                var tempFile = _settingsFile + ".tmp";
                var jsonContent = JsonConvert.SerializeObject(Settings, Formatting.Indented);

                // Validate the JSON before writing (extra safety check)
                JsonConvert.DeserializeObject<ApplicationSettings>(jsonContent);

                // Write to temporary file first
                File.WriteAllText(tempFile, jsonContent);
                AppFilePermissions.ApplyPrivateFile(tempFile);

                const int MaxWriteAttempts = 5;
                const int WriteDelayMs = 100;

                for (var attempt = 1; attempt <= MaxWriteAttempts; attempt++)
                {
                    try
                    {
                        File.Move(tempFile, _settingsFile, true);
                        AppFilePermissions.ApplyPrivateFile(_settingsFile);
                        break;
                    }
                    catch (Exception ex) when (attempt < MaxWriteAttempts && ex is IOException or UnauthorizedAccessException)
                    {
                        Thread.Sleep(WriteDelayMs);
                    }
                    catch (Exception) when (attempt < MaxWriteAttempts)
                    {
                        Thread.Sleep(WriteDelayMs);
                    }
                }

                Logger.Log(LogLevel.Info, "Settings saved successfully.");
            }
            catch (UnauthorizedAccessException ex)
            {
                Logger.Log(LogLevel.Error, "Access denied when saving settings", ex);
                CleanupTempFile();
                throw;
            }
            catch (DirectoryNotFoundException ex)
            {
                Logger.Log(LogLevel.Error, "Settings directory not found", ex);
                CleanupTempFile();
                throw;
            }
            catch (JsonException ex)
            {
                Logger.Log(LogLevel.Error, "Failed to serialize settings to JSON", ex);
                CleanupTempFile();
                throw;
            }
            catch (Exception ex) when (ex is IOException or NotSupportedException or ArgumentException or System.Security.SecurityException)
            {
                Logger.Log(LogLevel.Error, $"Error saving settings: {ex.Message}", ex);
                CleanupTempFile();
                throw;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, $"Error saving settings: {ex.Message}", ex);
                CleanupTempFile();
                throw;
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
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException or ArgumentException)
            {
                // If we can't clean up the temp file, it's not critical
                Logger.Log(LogLevel.Debug, "Failed to clean up temporary settings file.", ex);
            }
            catch (Exception ex)
            {
                // If we can't clean up the temp file, it's not critical
                Logger.Log(LogLevel.Debug, "Failed to clean up temporary settings file.", ex);
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
                    var backupFile = Path.Join(backupDirectory, backupFileName);
                    File.Copy(_settingsFile, backupFile, true);
                    AppFilePermissions.ApplyPrivateFile(backupFile);
                    Logger.Log(LogLevel.Info, $"Corrupted settings file backed up to: {backupFile}");
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException or NotSupportedException or ArgumentException)
            {
                Logger.Log(LogLevel.Warning, $"Failed to backup corrupted settings file: {ex.Message}", ex);
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
        ///     Gets or sets whether file logging is enabled.
        /// </summary>
        public bool EnableFileLogging { get; set; } = true;

        // GUI Settings

        /// <summary>
        ///     Gets or sets the application theme name.
        /// </summary>
        public string AppTheme { get; set; } = "Auto";

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

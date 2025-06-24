using ColDogStudios.ColDogLocker.Menu;
using ColDogStudios.ColDogLocker.Utils;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Core
{
    public static class SettingsManager
    {
        // Path to the settings file
        private static readonly string settingsFile = Path.Combine(Variables.localConfig, "settings.json");

        // Property to hold the application settings
        public static ApplicationSettings Settings { get; private set; } = new ApplicationSettings();

        // Load settings from the configuration file
        public static void LoadSettings()
        {
            Logger.AddEntry("Loading settings.", LogLevel.Info);

            if (File.Exists(settingsFile))
            {
                try
                {
                    // Read and deserialize the settings file
                    var settingsContent = File.ReadAllText(settingsFile);
                    var deserializedSettings = JsonConvert.DeserializeObject<ApplicationSettings>(settingsContent);
                    if (deserializedSettings != null)
                    {
                        Settings = deserializedSettings;
                        ValidateSettings();
                    }
                    else
                    {
                        Logger.AddEntry("Settings file is empty or invalid. Initializing default settings.", LogLevel.Warning);
                        InitializeSettings();
                    }
                }
                catch (Exception ex)
                {
                    Logger.AddEntry($"Error loading settings: {ex.Message}. Initializing default settings.", LogLevel.Error);
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
                MaxLogSize = 1048576, // 1MB
                AutoUpdate = PromptForAutoUpdate()
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

            if (Settings.MaxLogSize <= 0)
            {
                Logger.AddEntry("Invalid MaxLogSize. Setting to default value (1MB).", LogLevel.Warning);
                Settings.MaxLogSize = 1048576; // 1MB
            }

            if (Settings.DebugMode != true && Settings.DebugMode != false)
            {
                Logger.AddEntry("Invalid DebugMode. Setting to default value (false).", LogLevel.Warning);
                Settings.DebugMode = false;
            }

            if (Settings.AutoUpdate != true && Settings.AutoUpdate != false)
            {
                Logger.AddEntry("Invalid AutoUpdate. Prompting user for value.", LogLevel.Warning);
                Settings.AutoUpdate = PromptForAutoUpdate();
            }

            SaveSettings();
        }

        // Save settings to the configuration file
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

                File.WriteAllText(settingsFile, JsonConvert.SerializeObject(Settings, Formatting.Indented));
                Logger.AddEntry("Settings saved successfully.", LogLevel.Success);
            }
            catch (UnauthorizedAccessException ex)
            {
                Logger.AddEntry($"Access denied when saving settings: {ex.Message}", LogLevel.Error);
            }
            catch (DirectoryNotFoundException ex)
            {
                Logger.AddEntry($"Settings directory not found: {ex.Message}", LogLevel.Error);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Error saving settings: {ex.Message}", LogLevel.Error);
            }
        }

        // Update settings based on user input
        public static void UpdateSettings()
        {
            // Show Settings Menu
            MainMenu.MenuTitle("Main Menu > Settings");

            // Prompt the user to enable or disable debug mode
            Console.Write("Enable Debug Mode? (y/N): ");
            var debugModeInput = Console.ReadLine();
            var debugMode = debugModeInput != null && debugModeInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            // Prompt the user to enter the maximum log file size in MB
            Console.Write("Enter the maximum log file size in MB: ");
            var maxLogSizeInput = Console.ReadLine();

            // Validate the input and convert it to bytes
            if (string.IsNullOrEmpty(maxLogSizeInput) || !int.TryParse(maxLogSizeInput, out _))
            {
                Console.WriteLine("Invalid input. Setting maximum log size to default (1MB).");
                maxLogSizeInput = "1"; // Default to 1MB if input is invalid
            }
            else if (int.Parse(maxLogSizeInput) <= 0)
            {
                Console.WriteLine("Maximum log size must be greater than 0. Setting to default (1MB).");
                maxLogSizeInput = "1"; // Default to 1MB if input is less than or equal to 0
            }
            
            var maxLogSize = maxLogSizeInput != null ? int.Parse(maxLogSizeInput) * 1048576 : 1048576; // Convert MB to bytes

            // Prompt the user to enable or disable auto updates
            Console.Write("Enable Auto Update? (y/N): ");
            var autoUpdateInput = Console.ReadLine();
            var autoUpdate = autoUpdateInput != null && autoUpdateInput.Equals("y", StringComparison.OrdinalIgnoreCase);

            // Update the settings object with the new values
            Settings = new ApplicationSettings
            {
                DebugMode = debugMode,
                MaxLogSize = maxLogSize,
                AutoUpdate = autoUpdate
            };

            // Save the updated settings to the configuration file
            SaveSettings();

            // Log the successful update of settings
            Logger.AddEntry("Settings updated successfully.", LogLevel.Success);
            Console.Write("\nSettings updated successfully.");
            Console.ReadLine();
        }

        // Prompt the user to enable auto updates
        private static bool PromptForAutoUpdate()
        {
            // Show Settings Menu
            MainMenu.MenuTitle("Main Menu > Settings");

            Console.Write("Enable Auto Update? (y/N): ");
            var autoUpdateInput = Console.ReadLine();
            return autoUpdateInput != null && autoUpdateInput.Equals("y", StringComparison.OrdinalIgnoreCase);
        }
    }

    // Class to hold application settings
    public class ApplicationSettings
    {
        /// <summary>
        /// Gets or sets a value indicating whether debug mode is enabled.
        /// </summary>
        public bool DebugMode { get; set; }

        /// <summary>
        /// Gets or sets the maximum log file size in bytes.
        /// </summary>
        public int MaxLogSize { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether auto updates are enabled.
        /// </summary>
        public bool AutoUpdate { get; set; }
    }
}

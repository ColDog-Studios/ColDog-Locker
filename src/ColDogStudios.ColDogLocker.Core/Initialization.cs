using ColDogStudios.ColDogLocker.Core.Utils;
using ColDogStudios.ColDogLocker.Core.Services;

namespace ColDogStudios.ColDogLocker.Core
{
    public static class Initialization
    {
        public static async Task InitializeAsync()
        {
            try
            {
                // Create necessary directories
                CreateDirectories();

                // Initialize logging
                Logger.AddEntry("Application starting up", LogLevel.Info);

                // Load locker metadata
                LockerService.LoadLockers();

                // Clean up old logs
                Logger.TrimLog();

                Logger.AddEntry("Application initialization completed", LogLevel.Success);
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Error during initialization: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        private static void CreateDirectories()
        {
            try
            {
                // Create local config directory
                if (!Directory.Exists(Variables.LocalConfig))
                {
                    Directory.CreateDirectory(Variables.LocalConfig);
                    Logger.AddEntry($"Created local config directory: {Variables.LocalConfig}", LogLevel.Info);
                }

                // Create ColDog Locker directory
                if (!Directory.Exists(Variables.CdlDir))
                {
                    Directory.CreateDirectory(Variables.CdlDir);
                    Logger.AddEntry($"Created ColDog Locker directory: {Variables.CdlDir}", LogLevel.Info);
                }
            }
            catch (Exception ex)
            {
                Logger.AddEntry($"Error creating directories: {ex.Message}", LogLevel.Error);
                throw;
            }
        }
    }
}

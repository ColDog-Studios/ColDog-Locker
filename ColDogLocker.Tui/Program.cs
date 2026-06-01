using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Services.Updates;
using ColDogStudios.ColDogLocker.Tui.Views;

namespace ColDogStudios.ColDogLocker.Tui
{
    /// <summary>
    ///     Entry point for the TUI (Terminal User Interface) application.
    ///     This class is invoked by ColDogLocker.Cli when launching the terminal interface.
    /// </summary>
    public static class TuiLauncher
    {
        /// <summary>
        ///     Launches the TUI application.
        /// </summary>
        /// <returns>Exit code (0 for success, non-zero for error)</returns>
        public static int Launch()
        {
            try
            {
                Logger.Log(LogLevel.Debug, "Launching ColDog Locker TUI");

                // Set up the UpdateService menu title delegate
                UpdateService.ShowMenuTitle = MainMenu.MenuTitle;

                // Show the main menu (TUI)
                MainMenu.MenuOptions().GetAwaiter().GetResult();

                return 0;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"Error: {ex.Message}");
                Console.ResetColor();
                Logger.Log(LogLevel.Fatal, "Unhandled exception in TUI", ex);
                return 1;
            }
        }
    }
}

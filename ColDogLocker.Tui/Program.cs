using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Tui.Views;

namespace ColDogStudios.ColDogLocker.Tui;

/// <summary>
/// Entry point for the TUI (Terminal User Interface) application.
/// This class is invoked by ColDogLocker.Cli when launching the terminal interface.
/// </summary>
public static class TuiLauncher
{
    /// <summary>
    /// Launches the TUI application.
    /// </summary>
    /// <returns>Exit code (0 for success, non-zero for error)</returns>
    public static int Launch()
    {
        try
        {
            // Initialize the application
            Initialization.InitializeAsync().GetAwaiter().GetResult();

            // Set up the UpdateManager menu title delegate
            UpdateManager.ShowMenuTitle = MainMenu.MenuTitle;

            // Show the main menu (TUI)
            MainMenu.MenuOptions().GetAwaiter().GetResult();

            return 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine($"Error: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }
}

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

using ColDogStudios.ColDogLocker.Services.Logging;
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

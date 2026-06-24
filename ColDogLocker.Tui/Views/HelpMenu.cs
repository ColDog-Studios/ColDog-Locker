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

namespace ColDogStudios.ColDogLocker.Tui.Views
{
    public static class HelpMenu
    {
        /// <summary>
        ///     Displays the "Help" information for ColDog Locker.
        /// </summary>
        public static void Show()
        {
            MainMenu.MenuTitle("Main Menu > Help");

            Console.WriteLine(
                "\nColDog Locker is a simple file locker that allows you to encrypt and decrypt the contents of a 'managed' directory with a password.\n");
            Console.WriteLine("To lock a directory, select the 'Lock Locker' option from the main menu and follow the prompts.");
            Console.WriteLine("To unlock a directory, select the 'Unlock Locker' option from the main menu and follow the prompts.");
            Console.WriteLine(
                "To remove a directory from ColDog Locker management, select the 'Remove Locker' option from the main menu and follow the prompts.");
            Console.WriteLine("To check for updates, select the 'Check for Updates' option from the main menu.\n");
            Console.WriteLine("Help! I get stuck in loops and I dont know how to get out!\n");
            Console.WriteLine(
                "To get out of any loops, press (CTRL + C), or click the 'X' in the top right of the window to close the program, then relaunch.");
            Console.WriteLine("Report any bugs to ColDog Studios.");
            Console.ReadLine();
        }
    }
}

/*
** Copyright (C) 2026 ColDog Studios
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

            Console.WriteLine("\nColDog Locker is a simple file locker that allows you to encrypt and decrypt the contents of a 'managed' directory with a password.\n");
            Console.WriteLine("To lock a directory, select the 'Lock Locker' option from the main menu and follow the prompts.");
            Console.WriteLine("To unlock a directory, select the 'Unlock Locker' option from the main menu and follow the prompts.");
            Console.WriteLine("To remove a directory from ColDog Locker management, select the 'Remove Locker' option from the main menu and follow the prompts.");
            Console.WriteLine("To check for updates, select the 'Check for Updates' option from the main menu.\n");
            Console.WriteLine("Help! I get stuck in loops and I dont know how to get out!\n");
            Console.WriteLine("To get out of any loops, press (CTRL + C), or click the 'X' in the top right of the window to close the program, then relaunch.");
            Console.WriteLine("Report any bugs to ColDog Studios.");
            Console.ReadLine();
        }
    }
}
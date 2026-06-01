/*
** Copyright (C) 2026 ColDog Studios
*/

namespace ColDogStudios.ColDogLocker.Tui.Views
{
    public static class AboutMenu
    {
        /// <summary>
        ///     Displays the "About" information for ColDog Locker.
        /// </summary>
        public static void Show()
        {
            MainMenu.MenuTitle("Main Menu > About");

            Console.Write("\nThe idea of ColDog Locker was created by Collin 'ColDog' Laney on 11/17/21,\n" +
                          "for a security project in Cybersecurity class.\n" +
                          "Collin Laney is the Founder and CEO of ColDog Studios.");
            Console.ReadLine();
        }
    }
}
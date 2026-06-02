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
            Console.WriteLine("\n\nColDog Locker is a free and open-source project licensed under the GNU General Public License v3.0.");
            Console.ReadLine();
        }
    }
}
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

using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Tui.Views
{
    public static class MainMenu
    {
        public static async Task MenuOptions()
        {
            while (true)
            {
                Console.Clear();
                MenuTitle("Main Menu");

                Console.WriteLine("Choose an option from the following:\n");

                Console.WriteLine(" 1) New Locker");
                Console.WriteLine(" 2) Remove Locker");
                Console.WriteLine(" 3) Lock Locker");
                Console.WriteLine(" 4) Unlock Locker");
                Console.WriteLine(" 5) About ColDog Locker");
                Console.WriteLine(" 6) ColDog Locker Help");
                Console.WriteLine(" 7) Check for Updates");
                Console.WriteLine(" 9) Update ColDog Locker Settings\n");
                Console.WriteLine(" 0) Exit\n");
                Console.Write("> ");

                var choice = Console.ReadLine()?.ToLower();

                switch (choice)
                {
                    case "1":
                        LockerMenu.NewLocker();
                        break;
                    case "2":
                        LockerMenu.RemoveLocker();
                        break;
                    case "3":
                        LockerMenu.Lock();
                        break;
                    case "4":
                        LockerMenu.Unlock();
                        break;
                    case "5":
                        AboutMenu.Show();
                        break;
                    case "6":
                        HelpMenu.Show();
                        break;
                    case "7":
                        await CheckForUpdates();
                        break;
                    case "9":
                        SettingsMenu.UpdateSettings();
                        break;
                    case "0":
                        return;
                    case "dev":
                        DevMenu.Show();
                        break;
                    default:
                        Console.Write("\nInvalid choice. Please try again.");
                        Console.ReadLine();
                        break;
                }
            }
        }

        public static void MenuTitle(string subMenu)
        {
            Console.Clear();
            var width = Console.WindowWidth;
            var title = $"ColDog Locker {AppInfo.SemanticVersion}";
            var copyright = "Copyright (c) ColDog Studios.";
            var license = "Licensed under the GNU General Public License v3.0.";
            string line = new('#', width);
            var separatorLength = width / 2;
            string separator = new('-', separatorLength);
            string emptyLine = new(' ', width);

            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(line);
            Console.WriteLine(emptyLine);
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(title.PadLeft((width + title.Length) / 2).PadRight(width));
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(subMenu.PadLeft((width + subMenu.Length) / 2).PadRight(width));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(separator.PadLeft((width + separator.Length) / 2).PadRight(width));
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(copyright.PadLeft((width + copyright.Length) / 2).PadRight(width));
            Console.WriteLine(license.PadLeft((width + license.Length) / 2).PadRight(width));
            Console.WriteLine(emptyLine);
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(line);
            Console.WriteLine(emptyLine);
            Console.ResetColor();
        }

        private static async Task CheckForUpdates()
        {
            MenuTitle("Main Menu > Check for Updates");

            try
            {
                var result = await UpdateService.CheckForUpdatesAsync();

                if (result.UpdateAvailable)
                {
                    Console.WriteLine("\nA newer version is available:\n");
                    Console.WriteLine($"Current Version: {result.CurrentVersion}");
                    Console.WriteLine($"Latest Version: {result.LatestVersion}\n");

                    if (!string.IsNullOrWhiteSpace(result.ReleaseNotesMarkdown))
                    {
                        Console.WriteLine("Release Notes:");
                        Console.WriteLine(result.ReleaseNotesMarkdown.Trim());
                        Console.WriteLine();
                    }

                    if (!result.CanDownload)
                    {
                        Console.WriteLine(result.UserMessage ?? "This update cannot be downloaded automatically.");
                        if (!string.IsNullOrWhiteSpace(result.ManualUpdateInstructions))
                        {
                            Console.WriteLine(result.ManualUpdateInstructions);
                        }

                        if (!string.IsNullOrWhiteSpace(result.ReleaseUrl))
                        {
                            Console.WriteLine($"Release: {result.ReleaseUrl}");
                        }

                        Console.WriteLine("\nPress any key to continue...");
                        Console.ReadKey();
                        return;
                    }

                    Console.Write("Do you want to download the latest version? (y/N): ");

                    var response = Console.ReadLine()?.ToLower();
                    if (response == "y")
                    {
                        try
                        {
                            var filePath = await UpdateService.DownloadUpdateAsync(result);
                            Console.WriteLine($"\nDownloaded the latest version to: {filePath}");
                            Console.WriteLine("Please run the installer to update ColDog Locker.");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"\nError downloading update: {ex.Message}");
                        }
                    }
                    else
                    {
                        Console.WriteLine("\nUpdate cancelled.");
                    }
                }
                else
                {
                    Console.WriteLine("\nColDog Locker is up to date:\n");
                    Console.WriteLine($"Current Version: {result.CurrentVersion}");
                    Console.WriteLine($"Latest Version: {result.LatestVersion}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn error occurred while checking for updates: {ex.Message}");
            }

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }
    }
}

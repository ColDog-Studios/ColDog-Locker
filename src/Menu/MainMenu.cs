using ColDogStudios.ColDogLocker.Core;

namespace ColDogStudios.ColDogLocker.Menu
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
                        AboutHelpDev.ShowAbout();
                        break;
                    case "6":
                        AboutHelpDev.ShowHelp();
                        break;
                    case "7":
                        await UpdateManager.CheckForUpdatesAsync(false);
                        break;
                    case "9":
                        SettingsManager.UpdateSettings();
                        break;
                    case "0":
                        return;
                    case "dev":
                        AboutHelpDev.ShowDev();
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
            int width = Console.WindowWidth;
            string title = $"ColDog Locker {Variables.version}";
            string copyright = "Copyright (c) ColDog Studios. All Rights Reserved.";
            string line = new('#', width);
            int separatorLength = width / 2;
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
            Console.WriteLine(emptyLine);
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(line);
            Console.WriteLine(emptyLine);
            Console.ResetColor();
        }
    }
}

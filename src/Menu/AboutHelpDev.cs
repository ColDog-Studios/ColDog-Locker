using ColDogStudios.ColDogLocker.Core;

namespace ColDogStudios.ColDogLocker.Menu
{
    public static class AboutHelpDev
    {
        public static void ShowAbout()
        {
            MainMenu.MenuTitle("Main Menu > About");

            Console.Write("\nThe idea of ColDog Locker was created by Collin 'ColDog' Laney on 11/17/21,\n" +
                          "for a security project in Cybersecurity class.\n" +
                          "Collin Laney is the Founder and CEO of ColDog Studios.");
            Console.ReadLine();
        }

        public static void ShowHelp()
        {
            MainMenu.MenuTitle("Main Menu > Help");

            Console.WriteLine("\nColDog Locker is a simple file locker that allows you to encrypt and decrypt the contents of a 'managed' directory with a password.\n");
            Console.WriteLine("To lock a directory, select the 'Lock Locker' option from the main menu and follow the prompts.");
            Console.WriteLine("To unlock a directory, select the 'Unlock Locker' option from the main menu and follow the prompts.");
            Console.WriteLine("To remove a directory from ColDog Locker management, select the 'Remove Locker' option from the main menu and follow the prompts.");
            Console.WriteLine("To check for updates, select the 'Check for Updates' option from the main menu.\n");
            Console.WriteLine("Help! I get stuck in loops and I dont know how to get out!\n");
            Console.WriteLine("To get out of any loops, press (CTRL + C), or click the 'X' in the top right of the window to close the program, then relaunch. " +
                              "Report any bugs to ColDog Studios.");
            Console.ReadLine();
        }

        public static void ShowDev()
        {
            MainMenu.MenuTitle("Main Menu > Dev");

            Console.WriteLine($"\nVersion: {Variables.version}");
            Console.WriteLine($"Build Version: {Variables.buildVersion}");
            Console.WriteLine($"Build Number: {Variables.buildNumber}");
            Console.WriteLine($"Build Date: {Variables.buildDate}");
            Console.WriteLine($"\nMetadata Location: {Variables.localConfig}");
            Console.Write($"Current Directory: {Variables.cdlDir}");
            Console.ReadLine();
        }
    }
}

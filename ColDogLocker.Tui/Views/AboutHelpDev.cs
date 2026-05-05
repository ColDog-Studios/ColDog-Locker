using ColDogStudios.ColDogLocker.Core.Constants;
using System.Runtime.InteropServices;

namespace ColDogStudios.ColDogLocker.Tui.Views
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
            Console.WriteLine("To get out of any loops, press (CTRL + C), or click the 'X' in the top right of the window to close the program, then relaunch.");
            Console.WriteLine("Report any bugs to ColDog Studios.");
            Console.ReadLine();
        }

        public static void ShowDev()
        {
            MainMenu.MenuTitle("Main Menu > Dev");

            Console.WriteLine($"ColDog Locker {BuildInfo.Version}");
            Console.WriteLine($"Build Version: {BuildInfo.BuildVersion}");
            Console.WriteLine($"Build Date: {BuildInfo.BuildDate}");
            Console.WriteLine($"Build Time: {BuildInfo.BuildTime}");

            Console.WriteLine($"\nEnvironment: {Environment.OSVersion.Platform}");
            Console.WriteLine($"Architecture: {RuntimeInformation.ProcessArchitecture}");
            Console.WriteLine($"Runtime Identifier: {RuntimeInformation.RuntimeIdentifier}");
            Console.WriteLine($"Framework: {RuntimeInformation.FrameworkDescription}");
        #if DEBUG
            Console.WriteLine("Build: DEBUG");
        #else
            Console.WriteLine("Build: RELEASE");
        #endif
        
            Console.WriteLine($"\nUser: {Environment.UserName}");
        
            Console.WriteLine($"\nLocal Config Location: {Variables.localConfig}");
            Console.WriteLine($"Current Directory: {Variables.cdlDir}");
            var logPath = Path.Combine(Variables.localConfig, "logs");
            Console.WriteLine($"Log Directory: {logPath}");
            Console.WriteLine($"Log Directory Exists: {Directory.Exists(logPath)}");
        
            var configDrive = new DriveInfo(new DirectoryInfo(Variables.localConfig).Root.Name);
            Console.WriteLine($"\nAvailable Disk Space: {configDrive.AvailableFreeSpace / (1024 * 1024 * 1024)} GB");
            Console.WriteLine($"Process Memory: {GC.GetTotalMemory(false) / 1024} KB");
            Console.ReadLine();
        }
    }
}

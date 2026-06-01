/*
** Copyright (C) 2026 ColDog Studios
*/

using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Core.Environment;

namespace ColDogStudios.ColDogLocker.Tui.Views
{
    public static class DevMenu
    {
        /// <summary>
        ///     Displays the "Dev" information for ColDog Locker, including build and environment details.
        /// </summary>
        public static void Show()
        {
            MainMenu.MenuTitle("Main Menu > Dev");

            Console.WriteLine($"ColDog Locker {AppInfo.SemanticVersion}");
            Console.WriteLine($"Build Version: {AppInfo.BuildVersion}");
            Console.WriteLine($"Build Date: {AppInfo.BuildDate}");
            Console.WriteLine($"Build Time: {AppInfo.BuildTime}");

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

            Console.WriteLine($"\nLocal Config Location: {AppPaths.LocalConfig}");
            Console.WriteLine($"Current Directory: {AppPaths.CdlDir}");
            var logPath = Path.Combine(AppPaths.LocalConfig, "logs");
            Console.WriteLine($"Log Directory: {logPath}");
            Console.WriteLine($"Log Directory Exists: {Directory.Exists(logPath)}");

            var configDrive = new DriveInfo(new DirectoryInfo(AppPaths.LocalConfig).Root.Name);
            Console.WriteLine($"\nAvailable Disk Space: {configDrive.AvailableFreeSpace / (1024 * 1024 * 1024)} GB");
            Console.WriteLine($"Process Memory: {GC.GetTotalMemory(false) / 1024} KB");
            Console.ReadLine();
        }
    }
}
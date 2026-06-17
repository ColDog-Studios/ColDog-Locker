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

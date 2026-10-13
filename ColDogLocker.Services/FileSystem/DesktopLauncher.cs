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

using System.Diagnostics;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>Shared local-folder launcher for GUI and CLI. Paths are passed as individual arguments.</summary>
    public static class DesktopLauncher
    {
        public static void OpenFolder(string path)
        {
            var fullPath = Path.GetFullPath(path);
            if (!Directory.Exists(fullPath))
            {
                throw new DirectoryNotFoundException($"Directory not found: {fullPath}");
            }

            var start = new ProcessStartInfo { UseShellExecute = false };
            if (OperatingSystem.IsWindows())
            {
                start.FileName = "explorer.exe";
            }
            else if (OperatingSystem.IsMacOS())
            {
                start.FileName = "open";
            }
            else if (OperatingSystem.IsLinux())
            {
                start.FileName = "xdg-open";
            }
            else
            {
                throw new PlatformNotSupportedException("No desktop file manager is available.");
            }

            start.ArgumentList.Add(fullPath);
            start.RedirectStandardError = OperatingSystem.IsLinux();
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to open the file manager.");
            if (OperatingSystem.IsLinux() && process.WaitForExit(1000) && process.ExitCode != 0)
            {
                var error = process.StandardError.ReadToEnd().Trim();
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(error)
                    ? $"File manager launcher exited with code {process.ExitCode}."
                    : error);
            }
        }
    }
}

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
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class DesktopPlatformService : IPlatformService
    {
        public Task OpenUrlAsync(string url)
        {
            StartWithShell(url);
            return Task.CompletedTask;
        }

        public Task OpenFolderAsync(string path)
        {
            if (!Directory.Exists(path))
            {
                var parent = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(parent) && Directory.Exists(parent))
                {
                    path = parent;
                }
            }

            StartWithShell(path);
            return Task.CompletedTask;
        }

        public Task OpenFolderAndSelectAsync(string path)
        {
            if (OperatingSystem.IsWindows() && Directory.Exists(path))
            {
                Process.Start("explorer.exe", $"\"{path}\"");
                return Task.CompletedTask;
            }

            if (OperatingSystem.IsWindows() && File.Exists(path))
            {
                Process.Start("explorer.exe", $"/select,\"{path}\"");
                return Task.CompletedTask;
            }

            return OpenFolderAsync(path);
        }

        public async Task CopyTextAsync(string text)
        {
            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop &&
                desktop.MainWindow?.Clipboard is IClipboard clipboard)
            {
                await clipboard.SetTextAsync(text);
            }
        }

        private static void StartWithShell(string target)
        {
            if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS())
            {
                StartProcess(new ProcessStartInfo { FileName = target, UseShellExecute = true });
                return;
            }

            if (OperatingSystem.IsLinux())
            {
                var startInfo = new ProcessStartInfo { FileName = "xdg-open", UseShellExecute = false };
                startInfo.ArgumentList.Add(target);
                StartLinuxLauncher(startInfo);
                return;
            }

            throw new PlatformNotSupportedException("No launcher is available for this platform.");
        }

        private static void StartProcess(ProcessStartInfo startInfo)
        {
            if (Process.Start(startInfo) == null)
            {
                throw new InvalidOperationException($"Failed to launch '{startInfo.FileName}'.");
            }
        }

        private static void StartLinuxLauncher(ProcessStartInfo startInfo)
        {
            startInfo.RedirectStandardError = true;
            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException($"Failed to launch '{startInfo.FileName}'.");

            if (process.WaitForExit(1000) && process.ExitCode != 0)
            {
                var error = process.StandardError.ReadToEnd().Trim();
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(error)
                    ? $"{startInfo.FileName} exited with code {process.ExitCode}."
                    : error);
            }
        }
    }
}

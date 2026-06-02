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
                Process.Start(new ProcessStartInfo { FileName = target, UseShellExecute = true });
                return;
            }

            if (OperatingSystem.IsLinux())
            {
                Process.Start("xdg-open", target);
                return;
            }

            throw new PlatformNotSupportedException("No launcher is available for this platform.");
        }
    }
}

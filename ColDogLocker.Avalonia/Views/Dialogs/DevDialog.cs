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
using System.Runtime.InteropServices;
using System.Text;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class DevDialog : Window
    {
        private IPlatformService? _platformService;

        public DevDialog()
        {
            InitializeComponent();
            LoadInformation();
            CopyButton.Click += CopyButton_Click;
            CloseButton.Click += CloseButton_Click;
        }

        public DevDialog(IPlatformService platformService)
            : this()
        {
            _platformService = platformService;
        }

        private void LoadInformation()
        {
            VersionText.Text = AppInfo.SemanticVersion ?? "Unknown";
            BuildNumberText.Text = AppInfo.BuildNumber ?? "Unknown";
            BuildDateText.Text = AppInfo.BuildDate ?? "Unknown";
            BuildTimeText.Text = AppInfo.BuildTime ?? "Unknown";
            FullVersionText.Text = AppInfo.BuildVersion ?? "Unknown";

            OsText.Text = SafeValue(() => Environment.OSVersion.VersionString);
            RuntimeText.Text = SafeValue(() => $".NET {Environment.Version}");
            ProcessorCountText.Text = SafeValue(() => Environment.ProcessorCount.ToString());
            ManagedMemoryText.Text = SafeValue(() => FormatMegabytes(GC.GetTotalMemory(forceFullCollection: false)));
            WorkingSetText.Text = SafeValue(() => FormatMegabytes(Environment.WorkingSet));
            ArchitectureText.Text = SafeValue(() => $"{RuntimeInformation.OSArchitecture} OS, {RuntimeInformation.ProcessArchitecture} process");
            InstallPathText.Text = SafeValue(() => Process.GetCurrentProcess().MainModule?.FileName ?? AppContext.BaseDirectory);
            ConfigDirText.Text = SafeValue(() => AppPaths.LocalConfig);
            DatabasePathText.Text = SafeValue(() => Path.Join(AppPaths.LocalConfig, "lockers.db"));
            LogFileText.Text = SafeValue(Logger.GetCurrentLogFilePath);
        }

        private async void CopyButton_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                await CopyTextAsync(BuildClipboardText());
                CopyStatusText.Text = "Developer information copied to clipboard.";
            }
            catch (Exception ex)
            {
                await new ErrorDialog(
                        "Copy Failed",
                        "Failed to copy developer information to clipboard.",
                        ex,
                        _platformService)
                    .ShowDialog<object?>(this);
            }
        }

        private void CloseButton_Click(object? sender, RoutedEventArgs e)
        {
            Close();
        }

        private async Task CopyTextAsync(string text)
        {
            if (_platformService != null)
            {
                await _platformService.CopyTextAsync(text);
                return;
            }

            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            if (clipboard == null)
            {
                throw new InvalidOperationException("No clipboard is available.");
            }

            await clipboard.SetTextAsync(text);
        }

        private string BuildClipboardText()
        {
            var info = new StringBuilder();
            info.AppendLine("=== ColDog Locker Developer Information ===");
            info.AppendLine();
            info.AppendLine("BUILD INFORMATION:");
            info.AppendLine($"  Version: {VersionText.Text}");
            info.AppendLine($"  Build Number: {BuildNumberText.Text}");
            info.AppendLine($"  Build Date: {BuildDateText.Text}");
            info.AppendLine($"  Build Time: {BuildTimeText.Text}");
            info.AppendLine($"  Full Version: {FullVersionText.Text}");
            info.AppendLine();
            info.AppendLine("SYSTEM INFORMATION:");
            info.AppendLine($"  OS: {OsText.Text}");
            info.AppendLine($"  .NET Version: {RuntimeText.Text}");
            info.AppendLine($"  CPU Cores: {ProcessorCountText.Text}");
            info.AppendLine($"  Managed Memory: {ManagedMemoryText.Text}");
            info.AppendLine($"  Working Set: {WorkingSetText.Text}");
            info.AppendLine($"  Architecture: {ArchitectureText.Text}");
            info.AppendLine($"  Install Path: {InstallPathText.Text}");
            info.AppendLine();
            info.AppendLine("APPLICATION PATHS:");
            info.AppendLine($"  Config Directory: {ConfigDirText.Text}");
            info.AppendLine($"  Database Path: {DatabasePathText.Text}");
            info.AppendLine($"  Log File: {LogFileText.Text}");
            return info.ToString();
        }

        private static string SafeValue(Func<string> valueFactory)
        {
            try
            {
                return valueFactory();
            }
            catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or UnauthorizedAccessException)
            {
                return "Unknown";
            }
        }

        private static string FormatMegabytes(long bytes)
        {
            return $"{bytes / 1024.0 / 1024.0:F2} MB";
        }
    }
}

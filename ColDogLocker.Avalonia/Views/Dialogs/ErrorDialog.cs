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
    public sealed partial class ErrorDialog : Window
    {
        private IPlatformService? _platformService;

        public ErrorDialog()
        {
            InitializeComponent();
            Configure("Error", "An error occurred.", exception: null, platformService: null);
            CopyErrorButton.Click += CopyErrorButton_Click;
            OpenLogsButton.Click += OpenLogsButton_Click;
            OkButton.Click += OkButton_Click;
        }

        public ErrorDialog(
            string title,
            string message,
            Exception? exception = null,
            IPlatformService? platformService = null)
            : this()
        {
            Configure(title, message, exception, platformService);
        }

        private void Configure(
            string title,
            string message,
            Exception? exception,
            IPlatformService? platformService)
        {
            _platformService = platformService;
            Title = title;
            ErrorTitleText.Text = title;
            ErrorMessageText.Text = message;
            ExceptionTypeText.Text = exception?.GetType().FullName ?? "No exception details available";
            StackTraceText.Text = exception?.StackTrace ?? "N/A";
            FullErrorTextBox.Text = BuildErrorDetails(message, exception);
            CopyStatusText.Text = string.Empty;
        }

        private async void CopyErrorButton_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                await CopyTextAsync(FullErrorTextBox.Text ?? string.Empty);
                CopyStatusText.Text = "Error details copied to clipboard.";
            }
            catch (Exception ex)
            {
                CopyStatusText.Text = $"Failed to copy error details: {ex.Message}";
            }
        }

        private async void OpenLogsButton_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                var logsPath = Path.GetDirectoryName(Logger.GetCurrentLogFilePath())
                    ?? Path.Combine(AppPaths.LocalConfig, "logs");
                Directory.CreateDirectory(logsPath);

                if (_platformService != null)
                {
                    await _platformService.OpenFolderAsync(logsPath);
                }
                else
                {
                    StartWithShell(logsPath);
                }
            }
            catch (Exception ex)
            {
                await new MessageDialog("Error", $"Failed to open logs folder: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
        }

        private void OkButton_Click(object? sender, RoutedEventArgs e)
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

        private static string BuildErrorDetails(string errorMessage, Exception? exception)
        {
            var details = new StringBuilder();
            details.AppendLine("=== ERROR DETAILS ===");
            details.AppendLine($"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            details.AppendLine("Application: ColDog Locker");
            details.AppendLine($"Version: {AppInfo.SemanticVersion ?? "Unknown"}");
            details.AppendLine($"Log File: {Logger.GetCurrentLogFilePath()}");
            details.AppendLine($"Session ID: {Logger.GetCurrentSessionId()}");
            details.AppendLine();
            details.AppendLine("Error Message:");
            details.AppendLine(errorMessage);
            details.AppendLine();

            if (exception != null)
            {
                AppendException(details, exception, level: 0);
            }
            else
            {
                details.AppendLine("Exception Details:");
                details.AppendLine("No exception details available.");
                details.AppendLine();
            }

            details.AppendLine("=== SYSTEM INFORMATION ===");
            details.AppendLine($"OS: {Environment.OSVersion}");
            details.AppendLine($"OS Architecture: {RuntimeInformation.OSArchitecture}");
            details.AppendLine($"Process Architecture: {RuntimeInformation.ProcessArchitecture}");
            details.AppendLine($".NET Version: {Environment.Version}");
            details.AppendLine($"Runtime: {RuntimeInformation.FrameworkDescription}");
            details.AppendLine($"Processor Count: {Environment.ProcessorCount}");
            details.AppendLine($"Working Set: {Environment.WorkingSet / 1024 / 1024} MB");
            details.AppendLine($"Base Directory: {AppContext.BaseDirectory}");

            return details.ToString();
        }

        private static void AppendException(StringBuilder details, Exception exception, int level)
        {
            details.AppendLine(level == 0 ? "Exception Type:" : $"Inner Exception {level} Type:");
            details.AppendLine(exception.GetType().FullName ?? exception.GetType().Name);
            details.AppendLine();

            if (!string.IsNullOrWhiteSpace(exception.Message))
            {
                details.AppendLine(level == 0 ? "Exception Message:" : $"Inner Exception {level} Message:");
                details.AppendLine(exception.Message);
                details.AppendLine();
            }

            if (!string.IsNullOrWhiteSpace(exception.StackTrace))
            {
                details.AppendLine(level == 0 ? "Stack Trace:" : $"Inner Exception {level} Stack Trace:");
                details.AppendLine(exception.StackTrace);
                details.AppendLine();
            }

            if (exception.InnerException != null)
            {
                AppendException(details, exception.InnerException, level + 1);
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

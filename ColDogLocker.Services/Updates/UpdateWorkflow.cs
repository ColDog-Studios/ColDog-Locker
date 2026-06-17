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

namespace ColDogStudios.ColDogLocker.Services.Updates
{
    public interface IUpdateDialogHost
    {
        Task ShowMessageAsync(UpdateDialogMessage message, CancellationToken cancellationToken = default);
        Task<bool> ConfirmDownloadAsync(UpdateDialogMessage prompt, CancellationToken cancellationToken = default);
        Task ShowErrorAsync(UpdateDialogError error, CancellationToken cancellationToken = default);
    }

    public interface IUpdateWorkflowMessageFormatter
    {
        UpdateDialogMessage FormatNoUpdate(UpdateCheckResult update);
        UpdateDialogMessage FormatManualUpdate(UpdateCheckResult update);
        UpdateDialogMessage FormatDownloadPrompt(UpdateCheckResult update);
        UpdateDialogMessage FormatDownloadSuccess(UpdateDownloadResult download);
        UpdateDialogError FormatCheckError(Exception exception);
        UpdateDialogError FormatDownloadError(Exception exception);
    }

    public sealed class UpdateDialogMessage
    {
        public UpdateDialogMessage(string title, string message)
        {
            Title = title;
            Message = message;
        }

        public string Title { get; }
        public string Message { get; }
    }

    public sealed class UpdateDialogError
    {
        public UpdateDialogError(string title, string message, Exception exception)
        {
            Title = title;
            Message = message;
            Exception = exception;
        }

        public string Title { get; }
        public string Message { get; }
        public Exception Exception { get; }
    }

    public enum UpdateWorkflowStatus
    {
        NoUpdate,
        ManualUpdate,
        DownloadDeclined,
        Downloaded,
        CheckFailed,
        DownloadFailed
    }

    public sealed class UpdateWorkflowResult
    {
        private UpdateWorkflowResult(
            UpdateWorkflowStatus status,
            UpdateCheckResult? update,
            UpdateDownloadResult? download,
            Exception? exception)
        {
            Status = status;
            Update = update;
            Download = download;
            Exception = exception;
        }

        public UpdateWorkflowStatus Status { get; }
        public UpdateCheckResult? Update { get; }
        public UpdateDownloadResult? Download { get; }
        public Exception? Exception { get; }

        public static UpdateWorkflowResult NoUpdate(UpdateCheckResult update)
        {
            return new UpdateWorkflowResult(UpdateWorkflowStatus.NoUpdate, update, null, null);
        }

        public static UpdateWorkflowResult ManualUpdate(UpdateCheckResult update)
        {
            return new UpdateWorkflowResult(UpdateWorkflowStatus.ManualUpdate, update, null, null);
        }

        public static UpdateWorkflowResult DownloadDeclined(UpdateCheckResult update)
        {
            return new UpdateWorkflowResult(UpdateWorkflowStatus.DownloadDeclined, update, null, null);
        }

        public static UpdateWorkflowResult Downloaded(UpdateCheckResult update, UpdateDownloadResult download)
        {
            return new UpdateWorkflowResult(UpdateWorkflowStatus.Downloaded, update, download, null);
        }

        public static UpdateWorkflowResult CheckFailed(Exception exception)
        {
            return new UpdateWorkflowResult(UpdateWorkflowStatus.CheckFailed, null, null, exception);
        }

        public static UpdateWorkflowResult DownloadFailed(UpdateCheckResult update, Exception exception)
        {
            return new UpdateWorkflowResult(UpdateWorkflowStatus.DownloadFailed, update, null, exception);
        }
    }

    public sealed class DefaultUpdateWorkflowMessageFormatter : IUpdateWorkflowMessageFormatter
    {
        public UpdateDialogMessage FormatNoUpdate(UpdateCheckResult update)
        {
            var message = string.IsNullOrWhiteSpace(update.UserMessage)
                ? "ColDog Locker is up to date."
                : update.UserMessage.Trim();

            return new UpdateDialogMessage(
                "No Updates Available",
                $"{message}\n\nCurrent Version: {update.CurrentVersion}\nLatest Version: {update.LatestVersion}");
        }

        public UpdateDialogMessage FormatManualUpdate(UpdateCheckResult update)
        {
            var message = FormatUpdateAvailable(update);
            message += $"\n{update.UserMessage ?? "This update cannot be downloaded automatically."}";

            if (!string.IsNullOrWhiteSpace(update.ManualUpdateInstructions))
            {
                message += $"\n\n{update.ManualUpdateInstructions}";
            }

            if (!string.IsNullOrWhiteSpace(update.ReleaseUrl))
            {
                message += $"\n\nRelease: {update.ReleaseUrl}";
            }

            return new UpdateDialogMessage("Update Available", message);
        }

        public UpdateDialogMessage FormatDownloadPrompt(UpdateCheckResult update)
        {
            return new UpdateDialogMessage(
                "Update Available",
                $"{FormatUpdateAvailable(update)}\nWould you like to download and install it now?");
        }

        public UpdateDialogMessage FormatDownloadSuccess(UpdateDownloadResult download)
        {
            return new UpdateDialogMessage(
                "Download Complete",
                $"Update downloaded successfully to:\n{download.FilePath}\n\nPlease run the installer to complete the update.");
        }

        public UpdateDialogError FormatCheckError(Exception exception)
        {
            return new UpdateDialogError(
                "Update Check Failed",
                $"Failed to check for updates: {exception.Message}",
                exception);
        }

        public UpdateDialogError FormatDownloadError(Exception exception)
        {
            return new UpdateDialogError(
                "Download Failed",
                $"Failed to download update: {exception.Message}",
                exception);
        }

        private static string FormatUpdateAvailable(UpdateCheckResult update)
        {
            var message = "A new version is available!\n\n" +
                          $"Current Version: {update.CurrentVersion}\n" +
                          $"Latest Version: {update.LatestVersion}\n";

            if (!string.IsNullOrWhiteSpace(update.ReleaseNotesMarkdown))
            {
                message += $"\nRelease Notes:\n{update.ReleaseNotesMarkdown.Trim()}\n";
            }

            return message;
        }
    }

    public sealed class UpdateWorkflow
    {
        private readonly IUpdateService _updateService;
        private readonly IUpdateDialogHost _dialogHost;
        private readonly IUpdateWorkflowMessageFormatter _formatter;

        public UpdateWorkflow(
            IUpdateService updateService,
            IUpdateDialogHost dialogHost,
            IUpdateWorkflowMessageFormatter? formatter = null)
        {
            _updateService = updateService;
            _dialogHost = dialogHost;
            _formatter = formatter ?? new DefaultUpdateWorkflowMessageFormatter();
        }

        public async Task<UpdateWorkflowResult> RunAsync(CancellationToken cancellationToken = default)
        {
            UpdateCheckResult update;
            try
            {
                update = await _updateService.CheckForUpdatesAsync(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await _dialogHost.ShowErrorAsync(_formatter.FormatCheckError(ex), cancellationToken);
                return UpdateWorkflowResult.CheckFailed(ex);
            }

            if (!update.UpdateAvailable)
            {
                await _dialogHost.ShowMessageAsync(_formatter.FormatNoUpdate(update), cancellationToken);
                return UpdateWorkflowResult.NoUpdate(update);
            }

            if (!update.CanDownload)
            {
                await _dialogHost.ShowMessageAsync(_formatter.FormatManualUpdate(update), cancellationToken);
                return UpdateWorkflowResult.ManualUpdate(update);
            }

            var shouldDownload = await _dialogHost.ConfirmDownloadAsync(
                _formatter.FormatDownloadPrompt(update),
                cancellationToken);

            if (!shouldDownload)
            {
                return UpdateWorkflowResult.DownloadDeclined(update);
            }

            try
            {
                var download = await _updateService.DownloadUpdateAsync(update, cancellationToken);
                await _dialogHost.ShowMessageAsync(_formatter.FormatDownloadSuccess(download), cancellationToken);
                return UpdateWorkflowResult.Downloaded(update, download);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await _dialogHost.ShowErrorAsync(_formatter.FormatDownloadError(ex), cancellationToken);
                return UpdateWorkflowResult.DownloadFailed(update, ex);
            }
        }
    }
}

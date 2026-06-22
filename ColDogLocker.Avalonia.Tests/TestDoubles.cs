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

using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Avalonia.ViewModels;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests
{
    internal static class TestViewModelFactory
    {
        public static MainWindowViewModel Create(
            out RecordingDialogService dialogs,
            out RecordingPlatformService platform,
            out StubUpdateService updates,
            out RecordingUpdateDialogHost updateDialogs)
        {
            SettingsManager.Settings.DevMode = false;
            SettingsManager.Settings.DefaultGuiViewMode = GuiViewMode.Grid;

            dialogs = new RecordingDialogService();
            platform = new RecordingPlatformService();
            updates = new StubUpdateService();
            updateDialogs = new RecordingUpdateDialogHost();
            var workflow = new UpdateWorkflow(updates, updateDialogs);
            return new MainWindowViewModel(dialogs, platform, workflow);
        }
    }

    internal sealed class RecordingDialogService : IUserDialogService
    {
        public NewLockerRequest? NewLockerRequest { get; set; }
        public string? PasswordResponse { get; set; }
        public bool ConfirmationResponse { get; set; }
        public List<(string Title, string Message)> Messages { get; } = [];
        public List<(string Title, string Message)> Warnings { get; } = [];
        public List<(string Title, string Message, Exception? Exception)> Errors { get; } = [];
        public int NewLockerPromptCount { get; private set; }

        public Task ShowMessageAsync(string title, string message)
        {
            Messages.Add((title, message));
            return Task.CompletedTask;
        }

        public Task ShowErrorAsync(string title, string message, Exception? exception = null)
        {
            Errors.Add((title, message, exception));
            return Task.CompletedTask;
        }

        public Task ShowWarningAsync(string title, string message)
        {
            Warnings.Add((title, message));
            return Task.CompletedTask;
        }

        public Task<bool> ConfirmAsync(string title, string message)
        {
            return Task.FromResult(ConfirmationResponse);
        }

        public Task<string?> PromptPasswordAsync(string title)
        {
            return Task.FromResult(PasswordResponse);
        }

        public Task<NewLockerRequest?> ShowNewLockerAsync()
        {
            NewLockerPromptCount++;
            return Task.FromResult(NewLockerRequest);
        }

        public Task ShowLockerPropertiesAsync(LockerModel locker)
        {
            return Task.CompletedTask;
        }

        public Task ShowSettingsAsync()
        {
            return Task.CompletedTask;
        }

        public Task ShowAboutAsync()
        {
            return Task.CompletedTask;
        }

        public Task ShowDevInfoAsync()
        {
            return Task.CompletedTask;
        }

        public Task ShowProgressTestAsync()
        {
            return Task.CompletedTask;
        }
    }

    internal sealed class RecordingPlatformService : IPlatformService
    {
        public string? LastOpenedUrl { get; private set; }
        public string? LastOpenedFolder { get; private set; }
        public string? LastSelectedPath { get; private set; }
        public string? LastCopiedText { get; private set; }
        public Exception? OpenFolderAndSelectException { get; set; }

        public Task OpenUrlAsync(string url)
        {
            LastOpenedUrl = url;
            return Task.CompletedTask;
        }

        public Task OpenFolderAsync(string path)
        {
            LastOpenedFolder = path;
            return Task.CompletedTask;
        }

        public Task OpenFolderAndSelectAsync(string path)
        {
            if (OpenFolderAndSelectException != null)
            {
                throw OpenFolderAndSelectException;
            }

            LastSelectedPath = path;
            return Task.CompletedTask;
        }

        public Task CopyTextAsync(string text)
        {
            LastCopiedText = text;
            return Task.CompletedTask;
        }
    }

    internal sealed class StubUpdateService : IUpdateService
    {
        public int CheckCount { get; private set; }
        public UpdateCheckResult CheckResult { get; set; } = new()
        {
            CurrentVersion = "1.0.0",
            LatestVersion = "1.0.0",
            PlatformName = "Test",
            UserMessage = "ColDog Locker is up to date."
        };

        public Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
        {
            CheckCount++;
            return Task.FromResult(CheckResult);
        }

        public Task<UpdateDownloadResult> DownloadUpdateAsync(
            UpdateCheckResult updateInfo,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("The test update is not downloadable.");
        }

        public Task<UpdateInstallResult> InstallUpdateAsync(
            UpdateDownloadResult download,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("The test update is not installable.");
        }
    }

    internal sealed class RecordingUpdateDialogHost : IUpdateDialogHost
    {
        public List<UpdateDialogMessage> Messages { get; } = [];
        public List<UpdateDialogError> Errors { get; } = [];
        public bool ConfirmDownloadResponse { get; set; }

        public Task ShowMessageAsync(UpdateDialogMessage message, CancellationToken cancellationToken = default)
        {
            Messages.Add(message);
            return Task.CompletedTask;
        }

        public Task<bool> ConfirmDownloadAsync(UpdateDialogMessage prompt, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ConfirmDownloadResponse);
        }

        public Task ShowErrorAsync(UpdateDialogError error, CancellationToken cancellationToken = default)
        {
            Errors.Add(error);
            return Task.CompletedTask;
        }
    }
}

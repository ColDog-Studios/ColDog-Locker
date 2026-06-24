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

using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Services.Tests.Updates
{
    public class UpdateWorkflowTests
    {
        [Fact]
        public async Task RunAsync_NoUpdate_ShowsNoUpdateMessage()
        {
            // Arrange
            var update = new UpdateCheckResult { UpdateAvailable = false, CurrentVersion = "1.2.0", LatestVersion = "1.2.0" };
            var service = new StubUpdateService { CheckResult = update };
            var host = new RecordingUpdateDialogHost();
            var workflow = new UpdateWorkflow(service, host);

            // Act
            var result = await workflow.RunAsync();

            // Assert
            Assert.Equal(UpdateWorkflowStatus.NoUpdate, result.Status);
            Assert.Same(update, result.Update);
            Assert.Equal(1, service.CheckCount);
            Assert.Equal(0, service.DownloadCount);
            var message = Assert.Single(host.Messages);
            Assert.Equal("No Updates Available", message.Title);
            Assert.Contains("ColDog Locker is up to date", message.Message);
            Assert.Empty(host.Confirmations);
            Assert.Empty(host.Errors);
        }

        [Fact]
        public async Task RunAsync_ManualUpdate_ShowsManualUpdateMessage()
        {
            // Arrange
            var update = new UpdateCheckResult
            {
                UpdateAvailable = true,
                CanDownload = false,
                CurrentVersion = "1.2.0",
                LatestVersion = "1.3.0",
                ReleaseNotesMarkdown = "## Changes\nManual package",
                UserMessage = "This update needs manual installation.",
                ManualUpdateInstructions = "Download the matching installer.",
                ReleaseUrl = "https://github.example/releases/v1.3.0"
            };
            var service = new StubUpdateService { CheckResult = update };
            var host = new RecordingUpdateDialogHost();
            var workflow = new UpdateWorkflow(service, host);

            // Act
            var result = await workflow.RunAsync();

            // Assert
            Assert.Equal(UpdateWorkflowStatus.ManualUpdate, result.Status);
            Assert.Same(update, result.Update);
            Assert.Equal(0, service.DownloadCount);
            var message = Assert.Single(host.Messages);
            Assert.Equal("Update Available", message.Title);
            Assert.Contains("Manual package", message.Message);
            Assert.Contains("This update needs manual installation.", message.Message);
            Assert.Contains("Download the matching installer.", message.Message);
            Assert.Contains(update.ReleaseUrl, message.Message);
            Assert.Empty(host.Confirmations);
            Assert.Empty(host.Errors);
        }

        [Fact]
        public async Task RunAsync_DownloadableUpdateAccepted_DownloadsAndReportsSuccess()
        {
            // Arrange
            var update = CreateDownloadableUpdate();
            var download = new UpdateDownloadResult { FilePath = @"C:\Downloads\ColDogLocker.msi", BytesDownloaded = 1234, Sha256 = "abc123" };
            var install = new UpdateInstallResult
            {
                FilePath = download.FilePath,
                Command = "msiexec.exe /i C:\\Downloads\\ColDogLocker.msi",
                InstallerStarted = true,
                UserMessage = "Installer started."
            };
            var service = new StubUpdateService { CheckResult = update, DownloadResult = download, InstallResult = install };
            var host = new RecordingUpdateDialogHost { ConfirmDownload = true };
            var workflow = new UpdateWorkflow(service, host);

            // Act
            var result = await workflow.RunAsync();

            // Assert
            Assert.Equal(UpdateWorkflowStatus.Installed, result.Status);
            Assert.Same(update, result.Update);
            Assert.Same(download, result.Download);
            Assert.Same(install, result.Install);
            Assert.Equal(1, service.DownloadCount);
            Assert.Equal(1, service.InstallCount);
            var confirmation = Assert.Single(host.Confirmations);
            Assert.Equal("Update Available", confirmation.Title);
            Assert.Contains("Would you like to download and install it now?", confirmation.Message);
            var message = Assert.Single(host.Messages);
            Assert.Equal("Installer Started", message.Title);
            Assert.Contains(download.FilePath, message.Message);
            Assert.Contains("Installer started.", message.Message);
            Assert.Empty(host.Errors);
        }

        [Fact]
        public async Task RunAsync_DownloadableUpdateDeclined_DoesNotDownload()
        {
            // Arrange
            var update = CreateDownloadableUpdate();
            var service = new StubUpdateService { CheckResult = update };
            var host = new RecordingUpdateDialogHost { ConfirmDownload = false };
            var workflow = new UpdateWorkflow(service, host);

            // Act
            var result = await workflow.RunAsync();

            // Assert
            Assert.Equal(UpdateWorkflowStatus.DownloadDeclined, result.Status);
            Assert.Same(update, result.Update);
            Assert.Equal(0, service.DownloadCount);
            Assert.Single(host.Confirmations);
            Assert.Empty(host.Messages);
            Assert.Empty(host.Errors);
        }

        [Fact]
        public async Task RunAsync_CheckException_ReportsError()
        {
            // Arrange
            var exception = new UpdateException(UpdateFailureKind.Network, "Network unavailable");
            var service = new StubUpdateService { CheckException = exception };
            var host = new RecordingUpdateDialogHost();
            var workflow = new UpdateWorkflow(service, host);

            // Act
            var result = await workflow.RunAsync();

            // Assert
            Assert.Equal(UpdateWorkflowStatus.CheckFailed, result.Status);
            Assert.Same(exception, result.Exception);
            Assert.Equal(1, service.CheckCount);
            Assert.Equal(0, service.DownloadCount);
            var error = Assert.Single(host.Errors);
            Assert.Equal("Update Check Failed", error.Title);
            Assert.Contains("Network unavailable", error.Message);
            Assert.Same(exception, error.Exception);
            Assert.Empty(host.Messages);
            Assert.Empty(host.Confirmations);
        }

        [Fact]
        public async Task RunAsync_DownloadException_ReportsError()
        {
            // Arrange
            var update = CreateDownloadableUpdate();
            var exception = new UpdateException(UpdateFailureKind.FileSystem, "Could not save installer");
            var service = new StubUpdateService { CheckResult = update, DownloadException = exception };
            var host = new RecordingUpdateDialogHost { ConfirmDownload = true };
            var workflow = new UpdateWorkflow(service, host);

            // Act
            var result = await workflow.RunAsync();

            // Assert
            Assert.Equal(UpdateWorkflowStatus.DownloadFailed, result.Status);
            Assert.Same(update, result.Update);
            Assert.Same(exception, result.Exception);
            Assert.Equal(1, service.DownloadCount);
            Assert.Equal(0, service.InstallCount);
            Assert.Single(host.Confirmations);
            var error = Assert.Single(host.Errors);
            Assert.Equal("Download Failed", error.Title);
            Assert.Contains("Could not save installer", error.Message);
            Assert.Same(exception, error.Exception);
            Assert.Empty(host.Messages);
        }

        [Fact]
        public async Task RunAsync_InstallException_ReportsErrorAndLeavesDownload()
        {
            // Arrange
            var update = CreateDownloadableUpdate();
            var download = new UpdateDownloadResult { FilePath = "/home/user/Downloads/ColDogLocker.deb", BytesDownloaded = 1234, Sha256 = "abc123" };
            var exception = new UpdateException(UpdateFailureKind.InstallFailed, "Package manager failed");
            var service = new StubUpdateService { CheckResult = update, DownloadResult = download, InstallException = exception };
            var host = new RecordingUpdateDialogHost { ConfirmDownload = true };
            var workflow = new UpdateWorkflow(service, host);

            // Act
            var result = await workflow.RunAsync();

            // Assert
            Assert.Equal(UpdateWorkflowStatus.InstallFailed, result.Status);
            Assert.Same(update, result.Update);
            Assert.Same(download, result.Download);
            Assert.Same(exception, result.Exception);
            Assert.Equal(1, service.DownloadCount);
            Assert.Equal(1, service.InstallCount);
            Assert.Single(host.Confirmations);
            var error = Assert.Single(host.Errors);
            Assert.Equal("Install Failed", error.Title);
            Assert.Contains(download.FilePath, error.Message);
            Assert.Contains("Package manager failed", error.Message);
            Assert.Same(exception, error.Exception);
            Assert.Empty(host.Messages);
        }

        private static UpdateCheckResult CreateDownloadableUpdate()
        {
            return new UpdateCheckResult
            {
                UpdateAvailable = true,
                CanDownload = true,
                CurrentVersion = "1.2.0",
                LatestVersion = "1.3.0",
                ReleaseNotesMarkdown = "## Changes\nInstaller update",
                DownloadUrl = "https://downloads.example/ColDogLocker.msi",
                InstallerFileName = "ColDogLocker.msi",
                AssetDigest = "sha256:abc123"
            };
        }

        private sealed class StubUpdateService : IUpdateService
        {
            public UpdateCheckResult? CheckResult { get; set; }
            public UpdateDownloadResult? DownloadResult { get; set; }
            public UpdateInstallResult? InstallResult { get; set; }
            public Exception? CheckException { get; set; }
            public Exception? DownloadException { get; set; }
            public Exception? InstallException { get; set; }
            public int CheckCount { get; private set; }
            public int DownloadCount { get; private set; }
            public int InstallCount { get; private set; }
            public UpdateCheckResult? DownloadUpdate { get; private set; }
            public UpdateDownloadResult? InstallDownload { get; private set; }

            public Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
            {
                CheckCount++;

                if (CheckException != null)
                {
                    throw CheckException;
                }

                return Task.FromResult(CheckResult ?? new UpdateCheckResult());
            }

            public Task<UpdateDownloadResult> DownloadUpdateAsync(
                UpdateCheckResult updateInfo,
                CancellationToken cancellationToken = default)
            {
                DownloadCount++;
                DownloadUpdate = updateInfo;

                if (DownloadException != null)
                {
                    throw DownloadException;
                }

                return Task.FromResult(DownloadResult ?? new UpdateDownloadResult());
            }

            public Task<UpdateInstallResult> InstallUpdateAsync(
                UpdateDownloadResult download,
                CancellationToken cancellationToken = default)
            {
                InstallCount++;
                InstallDownload = download;

                if (InstallException != null)
                {
                    throw InstallException;
                }

                return Task.FromResult(InstallResult ?? new UpdateInstallResult { FilePath = download.FilePath, InstallerStarted = true });
            }
        }

        private sealed class RecordingUpdateDialogHost : IUpdateDialogHost
        {
            public bool ConfirmDownload { get; set; }
            public List<UpdateDialogMessage> Messages { get; } = new();
            public List<UpdateDialogMessage> Confirmations { get; } = new();
            public List<UpdateDialogError> Errors { get; } = new();

            public Task ShowMessageAsync(UpdateDialogMessage message, CancellationToken cancellationToken = default)
            {
                Messages.Add(message);
                return Task.CompletedTask;
            }

            public Task<bool> ConfirmDownloadAsync(
                UpdateDialogMessage prompt,
                CancellationToken cancellationToken = default)
            {
                Confirmations.Add(prompt);
                return Task.FromResult(ConfirmDownload);
            }

            public Task ShowErrorAsync(UpdateDialogError error, CancellationToken cancellationToken = default)
            {
                Errors.Add(error);
                return Task.CompletedTask;
            }
        }
    }
}

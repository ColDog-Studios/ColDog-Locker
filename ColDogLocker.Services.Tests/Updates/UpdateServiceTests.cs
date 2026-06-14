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

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Services.Tests.Updates
{
    public class UpdateServiceTests
    {
        [Fact]
        public async Task CheckForUpdatesAsync_NewerWindowsReleaseWithDigest_ShouldReturnDownloadableUpdate()
        {
            // Arrange
            var releaseJson = CreateReleaseJson(
                "v1.2.0",
                """
                ## Changes
                - Added updater tests
                """,
                ("ColDogLocker-win-x64.msi", "https://downloads.example/cdl.msi", Sha256Digest("installer")));

            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] = JsonResponse(releaseJson)
                },
                currentVersion: "1.1.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = System.Runtime.InteropServices.Architecture.X64 });

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.True(result.UpdateAvailable);
            Assert.True(result.CanDownload);
            Assert.True(result.IsSupportedPlatform);
            Assert.Equal("1.1.0", result.CurrentVersion);
            Assert.Equal("1.2.0", result.LatestVersion);
            Assert.Equal("https://downloads.example/cdl.msi", result.DownloadUrl);
            Assert.Equal("ColDogLocker-win-x64.msi", result.InstallerFileName);
            Assert.Contains("Added updater tests", result.ReleaseNotesMarkdown);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_WindowsReleaseWithMsiAndSetupExe_ShouldPreferMsi()
        {
            // Arrange
            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] = JsonResponse(CreateReleaseJson(
                        "v1.2.0",
                        "Windows release",
                        ("ColDogLocker-win-x64.msi", "https://downloads.example/cdl.msi", Sha256Digest("msi")),
                        ("ColDogLocker-win-x64-setup.exe", "https://downloads.example/cdl-setup.exe", Sha256Digest("setup"))))
                },
                currentVersion: "1.1.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = System.Runtime.InteropServices.Architecture.X64 });

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.True(result.CanDownload);
            Assert.Equal("https://downloads.example/cdl.msi", result.DownloadUrl);
            Assert.Equal("ColDogLocker-win-x64.msi", result.InstallerFileName);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_CurrentVersionIsLatest_ShouldReturnNoUpdate()
        {
            // Arrange
            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] =
                        JsonResponse(CreateReleaseJson("v1.2.0", "No changes", ("ColDogLocker-win-x64.msi", "https://downloads.example/cdl.msi", Sha256Digest("installer"))))
                },
                currentVersion: "1.2.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = System.Runtime.InteropServices.Architecture.X64 });

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.False(result.UpdateAvailable);
            Assert.False(result.CanDownload);
            Assert.Equal("1.2.0", result.LatestVersion);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_StableChannelWithoutLatestRelease_ShouldReturnNoUpdate()
        {
            // Arrange
            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] =
                        new HttpResponseMessage(HttpStatusCode.NotFound)
                },
                currentVersion: "0.10.0-beta",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = System.Runtime.InteropServices.Architecture.X64 });

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.False(result.UpdateAvailable);
            Assert.False(result.CanDownload);
            Assert.Equal("0.10.0-beta", result.CurrentVersion);
            Assert.Equal("0.10.0-beta", result.LatestVersion);
            Assert.Contains("up to date", result.UserMessage, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_CurrentVersionNewerThanLatestPrerelease_ShouldReturnNoUpdate()
        {
            // Arrange
            var releasesJson =
                $$"""
                [
                  {{CreateReleaseObject("v0.9.0-alpha.1", "Older prerelease", false, true, ("ColDogLocker-0.9.0-alpha.1-win-x64-setup.exe", "https://downloads.example/alpha.exe", Sha256Digest("alpha")))}}
                ]
                """;

            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases"] = JsonResponse(releasesJson)
                },
                currentVersion: "0.10.0-beta",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = System.Runtime.InteropServices.Architecture.X64 },
                channel: UpdateChannel.Unstable);

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.False(result.UpdateAvailable);
            Assert.False(result.CanDownload);
            Assert.Equal("0.10.0-beta", result.CurrentVersion);
            Assert.Equal("0.9.0-alpha.1", result.LatestVersion);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_MacOsUpdate_ShouldReturnManualUpdateInstructions()
        {
            // Arrange
            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] =
                        JsonResponse(CreateReleaseJson("v1.3.0", "Mac release notes", ("ColDogLocker-win-x64.msi", "https://downloads.example/cdl.msi", Sha256Digest("installer"))))
                },
                currentVersion: "1.2.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.MacOS, Architecture = System.Runtime.InteropServices.Architecture.Arm64 });

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.True(result.UpdateAvailable);
            Assert.False(result.CanDownload);
            Assert.False(result.IsSupportedPlatform);
            Assert.Contains("macOS", result.PlatformName);
            Assert.Contains("Automatic macOS updates are disabled", result.ManualUpdateInstructions);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_LinuxDebPlatform_ShouldSelectDebAsset()
        {
            // Arrange
            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] = JsonResponse(CreateReleaseJson(
                        "v1.3.0",
                        "Linux release",
                        ("ColDogLocker-linux-x64.rpm", "https://downloads.example/cdl.rpm", Sha256Digest("rpm")),
                        ("ColDogLocker-linux-x64.deb", "https://downloads.example/cdl.deb", Sha256Digest("deb"))))
                },
                currentVersion: "1.2.0",
                platform: new UpdatePlatform
                {
                    OperatingSystem = UpdateOperatingSystem.Linux,
                    LinuxPackageFormat = LinuxPackageFormat.Deb,
                    Architecture = System.Runtime.InteropServices.Architecture.X64
                });

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.True(result.CanDownload);
            Assert.Equal("ColDogLocker-linux-x64.deb", result.InstallerFileName);
            Assert.Equal("https://downloads.example/cdl.deb", result.DownloadUrl);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_MissingDigest_ShouldReturnNonDownloadableUpdate()
        {
            // Arrange
            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] =
                        JsonResponse(CreateReleaseJson("v1.3.0", "Missing digest", ("ColDogLocker-win-x64.msi", "https://downloads.example/cdl.msi", null)))
                },
                currentVersion: "1.2.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = System.Runtime.InteropServices.Architecture.X64 });

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.True(result.UpdateAvailable);
            Assert.False(result.CanDownload);
            Assert.Contains("digest", result.UserMessage, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_UnstableChannel_ShouldUseReleasesEndpointAndSkipDrafts()
        {
            // Arrange
            var releasesJson =
                $$"""
                [
                  {{CreateReleaseObject("v1.4.0", "Draft", true, true, ("ColDogLocker-win-x64.msi", "https://downloads.example/draft.msi", Sha256Digest("draft")))}},
                  {{CreateReleaseObject("v1.3.0-beta.1", "Beta", false, true, ("ColDogLocker-win-x64.msi", "https://downloads.example/beta.msi", Sha256Digest("beta")))}},
                  {{CreateReleaseObject("v1.3.0", "Stable", false, false, ("ColDogLocker-win-x64.msi", "https://downloads.example/stable.msi", Sha256Digest("stable")))}}
                ]
                """;

            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases"] = JsonResponse(releasesJson)
                },
                currentVersion: "1.2.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = System.Runtime.InteropServices.Architecture.X64 },
                channel: UpdateChannel.Unstable);

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.True(result.UpdateAvailable);
            Assert.Equal("1.3.0", result.LatestVersion);
            Assert.Equal("https://downloads.example/stable.msi", result.DownloadUrl);
        }

        [Fact]
        public async Task CheckForUpdatesAsync_UnstableChannel_ShouldAcceptSequentialPrereleaseTag()
        {
            // Arrange
            var releasesJson =
                $$"""
                [
                  {{CreateReleaseObject("v1.3.0-alpha.1", "## Features\n- Sequential prerelease", false, true, ("ColDogLocker-1.3.0-alpha.1-win-x64-setup.exe", "https://downloads.example/main-alpha.exe", Sha256Digest("main-alpha")))}}
                ]
                """;

            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/repos/ColDog-Studios/ColDog-Locker/releases"] = JsonResponse(releasesJson)
                },
                currentVersion: "1.3.0-alpha",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = System.Runtime.InteropServices.Architecture.X64 },
                channel: UpdateChannel.Unstable);

            // Act
            var result = await service.CheckForUpdatesAsync();

            // Assert
            Assert.True(result.UpdateAvailable);
            Assert.True(result.CanDownload);
            Assert.Equal("1.3.0-alpha.1", result.LatestVersion);
            Assert.Equal("ColDogLocker-1.3.0-alpha.1-win-x64-setup.exe", result.InstallerFileName);
            Assert.Contains("Sequential prerelease", result.ReleaseNotesMarkdown);
        }

        [Fact]
        public async Task DownloadUpdateAsync_ValidDigest_ShouldWriteFileAndReturnMetadata()
        {
            // Arrange
            var bytes = Encoding.UTF8.GetBytes("installer payload");
            var tempDirectory = CreateTempDirectory();
            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/download/cdl.msi"] = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(bytes)
                    }
                },
                currentVersion: "1.2.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows },
                downloadDirectory: tempDirectory);

            var updateInfo = new UpdateCheckResult
            {
                UpdateAvailable = true,
                CanDownload = true,
                DownloadUrl = "https://api.test/download/cdl.msi",
                InstallerFileName = "cdl.msi",
                AssetDigest = Sha256Digest(bytes)
            };

            try
            {
                // Act
                var result = await service.DownloadUpdateAsync(updateInfo);

                // Assert
                Assert.True(File.Exists(result.FilePath));
                Assert.Equal(Path.Combine(tempDirectory, "cdl.msi"), result.FilePath);
                Assert.Equal(bytes.Length, result.BytesDownloaded);
                Assert.Equal(Sha256Hex(bytes), result.Sha256);
            }
            finally
            {
                Directory.Delete(tempDirectory, recursive: true);
            }
        }

        [Fact]
        public async Task DownloadUpdateAsync_DigestMismatch_ShouldNotWriteFile()
        {
            // Arrange
            var tempDirectory = CreateTempDirectory();
            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/download/cdl.msi"] = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(Encoding.UTF8.GetBytes("unexpected payload"))
                    }
                },
                currentVersion: "1.2.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows },
                downloadDirectory: tempDirectory);

            var updateInfo = new UpdateCheckResult
            {
                UpdateAvailable = true,
                CanDownload = true,
                DownloadUrl = "https://api.test/download/cdl.msi",
                InstallerFileName = "cdl.msi",
                AssetDigest = Sha256Digest("expected payload")
            };

            try
            {
                // Act
                var exception = await Assert.ThrowsAsync<UpdateException>(() => service.DownloadUpdateAsync(updateInfo));

                // Assert
                Assert.Equal(UpdateFailureKind.DigestMismatch, exception.FailureKind);
                Assert.False(File.Exists(Path.Combine(tempDirectory, "cdl.msi")));
            }
            finally
            {
                Directory.Delete(tempDirectory, recursive: true);
            }
        }

        [Fact]
        public async Task DownloadUpdateAsync_ExistingTargetFile_ShouldReplaceOnlyAfterVerifiedWrite()
        {
            // Arrange
            var oldBytes = Encoding.UTF8.GetBytes("old installer");
            var newBytes = Encoding.UTF8.GetBytes("new installer");
            var tempDirectory = CreateTempDirectory();
            var targetPath = Path.Combine(tempDirectory, "cdl.msi");
            await File.WriteAllBytesAsync(targetPath, oldBytes);

            using var service = CreateService(
                new Dictionary<string, HttpResponseMessage>
                {
                    ["/download/cdl.msi"] = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(newBytes)
                    }
                },
                currentVersion: "1.2.0",
                platform: new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows },
                downloadDirectory: tempDirectory);

            var updateInfo = new UpdateCheckResult
            {
                UpdateAvailable = true,
                CanDownload = true,
                DownloadUrl = "https://api.test/download/cdl.msi",
                InstallerFileName = "cdl.msi",
                AssetDigest = Sha256Digest(newBytes)
            };

            try
            {
                // Act
                var result = await service.DownloadUpdateAsync(updateInfo);

                // Assert
                Assert.Equal(targetPath, result.FilePath);
                Assert.Equal(newBytes, await File.ReadAllBytesAsync(targetPath));
                Assert.Empty(Directory.GetFiles(tempDirectory, "*.tmp"));
            }
            finally
            {
                Directory.Delete(tempDirectory, recursive: true);
            }
        }

        private static GitHubUpdateService CreateService(
            Dictionary<string, HttpResponseMessage> responses,
            string currentVersion,
            UpdatePlatform platform,
            UpdateChannel channel = UpdateChannel.Stable,
            string? downloadDirectory = null)
        {
            var client = new HttpClient(new StubHttpMessageHandler(responses))
            {
                BaseAddress = new Uri("https://api.test")
            };

            return new GitHubUpdateService(
                client,
                new UpdateServiceOptions
                {
                    ApiBaseUrl = "https://api.test",
                    CurrentVersion = currentVersion,
                    PlatformDetector = () => platform,
                    DownloadDirectoryProvider = () => downloadDirectory ?? CreateTempDirectory()
                },
                () => channel,
                disposeHttpClient: true);
        }

        private static HttpResponseMessage JsonResponse(string json)
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        }

        private static string CreateReleaseJson(
            string tagName,
            string body,
            params (string name, string url, string? digest)[] assets)
        {
            return $$"""
                   {
                     "tag_name": "{{tagName}}",
                     "name": "ColDog Locker {{tagName}}",
                     "body": {{JsonSerializer.Serialize(body)}},
                     "html_url": "https://github.example/releases/{{tagName}}",
                     "draft": false,
                     "prerelease": {{tagName.Contains('-').ToString().ToLowerInvariant()}},
                     "assets": [
                       {{string.Join(",\n    ", assets.Select(CreateAssetObject))}}
                     ]
                   }
                   """;
        }

        private static string CreateReleaseObject(
            string tagName,
            string body,
            bool draft,
            bool prerelease,
            params (string name, string url, string? digest)[] assets)
        {
            return $$"""
                   {
                     "tag_name": "{{tagName}}",
                     "name": "ColDog Locker {{tagName}}",
                     "body": {{JsonSerializer.Serialize(body)}},
                     "html_url": "https://github.example/releases/{{tagName}}",
                     "draft": {{draft.ToString().ToLowerInvariant()}},
                     "prerelease": {{prerelease.ToString().ToLowerInvariant()}},
                     "assets": [
                       {{string.Join(",\n    ", assets.Select(CreateAssetObject))}}
                     ]
                   }
                   """;
        }

        private static string CreateAssetObject((string name, string url, string? digest) asset)
        {
            var digestValue = asset.digest == null ? "null" : JsonSerializer.Serialize(asset.digest);
            return $$"""
                   {
                     "name": "{{asset.name}}",
                     "browser_download_url": "{{asset.url}}",
                     "digest": {{digestValue}},
                     "size": 100,
                     "content_type": "application/octet-stream"
                   }
                   """;
        }

        private static string Sha256Digest(string content)
        {
            return Sha256Digest(Encoding.UTF8.GetBytes(content));
        }

        private static string Sha256Digest(byte[] bytes)
        {
            return $"sha256:{Sha256Hex(bytes)}";
        }

        private static string Sha256Hex(byte[] bytes)
        {
            return Convert.ToHexStringLower(SHA256.HashData(bytes));
        }

        private static string CreateTempDirectory()
        {
            var path = Path.Combine(Path.GetTempPath(), $"cdl-update-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(path);
            return path;
        }

        private sealed class StubHttpMessageHandler : HttpMessageHandler
        {
            private readonly Dictionary<string, HttpResponseMessage> _responses;

            public StubHttpMessageHandler(Dictionary<string, HttpResponseMessage> responses)
            {
                _responses = responses;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var path = request.RequestUri?.AbsolutePath ?? string.Empty;
                if (_responses.TryGetValue(path, out var response))
                {
                    return Task.FromResult(response);
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                    Content = new StringContent($"No stubbed response for {path}")
                });
            }
        }
    }
}

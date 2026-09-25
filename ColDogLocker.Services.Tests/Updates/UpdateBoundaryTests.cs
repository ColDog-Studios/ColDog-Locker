using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Services.Tests.Updates
{
    public class UpdateBoundaryTests
    {
        [Theory]
        [InlineData("v2.0.0-rc.1", false, false)]
        [InlineData("v2.0.0", true, false)]
        [InlineData("v2.0.0", false, true)]
        public async Task StableChannel_RejectsUnsafeLatestAndFindsStableRelease(string tag, bool draft, bool prerelease)
        {
            var invalid = new GitHubReleaseDto { TagName = tag, Draft = draft, Prerelease = prerelease };
            var stable = new GitHubReleaseDto { TagName = "v1.5.0" };
            using var client = new HttpClient(new ResponseHandler(request =>
                new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(request.RequestUri!.AbsolutePath.EndsWith("/latest")
                        ? JsonSerializer.Serialize(invalid)
                        : JsonSerializer.Serialize(new[] { invalid, stable }))
                }));
            using var service = new GitHubUpdateService(client, Options(), () => UpdateChannel.Stable);

            var result = await service.CheckForUpdatesAsync();

            Assert.True(result.UpdateAvailable);
            Assert.Equal("1.5.0", result.LatestVersion);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task Download_StalledBodyHonorsDeadlineOrCallerCancellationAndCleansTemp(bool cancelByCaller)
        {
            var directory = Path.Join(Path.GetTempPath(), $"cdl-deadline-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var stream = new StalledStream();
            using var client = new HttpClient(new ResponseHandler(_ =>
                new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }));
            var options = Options();
            options.DownloadDirectoryProvider = () => directory;
            options.DownloadTimeout = cancelByCaller ? TimeSpan.FromMinutes(1) : TimeSpan.FromMilliseconds(100);
            using var service = new GitHubUpdateService(client, options);
            using var cancellation = new CancellationTokenSource();
            var update = new UpdateCheckResult
            {
                UpdateAvailable = true,
                CanDownload = true,
                DownloadUrl = "https://api.test/update.msi",
                InstallerFileName = "update.msi",
                AssetDigest = $"sha256:{new string('0', 64)}"
            };

            try
            {
                var download = service.DownloadUpdateAsync(update, cancellation.Token);
                if (cancelByCaller)
                {
                    await stream.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
                    cancellation.Cancel();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => download);
                }
                else
                {
                    var error = await Assert.ThrowsAsync<UpdateException>(() => download.WaitAsync(TimeSpan.FromSeconds(5)));
                    Assert.Equal(UpdateFailureKind.Timeout, error.FailureKind);
                }

                Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
            }
            finally
            {
                Directory.Delete(directory, true);
            }
        }

        private static UpdateServiceOptions Options()
        {
            return new UpdateServiceOptions
            {
                ApiBaseUrl = "https://api.test",
                CurrentVersion = "1.0.0",
                AllowedDownloadHosts = ["api.test"],
                PlatformDetector = () => new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = Architecture.X64 }
            };
        }

        private sealed class ResponseHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(respond(request));
            }
        }

        private sealed class StalledStream : Stream
        {
            public TaskCompletionSource ReadStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                ReadStarted.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return 0;
            }

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override void Flush() => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}

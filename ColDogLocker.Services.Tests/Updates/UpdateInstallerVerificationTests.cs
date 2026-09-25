using System.Runtime.Versioning;
using System.Security.Cryptography;
using ColDogStudios.ColDogLocker.Services.Tests.FileSystem;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Services.Tests.Updates
{
    public sealed class UpdateInstallerVerificationTests : IDisposable
    {
        private readonly string _directory = Path.Join(Path.GetTempPath(), $"cdl-install-verify-{Guid.NewGuid():N}");
        private readonly UpdatePlatform _platform = new() { OperatingSystem = UpdateOperatingSystem.Windows };
        private int _launches;

        public UpdateInstallerVerificationTests() => Directory.CreateDirectory(_directory);

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("abc")]
        [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
        public async Task InvalidDigest_RefusesBeforeLaunching(string? digest)
        {
            var path = WriteInstaller();
            var error = await Assert.ThrowsAsync<UpdateException>(() =>
                CreateInstaller().InstallAsync(path, digest!, _platform));

            Assert.Equal(UpdateFailureKind.MissingDigest, error.FailureKind);
            Assert.Equal(0, _launches);
            Assert.Equal("original installer", File.ReadAllText(path));
        }

        [Fact]
        public async Task ReplacedDownload_RefusesBeforeLaunchingAndPreservesFile()
        {
            var path = WriteInstaller();
            var digest = Hash(path);
            File.WriteAllText(path, "replacement installer");

            var error = await Assert.ThrowsAsync<UpdateException>(() =>
                CreateInstaller().InstallAsync(path, digest, _platform));

            Assert.Equal(UpdateFailureKind.DigestMismatch, error.FailureKind);
            Assert.Equal(0, _launches);
            Assert.Equal("replacement installer", File.ReadAllText(path));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task MatchingDownload_LaunchesOnce(bool lowerCase)
        {
            var path = WriteInstaller();
            var digest = Hash(path);
            var result = await CreateInstaller().InstallAsync(path, lowerCase ? digest.ToLowerInvariant() : digest, _platform);

            Assert.True(result.InstallerStarted);
            Assert.Equal(1, _launches);
            Assert.Equal("original installer", File.ReadAllText(path));
        }

        [UnixFact]
        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        public async Task MatchingDownload_TightensStagingDirectoryBeforeLaunch()
        {
            var path = WriteInstaller();
            File.SetUnixFileMode(_directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);

            await CreateInstaller().InstallAsync(path, Hash(path), _platform);

            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                File.GetUnixFileMode(_directory));
            Assert.Equal(1, _launches);
        }

        [Fact]
        public async Task CancelledVerification_DoesNotLaunch()
        {
            var path = WriteInstaller();
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CreateInstaller().InstallAsync(path, Hash(path), _platform, cancellation.Token));

            Assert.Equal(0, _launches);
        }

        [UnixFact]
        public async Task SymlinkDownload_RefusesEvenWhenTargetHasMatchingBytes()
        {
            var path = WriteInstaller();
            var link = Path.Join(_directory, "linked.msi");
            File.CreateSymbolicLink(link, path);

            var error = await Assert.ThrowsAsync<UpdateException>(() =>
                CreateInstaller().InstallAsync(link, Hash(path), _platform));

            Assert.Equal(UpdateFailureKind.InstallFailed, error.FailureKind);
            Assert.Equal(0, _launches);
            Assert.Equal("original installer", File.ReadAllText(path));
        }

        [UnixFact]
        public async Task LinkedStagingDirectory_RefusesBeforeLaunching()
        {
            var target = Directory.CreateDirectory(Path.Join(_directory, "target")).FullName;
            var installer = Path.Join(target, "update.msi");
            File.WriteAllText(installer, "original installer");
            var link = Path.Join(_directory, "linked");
            Directory.CreateSymbolicLink(link, target);

            var error = await Assert.ThrowsAsync<UpdateException>(() =>
                CreateInstaller().InstallAsync(Path.Join(link, "update.msi"), Hash(installer), _platform));

            Assert.Equal(UpdateFailureKind.InstallFailed, error.FailureKind);
            Assert.Equal(0, _launches);
            Assert.Equal("original installer", File.ReadAllText(installer));
        }

        [Fact]
        public async Task PublicService_UsesDownloadDigestForInstallation()
        {
            var path = WriteInstaller();
            var download = new UpdateDownloadResult { FilePath = path, Sha256 = Hash(path) };
            File.WriteAllText(path, "replacement installer");
            using var client = new HttpClient();
            using var service = new GitHubUpdateService(client, new UpdateServiceOptions { PlatformDetector = () => _platform });

            var error = await Assert.ThrowsAsync<UpdateException>(() => service.InstallUpdateAsync(download));

            Assert.Equal(UpdateFailureKind.DigestMismatch, error.FailureKind);
            Assert.Equal("replacement installer", File.ReadAllText(path));
        }

        private string WriteInstaller()
        {
            var path = Path.Join(_directory, "update.msi");
            File.WriteAllText(path, "original installer");
            return path;
        }

        private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

        private UpdateInstaller CreateInstaller() => new(
            _ => true,
            () => false,
            _ => null,
            (_, waitForExit, _) =>
            {
                _launches++;
                return Task.FromResult(new UpdateProcessResult(waitForExit ? 0 : null));
            });

        public void Dispose() => Directory.Delete(_directory, recursive: true);
    }
}

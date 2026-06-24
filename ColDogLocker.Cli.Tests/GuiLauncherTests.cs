using System.Diagnostics;
using ColDogStudios.ColDogLocker.Cli;

namespace ColDogStudios.ColDogLocker.Cli.Tests
{
    public sealed class GuiLauncherTests
    {
        private const string MacAppExecutable = "/Applications/ColDog Locker.app/Contents/MacOS/ColDogLocker";
        private const string LinuxInstalledExecutable = "/opt/coldog-locker/ColDogLocker";

        [Fact]
        public void GetCandidatePaths_WhenMacOs_IncludesInstalledAppBundleExecutable()
        {
            var environment = CreateEnvironment(isMacOS: true, isLinux: false, isWindows: false);

            var candidates = GuiLauncher.GetCandidatePaths(environment).ToArray();

            Assert.Contains(MacAppExecutable, candidates);
        }

        [Fact]
        public void GetCandidatePaths_WhenLinux_IncludesInstalledOptExecutable()
        {
            var environment = CreateEnvironment(isMacOS: false, isLinux: true, isWindows: false);

            var candidates = GuiLauncher.GetCandidatePaths(environment).ToArray();

            Assert.Contains(LinuxInstalledExecutable, candidates);
        }

        [Fact]
        public void Launch_WhenLinuxInstalledGuiExists_StartsOptExecutable()
        {
            var expectedExecutable = Path.GetFullPath(LinuxInstalledExecutable);
            ProcessStartInfo? startedProcessInfo = null;
            var process = new TestGuiProcess();
            var environment = CreateEnvironment(
                isMacOS: false,
                isLinux: true,
                isWindows: false,
                fileExists: path => string.Equals(path, expectedExecutable, StringComparison.Ordinal),
                startProcess: startInfo =>
                {
                    startedProcessInfo = startInfo;
                    return process;
                });

            var exitCode = GuiLauncher.Launch([], environment);

            Assert.Equal(0, exitCode);
            Assert.NotNull(startedProcessInfo);
            Assert.Equal(expectedExecutable, startedProcessInfo.FileName);
            Assert.True(startedProcessInfo.UseShellExecute);
            Assert.True(process.Disposed);
        }

        [Fact]
        public void Launch_WhenLinuxInstalledGuiIsMissing_ReturnsExecutableNotFoundError()
        {
            using var errorWriter = new StringWriter();
            var originalError = Console.Error;

            try
            {
                Console.SetError(errorWriter);
                var environment = CreateEnvironment(isMacOS: false, isLinux: true, isWindows: false);

                var exitCode = GuiLauncher.Launch([], environment);

                Assert.Equal(1, exitCode);
                Assert.Contains("Could not find the Avalonia GUI executable", errorWriter.ToString());
            }
            finally
            {
                Console.SetError(originalError);
            }
        }

        [Fact]
        public void GetCandidatePaths_WhenWindows_UsesExeName()
        {
            var environment = CreateEnvironment(isMacOS: false, isLinux: false, isWindows: true);

            var candidates = GuiLauncher.GetCandidatePaths(environment).ToArray();

            Assert.Contains(candidates, candidate => candidate.EndsWith("ColDogLocker.exe", StringComparison.Ordinal));
            Assert.DoesNotContain(MacAppExecutable, candidates);
            Assert.DoesNotContain(LinuxInstalledExecutable, candidates);
        }

        [Fact]
        public void GetCandidatePaths_WhenUnixSourceBuild_UsesUnixExecutableName()
        {
            var environment = CreateEnvironment(isMacOS: false, isLinux: false, isWindows: false);

            var candidates = GuiLauncher.GetCandidatePaths(environment).ToArray();

            Assert.Contains(candidates, candidate => candidate.EndsWith("ColDogLocker", StringComparison.Ordinal));
            Assert.DoesNotContain(candidates, candidate => candidate.EndsWith("ColDogLocker.exe", StringComparison.Ordinal));
        }

        [Fact]
        public void Launch_WhenProcessCannotStart_ReturnsFailure()
        {
            var baseDirectory = Path.Join(Path.GetTempPath(), $"cdlocker-gui-launcher-tests-{Guid.NewGuid():N}");
            var expectedExecutable = Path.GetFullPath(Path.Combine(baseDirectory, "ColDogLocker"));
            var environment = CreateEnvironment(
                isMacOS: false,
                isLinux: true,
                isWindows: false,
                baseDirectory: baseDirectory,
                fileExists: path => string.Equals(path, expectedExecutable, StringComparison.Ordinal),
                startProcess: _ => null);

            var exitCode = GuiLauncher.Launch([], environment);

            Assert.Equal(1, exitCode);
        }

        [Fact]
        public void Launch_WhenMacOsInstalledAppExists_StartsAppBundleExecutable()
        {
            var expectedExecutable = Path.GetFullPath(MacAppExecutable);
            ProcessStartInfo? startedProcessInfo = null;
            var process = new TestGuiProcess();
            var environment = CreateEnvironment(
                isMacOS: true,
                isLinux: false,
                isWindows: false,
                fileExists: path => string.Equals(path, expectedExecutable, StringComparison.Ordinal),
                startProcess: startInfo =>
                {
                    startedProcessInfo = startInfo;
                    return process;
                });

            var exitCode = GuiLauncher.Launch(["--test-mode", "macos"], environment);

            Assert.Equal(0, exitCode);
            Assert.NotNull(startedProcessInfo);
            Assert.Equal(expectedExecutable, startedProcessInfo.FileName);
            Assert.True(startedProcessInfo.UseShellExecute);
            Assert.Equal(["--test-mode", "macos"], startedProcessInfo.ArgumentList);
            Assert.True(process.Disposed);
        }

        [Fact]
        public void Launch_WhenMacOsInstalledAppIsMissing_ReturnsExecutableNotFoundError()
        {
            using var errorWriter = new StringWriter();
            var originalError = Console.Error;

            try
            {
                Console.SetError(errorWriter);
                var environment = CreateEnvironment(isMacOS: true, isLinux: false, isWindows: false);

                var exitCode = GuiLauncher.Launch([], environment);

                var error = errorWriter.ToString();
                Assert.Equal(1, exitCode);
                Assert.Contains("Could not find the Avalonia GUI executable", error);
                Assert.DoesNotContain("not yet available on macOS", error);
            }
            finally
            {
                Console.SetError(originalError);
            }
        }

        [Fact]
        public void GetCandidatePaths_WhenSourceTreeAndInstalledFallbackExist_PrefersSourceTreeBeforeInstalledFallback()
        {
            var sourceRoot = Path.Join(Path.GetTempPath(), $"cdlocker-source-{Guid.NewGuid():N}");
            var baseDirectory = Path.Combine(sourceRoot, "ColDogLocker.Cli", "bin", "Debug", "net10.0");
            var sourceCandidate = Path.Combine(sourceRoot, "ColDogLocker.Avalonia", "bin", "Debug", "net10.0", "ColDogLocker");
            var environment = CreateEnvironment(
                isMacOS: false,
                isLinux: true,
                isWindows: false,
                baseDirectory: baseDirectory,
                fileExists: path => string.Equals(path, Path.Combine(sourceRoot, "ColDogLocker.slnx"), StringComparison.Ordinal),
                directoryExists: path =>
                    string.Equals(path, Path.Combine(sourceRoot, "ColDogLocker.Avalonia"), StringComparison.Ordinal) ||
                    string.Equals(path, Path.Combine(sourceRoot, "ColDogLocker.Cli"), StringComparison.Ordinal));

            var candidates = GuiLauncher.GetCandidatePaths(environment).ToArray();

            Assert.True(
                Array.IndexOf(candidates, sourceCandidate) < Array.IndexOf(candidates, LinuxInstalledExecutable),
                "Source-tree GUI candidates should be checked before installed package fallbacks.");
        }

        private static GuiLauncherEnvironment CreateEnvironment(
            bool isMacOS,
            bool isLinux,
            bool isWindows,
            string? baseDirectory = null,
            Func<string, bool>? fileExists = null,
            Func<string, bool>? directoryExists = null,
            Func<ProcessStartInfo, IGuiProcess?>? startProcess = null)
        {
            return new GuiLauncherEnvironment
            {
                BaseDirectory = baseDirectory ?? Path.Join(Path.GetTempPath(), $"cdlocker-gui-launcher-tests-{Guid.NewGuid():N}"),
                IsMacOS = isMacOS,
                IsLinux = isLinux,
                IsWindows = isWindows,
                FileExists = fileExists ?? (_ => false),
                DirectoryExists = directoryExists ?? (_ => false),
                StartProcess = startProcess ?? (_ => throw new InvalidOperationException("Process start was not expected."))
            };
        }

        private sealed class TestGuiProcess : IGuiProcess
        {
            public int Id => 42;

            public bool Disposed { get; private set; }

            public void Dispose()
            {
                Disposed = true;
            }
        }
    }
}

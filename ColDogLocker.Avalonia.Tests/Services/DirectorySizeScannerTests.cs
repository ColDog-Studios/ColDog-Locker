using ColDogStudios.ColDogLocker.Avalonia.Models;
using ColDogStudios.ColDogLocker.Avalonia.Services;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests.Services
{
    public sealed class DirectorySizeScannerTests : IDisposable
    {
        private readonly string _root = Directory.CreateTempSubdirectory("cdl-scan-").FullName;

        [Fact]
        public void EmptyDirectoryIsZeroButMissingDirectoryIsUnknown()
        {
            Assert.Equal(0L, DirectorySizeScanner.Calculate(_root, TestContext.Current.CancellationToken));
            Assert.Null(DirectorySizeScanner.Calculate(Path.Join(_root, "missing"), TestContext.Current.CancellationToken));
            Assert.Equal("Unknown", new LockerItemViewModel().SizeText);
            Assert.Equal("0 B", new LockerItemViewModel { Size = 0 }.SizeText);
        }

        [Fact]
        public void CountsNestedFilesAndRefusesPartialTotalsAtLimits()
        {
            File.WriteAllBytes(Path.Join(_root, "first"), new byte[12]);
            var child = Directory.CreateDirectory(Path.Join(_root, "child")).FullName;
            File.WriteAllBytes(Path.Join(child, "second"), new byte[23]);
            Assert.Equal(35L, DirectorySizeScanner.Calculate(_root, TestContext.Current.CancellationToken));
            Assert.Null(DirectorySizeScanner.Calculate(_root, TestContext.Current.CancellationToken, maxEntries: 1));
            Assert.Null(DirectorySizeScanner.Calculate(_root, TestContext.Current.CancellationToken, maxDepth: 0));
            Assert.Null(DirectorySizeScanner.Calculate(_root, TestContext.Current.CancellationToken, timeLimit: TimeSpan.Zero));
        }

        [Fact]
        public void CancellationIsPropagatedInsteadOfReportedAsZero()
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            Assert.Throws<OperationCanceledException>(() => DirectorySizeScanner.Calculate(_root, cancellation.Token));
        }

        [Fact]
        public void DirectoryLinkCycleIsUnknownInsteadOfTraversed()
        {
            if (OperatingSystem.IsWindows())
            {
                Assert.Skip("Creating Windows symlinks requires host privileges; Unix link policy test.");
            }

            Directory.CreateSymbolicLink(Path.Join(_root, "loop"), _root);
            Assert.Null(DirectorySizeScanner.Calculate(_root, TestContext.Current.CancellationToken));
            Assert.Null(DirectorySizeScanner.Calculate(Path.Join(_root, "loop"), TestContext.Current.CancellationToken));
        }

        public void Dispose() => Directory.Delete(_root, true);
    }
}

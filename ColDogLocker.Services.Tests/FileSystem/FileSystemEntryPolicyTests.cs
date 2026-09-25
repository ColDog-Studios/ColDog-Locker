using System.Diagnostics;
using System.Net.Sockets;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public sealed class FileSystemEntryPolicyTests : IDisposable
    {
        private readonly string _root = Directory.CreateTempSubdirectory("cdl-kind-").FullName;

        [UnixTheory]
        [InlineData("fifo")]
        [InlineData("symlink")]
        public async Task ReplacementBetweenInspectionAndOpenIsRejected(string kind)
        {
            var path = Path.Join(_root, "original");
            var retained = Path.Join(_root, "retained");
            var unrelated = Path.Join(_root, "unrelated");
            File.WriteAllText(path, "original bytes");
            File.WriteAllText(unrelated, "unrelated bytes");
            var failure = await Record.ExceptionAsync(async () => await Task.Run(() =>
            {
                using var stream = FileSystemEntryPolicy.OpenRead(path, () =>
                {
                    File.Move(path, retained);
                    if (kind == "symlink")
                    {
                        File.CreateSymbolicLink(path, unrelated);
                    }
                    else
                    {
                        var start = new ProcessStartInfo("mkfifo") { UseShellExecute = false };
                        start.ArgumentList.Add(path);
                        using var process = Process.Start(start)!;
                        Assert.True(process.WaitForExit(5000));
                        Assert.Equal(0, process.ExitCode);
                    }
                });
            }).WaitAsync(TimeSpan.FromSeconds(10)));
            if (kind == "fifo")
            {
                Assert.IsType<InvalidDataException>(failure);
            }
            else
            {
                Assert.IsType<IOException>(failure);
            }

            Assert.Equal("original bytes", File.ReadAllText(retained));
            Assert.Equal("unrelated bytes", File.ReadAllText(unrelated));
        }

        [Fact]
        public void DifferentRegularFileReplacementBetweenInspectionAndOpenIsRejected()
        {
            var path = Path.Join(_root, "original");
            var retained = Path.Join(_root, "retained");
            var replacement = Path.Join(_root, "replacement");
            File.WriteAllText(path, "same length");
            File.WriteAllText(replacement, "other data!");
            File.SetLastWriteTimeUtc(replacement, File.GetLastWriteTimeUtc(path));

            Assert.Throws<IOException>(() => FileSystemEntryPolicy.OpenRead(path, () =>
            {
                File.Move(path, retained);
                File.Move(replacement, path);
            }));

            Assert.Equal("same length", File.ReadAllText(retained));
            Assert.Equal("other data!", File.ReadAllText(path));
        }

        [UnixFact]
        public void OpenedReaderStaysOnOriginalFileAfterPathReplacement()
        {
            var path = Path.Join(_root, "original");
            File.WriteAllText(path, "original bytes");
            using var stream = FileSystemEntryPolicy.OpenRead(path);
            File.Move(path, Path.Join(_root, "retained"));
            File.WriteAllText(path, "replacement bytes");
            using var reader = new StreamReader(stream);
            Assert.Equal("original bytes", reader.ReadToEnd());
            Assert.Equal("replacement bytes", File.ReadAllText(path));
        }

        [UnixFact]
        public void ReadHonorsAnExistingExclusiveManagedFileLock()
        {
            var path = Path.Join(_root, "original");
            File.WriteAllText(path, "original bytes");
            using (var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.Throws<IOException>(() => FileSystemEntryPolicy.OpenRead(path));
            }

            using var stream = FileSystemEntryPolicy.OpenRead(path);
            using var reader = new StreamReader(stream);
            Assert.Equal("original bytes", reader.ReadToEnd());
        }

        [Fact]
        public void RegularFileAndDirectoryAreAccepted()
        {
            var file = Path.Join(_root, "regular");
            File.WriteAllText(file, "ordinary bytes");
            FileSystemEntryPolicy.EnsureSupported(new DirectoryInfo(_root));
            FileSystemEntryPolicy.EnsureSupported(new FileInfo(file));
            Assert.Equal("ordinary bytes", File.ReadAllText(file));
        }

        [Fact]
        public void MissingEntryIsRejected()
        {
            Assert.Throws<InvalidDataException>(() => FileSystemEntryPolicy.EnsureSupported(new FileInfo(Path.Join(_root, "missing"))));
        }

        [UnixFact]
        public void UnixCharacterDeviceIsRejectedWithoutReadingIt()
        {
            Assert.Throws<InvalidDataException>(() => FileSystemEntryPolicy.EnsureSupported(new FileInfo("/dev/null")));
        }

        [UnixTheory]
        [InlineData("fifo")]
        [InlineData("socket")]
        public async Task UnsupportedEntriesAbortArchiveAndDigestWithoutReadingData(string kind)
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            var original = Path.Join(source, "original.txt");
            File.WriteAllText(original, "preserve me");
            var special = Path.Join(source, "special");
            using var socket = kind == "socket" ? new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified) : null;
            if (socket != null)
            {
                socket.Bind(new UnixDomainSocketEndPoint(special));
            }
            else
            {
                var start = new ProcessStartInfo("mkfifo") { UseShellExecute = false };
                start.ArgumentList.Add(special);
                using var process = Process.Start(start)!;
                await process.WaitForExitAsync(CancellationToken.None);
                Assert.Equal(0, process.ExitCode);
            }

            var archive = Path.Join(_root, "locker.cdl");
            var locker = new LockerModel("Vault", "unused verifier", source);
            await Assert.ThrowsAsync<InvalidDataException>(async () => await Task.Run(() =>
                LockerArchiveService.CreateFromDirectory(source, archive, locker, "Violet!River9Moon"), CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(async () => await Task.Run(() => LockerTreeDigest.Compute(source), CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(async () => await Task.Run(() => LockerArchiveService.ReadMetadata(special), CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(async () => await Task.Run(() => LockerArchiveService.ComputeSha256(special), CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None));
            Assert.False(File.Exists(archive));
            Assert.Equal("preserve me", File.ReadAllText(original));
            Assert.Contains(special, Directory.EnumerateFileSystemEntries(source));
        }

        public void Dispose() => Directory.Delete(_root, true);
    }

    public sealed class UnixFactAttribute : FactAttribute
    {
        public UnixFactAttribute()
        {
            if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            {
                Skip = "Unix filesystem entry types require a Unix host.";
            }
        }
    }

    public sealed class UnixTheoryAttribute : TheoryAttribute
    {
        public UnixTheoryAttribute()
        {
            if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            {
                Skip = "Unix filesystem entry types require a Unix host.";
            }
        }
    }
}

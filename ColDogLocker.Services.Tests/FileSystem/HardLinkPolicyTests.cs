using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public sealed class HardLinkPolicyTests : IDisposable
    {
        private readonly string _root = Directory.CreateTempSubdirectory("cdl-hardlink-").FullName;

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ArchiveRefusesInternalAndExternalAliasesWithoutChangingOriginals(bool outside)
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            var original = Path.Join(source, "original");
            var alias = Path.Join(outside ? _root : source, "alias");
            File.WriteAllText(original, "preserve these bytes");
            Link(original, alias);
            var archive = Path.Join(_root, "locker.cdl");
            var locker = new LockerModel("Vault", "unused", source);

            var error = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.CreateFromDirectory(source, archive, locker, "River!Cobalt8Fern"));

            Assert.Contains("Hard-linked", error.Message);
            Assert.False(File.Exists(archive));
            Assert.Equal("preserve these bytes", File.ReadAllText(original));
            Assert.Equal("preserve these bytes", File.ReadAllText(alias));
            Assert.Throws<InvalidDataException>(() => LockerTreeDigest.Compute(source));

            // Read-only archive/input hashing has no relationship-preservation requirement.
            Assert.Equal(LockerArchiveService.ComputeSha256(original), LockerArchiveService.ComputeSha256(alias));

            File.Delete(alias);
            LockerArchiveService.CreateFromDirectory(source, archive, locker, "River!Cobalt8Fern");
            var archiveBackup = Path.Join(_root, "backup.cdl");
            Link(archive, archiveBackup);
            Assert.Equal("Vault", LockerArchiveService.ReadMetadata(archiveBackup).LockerName);
            var restored = Path.Join(_root, "restored");
            LockerArchiveService.ExtractToDirectory(archiveBackup, restored, locker, "River!Cobalt8Fern");
            Assert.Equal("preserve these bytes", File.ReadAllText(Path.Join(restored, "original")));
            Assert.Equal(LockerArchiveService.ComputeSha256(archive), LockerArchiveService.ComputeSha256(archiveBackup));
        }

        [Fact]
        public void LinkAddedAfterPreflightIsRejectedByOpenedHandle()
        {
            var original = Path.Join(_root, "original");
            var alias = Path.Join(_root, "alias");
            File.WriteAllText(original, "preserve these bytes");

            Assert.Throws<InvalidDataException>(() =>
                FileSystemEntryPolicy.OpenRead(original, () => Link(original, alias), rejectHardLinks: true));

            Assert.Equal("preserve these bytes", File.ReadAllText(original));
            Assert.Equal("preserve these bytes", File.ReadAllText(alias));
            // A failed inspection must release its handle.
            using var exclusive = new FileStream(original, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }

        [Fact]
        public void SingleLinkedFilesAndDirectoriesAreAccepted()
        {
            Directory.CreateDirectory(Path.Join(_root, "child"));
            var original = Path.Join(_root, "original");
            File.WriteAllText(original, "ordinary");
            FileSystemEntryPolicy.EnsureSupported(new DirectoryInfo(_root), rejectHardLinks: true);
            FileSystemEntryPolicy.EnsureSupported(new FileInfo(original), rejectHardLinks: true);
            using var stream = FileSystemEntryPolicy.OpenRead(original, rejectHardLinks: true);
            using var reader = new StreamReader(stream);
            Assert.Equal("ordinary", reader.ReadToEnd());
        }

        private static void Link(string original, string alias)
        {
            var success = OperatingSystem.IsWindows() ? CreateHardLink(alias, original, IntPtr.Zero)
                : OperatingSystem.IsMacOS() ? DarwinLink(original, alias) == 0 : LinuxLink(original, alias) == 0;
            Assert.True(success, $"Creating test hard link failed: {Marshal.GetLastPInvokeError()}");
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateHardLink(string newName, string existingName, IntPtr securityAttributes);

        [DllImport("libc", EntryPoint = "link", SetLastError = true)]
        private static extern int LinuxLink([MarshalAs(UnmanagedType.LPUTF8Str)] string original, [MarshalAs(UnmanagedType.LPUTF8Str)] string alias);

        [DllImport("libSystem.B.dylib", EntryPoint = "link", SetLastError = true)]
        private static extern int DarwinLink([MarshalAs(UnmanagedType.LPUTF8Str)] string original, [MarshalAs(UnmanagedType.LPUTF8Str)] string alias);

        public void Dispose() => Directory.Delete(_root, true);
    }
}

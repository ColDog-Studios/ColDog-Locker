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

using System.Buffers.Binary;
using System.Formats.Tar;
using System.Text;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public class LockerArchiveServiceTests
    {
        private const string Password = "CorrectHorseBatteryStaple123!";

        [Fact]
        public void CreateAndExtract_ShouldRestoreNestedFilesAndEmptyDirectories()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("PlainLocker");
            Directory.CreateDirectory(Path.Combine(source, "empty"));
            var nested = Directory.CreateDirectory(Path.Combine(source, "nested"));
            File.WriteAllText(Path.Combine(source, "root.txt"), "root secret");
            File.WriteAllText(Path.Combine(nested.FullName, "nested.txt"), "nested secret");

            var locker = CreateLocker("PlainLocker", source);
            var archivePath = Path.Combine(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);

            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);
            var restored = Path.Combine(workspace.Path, "restored");
            LockerArchiveService.ExtractToDirectory(archive.ArchivePath, restored, locker, Password);

            Assert.Equal("root secret", File.ReadAllText(Path.Combine(restored, "root.txt")));
            Assert.Equal("nested secret", File.ReadAllText(Path.Combine(restored, "nested", "nested.txt")));
            Assert.True(Directory.Exists(Path.Combine(restored, "empty")));
        }

        [Fact]
        public void Extract_WithTamperedArchive_ShouldThrow()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Combine(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Combine(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);

            var bytes = File.ReadAllBytes(archive.ArchivePath);
            bytes[^1] ^= 0x01;
            WriteArchiveBytesForTamperTest(archive.ArchivePath, bytes);

            Assert.ThrowsAny<Exception>(() =>
                LockerArchiveService.ExtractToDirectory(archive.ArchivePath, Path.Combine(workspace.Path, "restored"), locker, Password));
        }

        [Fact]
        public void ComputeSha256_ShouldChangeAfterArchiveTampering()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Combine(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Combine(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);

            var originalHash = archive.Sha256;
            using (var stream = new FileStream(archive.ArchivePath, FileMode.Open, FileAccess.ReadWrite))
            {
                stream.Position = stream.Length - 1;
                var value = stream.ReadByte();
                stream.Position = stream.Length - 1;
                stream.WriteByte((byte)(value ^ 0x01));
            }

            Assert.NotEqual(originalHash, LockerArchiveService.ComputeSha256(archive.ArchivePath));
        }

        [Fact]
        public void VerifyArchive_WithMetadataMismatch_ShouldFail()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Combine(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Combine(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);
            var otherLocker = CreateLocker("Locker", source);

            var result = LockerArchiveService.VerifyArchive(archive.ArchivePath, otherLocker, archive.Sha256);

            Assert.False(result.IsValid);
            Assert.True(result.HashMatches);
            Assert.False(result.MetadataMatches);
            Assert.Contains(result.Errors, error => error.Contains("metadata does not match"));
        }

        [Fact]
        public void CreateFromDirectory_ShouldNotWritePlaintextArchiveTempFile()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Combine(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Combine(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);

            LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);

            var plaintextArchiveFiles = Directory
                .EnumerateFiles(workspace.Path, "*", SearchOption.AllDirectories)
                .Where(path => path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
                               path.EndsWith(".tar", StringComparison.OrdinalIgnoreCase) ||
                               path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                .ToList();

            Assert.Empty(plaintextArchiveFiles);
        }

        [Fact]
        public void ExtractValidatedTar_WithTraversalEntry_ShouldThrow()
        {
            using var workspace = TestWorkspace.Create();
            using var tarStream = CreateTarStream(new PaxTarEntry(TarEntryType.RegularFile, "../escape.txt")
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes("escape"))
            });

            Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.ExtractValidatedTar(tarStream, workspace.CreateDirectory("restore")));
        }

        [Fact]
        public void ExtractValidatedTar_WithBackslashTraversalEntry_ShouldThrow()
        {
            using var workspace = TestWorkspace.Create();
            using var tarStream = CreateTarStream(new PaxTarEntry(TarEntryType.RegularFile, @"nested\escape.txt")
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes("escape"))
            });

            Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.ExtractValidatedTar(tarStream, workspace.CreateDirectory("restore")));
        }

        [Fact]
        public void ExtractValidatedTar_WithLinkEntry_ShouldThrow()
        {
            using var workspace = TestWorkspace.Create();
            using var tarStream = CreateTarStream(new PaxTarEntry(TarEntryType.SymbolicLink, "link") { LinkName = "target.txt" });

            Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.ExtractValidatedTar(tarStream, workspace.CreateDirectory("restore")));
        }

        [Fact]
        public void VerifyArchive_WithLockedAtMismatch_ShouldFail()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Combine(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Combine(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);
            locker.LockedAtUtc = archive.LockedAtUtc.AddMinutes(1);

            var result = LockerArchiveService.VerifyArchive(archive.ArchivePath, locker, archive.Sha256);

            Assert.False(result.IsValid);
            Assert.False(result.MetadataMatches);
            Assert.Contains(result.Errors, error => error.Contains("metadata does not match"));
        }

        [Fact]
        public void CreateFromDirectory_WithSourceSymlink_ShouldThrowWhenSymlinkCreationIsSupported()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            var target = Path.Combine(source, "target.txt");
            var link = Path.Combine(source, "link.txt");
            File.WriteAllText(target, "secret");

            try
            {
                File.CreateSymbolicLink(link, target);
            }
            catch (Exception) when (!File.Exists(link))
            {
                return;
            }

            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Combine(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);

            Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password));
        }

        [Fact]
        public void Extract_WithUnexpectedPbkdf2Iterations_ShouldThrowBeforeDecrypting()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Combine(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Combine(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);

            var bytes = File.ReadAllBytes(archive.ArchivePath);
            const int IterationOffset = 7 + 4 + 16 + 8;
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(IterationOffset, 4), 999999);
            WriteArchiveBytesForTamperTest(archive.ArchivePath, bytes);

            var exception = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.ExtractToDirectory(archive.ArchivePath, Path.Combine(workspace.Path, "restored"), locker, Password));
            Assert.Contains("key derivation", exception.Message);
        }

        private static LockerModel CreateLocker(string name, string path)
        {
            return new LockerModel(name, "hashed-password", path) { Guid = Guid.NewGuid().ToString() };
        }

        private static MemoryStream CreateTarStream(params TarEntry[] entries)
        {
            var stream = new MemoryStream();
            using (var writer = new TarWriter(stream, TarEntryFormat.Pax, true))
            {
                foreach (var entry in entries)
                {
                    writer.WriteEntry(entry);
                }
            }

            stream.Position = 0;
            return stream;
        }

        private static void WriteArchiveBytesForTamperTest(string archivePath, byte[] bytes)
        {
            if (File.Exists(archivePath))
            {
                File.SetAttributes(archivePath, File.GetAttributes(archivePath) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
            }

            File.WriteAllBytes(archivePath, bytes);
        }

        private sealed class TestWorkspace : IDisposable
        {
            private TestWorkspace(string path)
            {
                Path = path;
                Directory.CreateDirectory(path);
            }

            public string Path { get; }

            public void Dispose()
            {
                if (Directory.Exists(Path))
                {
                    DeleteDirectory(Path);
                }
            }

            public static TestWorkspace Create()
            {
                return new TestWorkspace(System.IO.Path.Join(System.IO.Path.GetTempPath(), $"cdlocker-archive-tests-{Guid.NewGuid():N}"));
            }

            public string CreateDirectory(string name)
            {
                var path = System.IO.Path.Combine(Path, name);
                Directory.CreateDirectory(path);
                return path;
            }

            private static void DeleteDirectory(string path)
            {
                foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                }

                foreach (var directory in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(directory, File.GetAttributes(directory) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                }

                File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                Directory.Delete(path, true);
            }
        }
    }
}

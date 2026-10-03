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
using System.Security.Cryptography;
using System.Text;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public class LockerArchiveServiceTests
    {
        private const string Password = "CorrectHorseBatteryStaple123!";

        [Fact]
        public void Create_InsufficientDestinationSpaceFailsBeforeWritingArchive()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            var sourceFile = Path.Join(source, "payload.bin");
            File.WriteAllBytes(sourceFile, new byte[4096]);
            var archive = Path.Join(workspace.Path, "locker.cdl");
            var locker = new LockerModel("Locker", "unused", source);
            var updates = new List<string>();

            var error = Assert.Throws<IOException>(() => LockerArchiveService.CreateFromDirectory(
                source,
                archive,
                locker,
                Password,
                LockerArchiveService.MaxExtractedBytes,
                reportProgress: (message, _) => updates.Add(message),
                getAvailableBytes: _ => 0));

            Assert.Contains("Not enough free space", error.Message);
            Assert.Contains("required", error.Message);
            Assert.Contains("available", error.Message);
            Assert.Contains(updates, message => message.Contains("0 B available", StringComparison.Ordinal));
            Assert.False(File.Exists(archive));
            Assert.Equal(4096, new FileInfo(sourceFile).Length);
        }

        [Fact]
        public void Create_UnknownDestinationSpaceReportsLimitationAndContinues()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "payload.txt"), "payload");
            var archive = Path.Join(workspace.Path, "locker.cdl");
            var locker = new LockerModel("Locker", "unused", source);
            var updates = new List<string>();

            LockerArchiveService.CreateFromDirectory(
                source,
                archive,
                locker,
                Password,
                LockerArchiveService.MaxExtractedBytes,
                reportProgress: (message, _) => updates.Add(message),
                getAvailableBytes: _ => null);

            Assert.Contains(updates, message =>
                message.Contains("could not be determined", StringComparison.Ordinal));
            Assert.True(File.Exists(archive));
            Assert.Equal("payload", File.ReadAllText(Path.Join(source, "payload.txt")));
        }

        [Theory]
        [InlineData(2, false)]
        [InlineData(3, true)]
        public void Create_EntryLimitCountsNestedFilesAndDirectories(int limit, bool allowed)
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "z.txt"), "outer");
            Directory.CreateDirectory(Path.Join(source, "a"));
            File.WriteAllText(Path.Join(source, "a", "b.txt"), "nested");
            var archive = Path.Join(workspace.Path, "limited.cdl");
            var locker = new LockerModel("Locker", "unused", source);

            if (allowed)
            {
                LockerArchiveService.CreateFromDirectory(source, archive, locker, Password, 100, maxArchiveEntries: limit);
                var restored = Path.Join(workspace.Path, "restored");
                LockerArchiveService.ExtractToDirectory(archive, restored, locker, Password);
                Assert.Equal("outer", File.ReadAllText(Path.Join(restored, "z.txt")));
                Assert.Equal("nested", File.ReadAllText(Path.Join(restored, "a", "b.txt")));
            }
            else
            {
                var error = Assert.Throws<InvalidDataException>(() =>
                    LockerArchiveService.CreateFromDirectory(source, archive, locker, Password, 100, maxArchiveEntries: limit));
                Assert.Contains("too many entries", error.Message);
                Assert.False(File.Exists(archive));
            }

            Assert.Equal("outer", File.ReadAllText(Path.Join(source, "z.txt")));
            Assert.Equal("nested", File.ReadAllText(Path.Join(source, "a", "b.txt")));
        }

        [Fact]
        public void Create_EmptySourceUsesNoEntryBudget()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            var archive = Path.Join(workspace.Path, "empty.cdl");
            var locker = new LockerModel("Locker", "unused", source);
            LockerArchiveService.CreateFromDirectory(source, archive, locker, Password, 0, maxArchiveEntries: 0);
            var restored = Path.Join(workspace.Path, "restored");
            LockerArchiveService.ExtractToDirectory(archive, restored, locker, Password);
            Assert.Empty(Directory.EnumerateFileSystemEntries(restored));
        }

        [Fact]
        public void CreateAndExtract_PreservesZeroLengthFiles()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllBytes(Path.Join(source, "empty.txt"), []);
            var archive = Path.Join(workspace.Path, "empty-file.cdl");
            var locker = new LockerModel("Locker", "unused", source);
            LockerArchiveService.CreateFromDirectory(source, archive, locker, Password);
            var restored = Path.Join(workspace.Path, "restored");
            LockerArchiveService.ExtractToDirectory(archive, restored, locker, Password);
            Assert.Equal(0, new FileInfo(Path.Join(restored, "empty.txt")).Length);
        }

        [Fact]
        public void Create_ExistingArchiveDestinationIsPreserved()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            var original = Path.Join(source, "original.txt");
            File.WriteAllText(original, "source bytes");
            var archive = Path.Join(workspace.Path, "existing.cdl");
            File.WriteAllText(archive, "unrelated existing archive");
            var locker = new LockerModel("Locker", "unused", source);

            Assert.Throws<IOException>(() => LockerArchiveService.CreateFromDirectory(source, archive, locker, Password));

            Assert.Equal("unrelated existing archive", File.ReadAllText(archive));
            Assert.Equal("source bytes", File.ReadAllText(original));
        }

        [Fact]
        public void TarExtraction_KeepsStagingPrivateBeforeApplyingMetadata()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            using var workspace = TestWorkspace.Create();
            var destination = Path.Join(workspace.Path, "staging");
            using var tar = CreateTarStream(new PaxTarEntry(TarEntryType.RegularFile, "secret.txt")
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes("secret")),
                Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead
            });
            var metadata = LockerArchiveService.ExtractValidatedTar(tar, destination);
            Assert.Single(metadata);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(destination));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Join(destination, "secret.txt")));
        }

        [Fact]
        public void RoundTrip_PreservesUnixModesAndModificationTimes()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            var child = Directory.CreateDirectory(Path.Join(source, "private")).FullName;
            var secret = Path.Join(child, "secret.txt");
            var executable = Path.Join(source, "run.sh");
            File.WriteAllText(secret, "secret");
            File.WriteAllText(executable, "#!/bin/sh\nexit 0\n");
            var privateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            var privateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            File.SetUnixFileMode(source, privateDirectory);
            File.SetUnixFileMode(child, privateDirectory);
            File.SetUnixFileMode(secret, privateFile);
            File.SetUnixFileMode(executable, privateDirectory);
            var modified = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            foreach (var path in new[] { secret, executable, child, source })
            {
                File.SetLastWriteTimeUtc(path, modified);
            }

            var locker = CreateLocker("Locker", source);
            var archive = Path.Join(workspace.Path, "locker.cdl");
            LockerArchiveService.CreateFromDirectory(source, archive, locker, Password);
            var restored = Path.Join(workspace.Path, "restored");
            LockerArchiveService.ExtractToDirectory(archive, restored, locker, Password);
            foreach (var relative in new[] { "", "private", "private/secret.txt", "run.sh" })
            {
                var original = Path.Join(source, relative);
                var actual = Path.Join(restored, relative);
                Assert.Equal(File.GetUnixFileMode(original), File.GetUnixFileMode(actual));
                Assert.Equal(modified, File.GetLastWriteTimeUtc(actual));
            }
        }

        [Fact]
        public void Create_RejectsSpecialUnixPermissionsWithoutRemovingOriginals()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            var secret = Path.Join(source, "secret.txt");
            File.WriteAllText(secret, "secret");
            File.SetUnixFileMode(secret, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.SetUser);
            var archive = Path.Join(workspace.Path, "locker.cdl");
            Assert.Throws<InvalidDataException>(() => LockerArchiveService.CreateFromDirectory(source, archive, CreateLocker("Locker", source), Password));
            Assert.Equal("secret", File.ReadAllText(secret));
            Assert.False(File.Exists(archive));
        }

        [Fact]
        public void Extract_RejectsIndependentVersionOneFixtureAndPreservesInput()
        {
            // Generated with Python tarfile/gzip, hashlib PBKDF2 and cryptography AESGCM,
            // using the original v1 layout (210,000 iterations and no end marker).
            const string Fixture = "Q0RMQVJDMa0AAAAAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgdQNAMAeyJmb3JtYXRWZXJzaW9uIjoxLCJsb2NrZXJHdWlkIjoibGVnYWN5LWZpeHR1cmUiLCJsb2NrZXJOYW1lIjoiTGVnYWN5IiwibG9ja2VkQXRVdGMiOiIyMDI2LTAxLTAxVDAwOjAwOjAwWiIsImFwcFZlcnNpb24iOiIwLjExLjEtYmV0YSIsImNvbXByZXNzaW9uQXJjaGl2ZUZvcm1hdCI6InRhcitnemlwIn1xAAAA+Pd6ixrXJZMcvsqt6+4qSydtsACXS/NEvzwHp7rs5EiQPFpcxQUAunHzfzylsPJ9aW3HX6KnS5SghQgKP9GXp8EzI0kP5xM/4YG6xMNSOENXJBbGc86LDDfP/Ao/WgXjZ/Vt2fZViUTqLO9e2oQdX3XaL4Q7huighqAEnTnvTxu4";
            using var workspace = TestWorkspace.Create();
            var archivePath = Path.Join(workspace.Path, "legacy.cdl");
            File.WriteAllBytes(archivePath, Convert.FromBase64String(Fixture));
            var destination = Path.Join(workspace.Path, "restored");
            var locker = CreateLocker("Legacy", destination);
            locker.Guid = "legacy-fixture";
            Assert.Throws<InvalidDataException>(() => LockerArchiveService.ExtractToDirectory(archivePath, destination, locker, Password));
            Assert.Throws<InvalidDataException>(() => LockerArchiveService.ReadMetadata(archivePath));
            Assert.False(Directory.Exists(destination));
            Assert.Equal(Convert.FromBase64String(Fixture), File.ReadAllBytes(archivePath));
        }

        [Fact]
        public void Extract_AcceptsIndependentCurrentFormatFixture()
        {
            // Generated outside .NET with Python tarfile/gzip/hashlib and OpenSSL EVP AES-256-GCM.
            // It includes one encrypted data chunk and the authenticated version-2 terminal chunk.
            const string Fixture = "Q0RMQVJDMckAAAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhfAJwkAeyJmb3JtYXRWZXJzaW9uIjoyLCJsb2NrZXJHdWlkIjoiaW5kZXBlbmRlbnQtdjItZml4dHVyZSIsImxvY2tlck5hbWUiOiJJbmRlcGVuZGVudCIsImxvY2tlZEF0VXRjIjoiMjAyNi0wMS0wMVQwMDowMDowMFoiLCJhcHBWZXJzaW9uIjoiaW5kZXBlbmRlbnQtcHl0aG9uLW9wZW5zc2wiLCJjb21wcmVzc2lvbkFyY2hpdmVGb3JtYXQiOiJ0YXIrZ3ppcCJ9fwAAAHgCmbGfku5wWskN1liucmFgOz1xUfNSC9NbK7Dfb7ZWr+Ojzhj7YVU0/nJcSlBHJgMa3rEvBCwuGI7A0rajnJdWezUh4hZw1qWVYonPPi58506NycN6PfthnxVOae64g1XO9xlPXvoUQ7celD2towLW/+hcGi7sRS3T1myRf00iwuqvZBhADbm4KFc9W525AAAAAI6OiY+Vt39eC4tAeB+1y2M=";
            using var workspace = TestWorkspace.Create();
            var archivePath = Path.Join(workspace.Path, "independent-v2.cdl");
            var fixtureBytes = Convert.FromBase64String(Fixture);
            File.WriteAllBytes(archivePath, fixtureBytes);
            var destination = Path.Join(workspace.Path, "restored");
            var locker = CreateLocker("Independent", destination);
            locker.Guid = "independent-v2-fixture";
            locker.LockedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            LockerArchiveService.ExtractToDirectory(archivePath, destination, locker, "Violet!River9Moon");

            Assert.Equal("independent current fixture\n", File.ReadAllText(Path.Join(destination, "secret.txt")));
            Assert.Equal(fixtureBytes, File.ReadAllBytes(archivePath));
        }

        [Theory]
        [InlineData("remove")]
        [InlineData("reorder")]
        [InlineData("duplicate")]
        public void Extract_RejectsChangedChunkSequence(string mutation)
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllBytes(Path.Join(source, "random.bin"), RandomNumberGenerator.GetBytes(200000));
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locker.cdl");
            LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);
            var bytes = File.ReadAllBytes(archivePath);
            var headerLength = 39 + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(7, 4));
            var chunks = new List<byte[]>();
            var offset = headerLength;
            while (offset < bytes.Length)
            {
                var length = 20 + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset, 4));
                chunks.Add(bytes.AsSpan(offset, length).ToArray());
                offset += length;
            }

            Assert.True(chunks.Count >= 4);
            switch (mutation)
            {
                case "remove":
                    chunks.RemoveAt(1);
                    break;
                case "reorder":
                    (chunks[0], chunks[1]) = (chunks[1], chunks[0]);
                    break;
                case "duplicate":
                    chunks.Insert(1, chunks[0]);
                    break;
            }

            WriteArchiveBytesForTamperTest(archivePath, [.. bytes.AsSpan(0, headerLength).ToArray(), .. chunks.SelectMany(chunk => chunk)]);
            var destination = Path.Join(workspace.Path, "restored");
            Assert.ThrowsAny<CryptographicException>(() => LockerArchiveService.ExtractToDirectory(archivePath, destination, locker, Password));
            Assert.False(Directory.Exists(destination));
        }

        [Theory]
        [InlineData("missing")]
        [InlineData("partial")]
        [InlineData("tampered")]
        [InlineData("appended")]
        public void Extract_RejectsInvalidAuthenticatedEnding(string mutation)
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locker.cdl");
            LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);
            var bytes = File.ReadAllBytes(archivePath);
            switch (mutation)
            {
                case "missing":
                    bytes = bytes[..^20];
                    break;
                case "partial":
                    bytes = bytes[..^1];
                    break;
                case "tampered":
                    bytes[^1] ^= 1;
                    break;
                case "appended":
                    bytes = [.. bytes, 42];
                    break;
            }

            WriteArchiveBytesForTamperTest(archivePath, bytes);
            var destination = Path.Join(workspace.Path, "restored");
            var error = Record.Exception(() => LockerArchiveService.ExtractToDirectory(archivePath, destination, locker, Password));
            Assert.True(error is InvalidDataException or EndOfStreamException or CryptographicException, error?.ToString());
            Assert.False(Directory.Exists(destination));
            Assert.True(File.Exists(archivePath));
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(81921)]
        public void Extract_RejectsInvalidChunkLengthBeforeAllocation(int chunkLength)
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locker.cdl");
            LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);
            var bytes = File.ReadAllBytes(archivePath);
            var firstChunkOffset = 39 + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(7, 4));
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(firstChunkOffset, 4), chunkLength);
            WriteArchiveBytesForTamperTest(archivePath, bytes);
            var destination = Path.Join(workspace.Path, "restored");

            var error = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.ExtractToDirectory(archivePath, destination, locker, Password));

            Assert.Contains("chunk length", error.Message);
            Assert.False(Directory.Exists(destination));
            Assert.Equal(bytes, File.ReadAllBytes(archivePath));
        }

        [Theory]
        [InlineData(7, false)]
        [InlineData(8, true)]
        public void Create_EnforcesTotalLogicalSizeBeforeWritingArchive(long limit, bool permitted)
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "one.txt"), "1234");
            File.WriteAllText(Path.Join(source, "two.txt"), "5678");
            var archive = Path.Join(workspace.Path, "limited.cdl");
            var locker = CreateLocker("Locker", source);

            if (permitted)
            {
                LockerArchiveService.CreateFromDirectory(source, archive, locker, Password, limit);
                var restored = Path.Join(workspace.Path, "restored");
                LockerArchiveService.ExtractToDirectory(archive, restored, locker, Password);
                Assert.Equal("5678", File.ReadAllText(Path.Join(restored, "two.txt")));
            }
            else
            {
                Assert.Throws<InvalidDataException>(() =>
                    LockerArchiveService.CreateFromDirectory(source, archive, locker, Password, limit));
                Assert.False(File.Exists(archive));
            }

            Assert.Equal("1234", File.ReadAllText(Path.Join(source, "one.txt")));
            Assert.Equal("5678", File.ReadAllText(Path.Join(source, "two.txt")));
        }

        [Fact]
        public void CreateAndExtract_ShouldRestoreNestedFilesAndEmptyDirectories()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("PlainLocker");
            Directory.CreateDirectory(Path.Join(source, "empty"));
            var nested = Directory.CreateDirectory(Path.Join(source, "nested"));
            File.WriteAllText(Path.Join(source, "root.txt"), "root secret");
            File.WriteAllText(Path.Join(nested.FullName, "nested.txt"), "nested secret");

            var locker = CreateLocker("PlainLocker", source);
            var archivePath = Path.Join(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);

            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);
            var restored = Path.Join(workspace.Path, "restored");
            LockerArchiveService.ExtractToDirectory(archive.ArchivePath, restored, locker, Password);

            Assert.Equal("root secret", File.ReadAllText(Path.Join(restored, "root.txt")));
            Assert.Equal("nested secret", File.ReadAllText(Path.Join(restored, "nested", "nested.txt")));
            Assert.True(Directory.Exists(Path.Join(restored, "empty")));
        }

        [Fact]
        public void Extract_WithTamperedArchive_ShouldThrow()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);

            var bytes = File.ReadAllBytes(archive.ArchivePath);
            bytes[^1] ^= 0x01;
            WriteArchiveBytesForTamperTest(archive.ArchivePath, bytes);

            Assert.ThrowsAny<Exception>(() =>
                LockerArchiveService.ExtractToDirectory(archive.ArchivePath, Path.Join(workspace.Path, "restored"), locker, Password));
        }

        [Fact]
        public void ComputeSha256_ShouldChangeAfterArchiveTampering()
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
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
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
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
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);

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
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
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
            var target = Path.Join(source, "target.txt");
            var link = Path.Join(source, "link.txt");
            File.WriteAllText(target, "secret");

            try
            {
                File.CreateSymbolicLink(link, target);
            }
            catch (Exception ex) when (!File.Exists(link) && ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException or NotSupportedException or ArgumentException)
            {
                return;
            }
            catch (Exception) when (!File.Exists(link))
            {
                return;
            }

            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);

            Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(3)]
        public void Extract_RejectsOtherVersionsEvenWithCurrentKdf(int version)
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "version.cdl");
            LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);
            var bytes = File.ReadAllBytes(archivePath);
            const int MetadataOffset = 7 + 4 + 16 + 8 + 4;
            var metadataLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(7, 4));
            var metadata = Encoding.UTF8.GetString(bytes, MetadataOffset, metadataLength);
            var changed = Encoding.UTF8.GetBytes(metadata.Replace("\"formatVersion\":2", $"\"formatVersion\":{version}", StringComparison.Ordinal));
            Assert.Equal(metadataLength, changed.Length);
            changed.CopyTo(bytes, MetadataOffset);
            WriteArchiveBytesForTamperTest(archivePath, bytes);
            var destination = Path.Join(workspace.Path, "restored");

            var error = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.ExtractToDirectory(archivePath, destination, locker, Password));

            Assert.Contains("format version is unsupported", error.Message);
            Assert.False(Directory.Exists(destination));
            Assert.Equal(bytes, File.ReadAllBytes(archivePath));
        }

        [Theory]
        [InlineData(999999)]
        [InlineData(210000)]
        public void Extract_WithUnexpectedPbkdf2Iterations_ShouldThrowBeforeDecrypting(int iterations)
        {
            using var workspace = TestWorkspace.Create();
            var source = workspace.CreateDirectory("Locker");
            File.WriteAllText(Path.Join(source, "secret.txt"), "secret");
            var locker = CreateLocker("Locker", source);
            var archivePath = Path.Join(workspace.Path, "locked", LockerArchiveService.ArchiveFileName);
            var archive = LockerArchiveService.CreateFromDirectory(source, archivePath, locker, Password);

            var bytes = File.ReadAllBytes(archive.ArchivePath);
            const int IterationOffset = 7 + 4 + 16 + 8;
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(IterationOffset, 4), iterations);
            WriteArchiveBytesForTamperTest(archive.ArchivePath, bytes);

            var exception = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.ExtractToDirectory(archive.ArchivePath, Path.Join(workspace.Path, "restored"), locker, Password));
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
                return new TestWorkspace(System.IO.Path.Join(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    $"cdlocker-archive-tests-{Guid.NewGuid():N}"));
            }

            public string CreateDirectory(string name)
            {
                var path = System.IO.Path.Join(Path, name);
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

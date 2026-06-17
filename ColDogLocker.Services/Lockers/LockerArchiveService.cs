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
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public static class LockerArchiveService
    {
        public const int CurrentStorageFormatVersion = 1;
        public const string ArchiveFileName = "locker.cdl";

        private const int BufferSize = 81920;
        private const int SaltSize = 16;
        private const int NoncePrefixSize = 8;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;
        private const int Pbkdf2Iterations = 210000;
        private const int MaxMetadataLength = 1024 * 1024;
        private const int MaxArchiveEntries = 200000;
        private const int MaxArchiveEntryNameLength = 4096;
        private const long MaxExtractedBytes = 1L * 1024 * 1024 * 1024 * 1024;
        private static readonly byte[] _magic = Encoding.ASCII.GetBytes("CDLARC1");
        private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        public static LockerArchiveCreationResult CreateFromDirectory(
            string sourceDirectory,
            string archivePath,
            LockerModel locker,
            string password)
        {
            ArgumentNullException.ThrowIfNull(locker);
            if (!Directory.Exists(sourceDirectory))
            {
                throw new DirectoryNotFoundException($"Locker directory not found: {sourceDirectory}");
            }

            var sourceEntries = GetSourceArchiveEntries(sourceDirectory);
            var archiveDirectory = Path.GetDirectoryName(archivePath);
            if (!string.IsNullOrEmpty(archiveDirectory))
            {
                Directory.CreateDirectory(archiveDirectory);
            }

            var lockedAtUtc = DateTime.UtcNow;
            var metadata = new LockerArchiveMetadata(
                CurrentStorageFormatVersion,
                locker.Guid,
                locker.LockerName,
                lockedAtUtc,
                AppInfo.SemanticVersion,
                "tar+gzip");

            var metadataBytes = JsonSerializer.SerializeToUtf8Bytes(metadata, _jsonOptions);

            try
            {
                using (var fileStream = new FileStream(archivePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var encryptedStream = new EncryptedArchiveWriteStream(fileStream, password, metadataBytes))
                using (var gzipStream = new GZipStream(encryptedStream, CompressionLevel.SmallestSize, leaveOpen: false))
                using (var tarWriter = new TarWriter(gzipStream, TarEntryFormat.Pax, leaveOpen: true))
                {
                    WriteSourceEntries(tarWriter, sourceEntries);
                }

                SetArchiveFileProtection(archivePath);
                return new LockerArchiveCreationResult(archivePath, ComputeSha256(archivePath), lockedAtUtc);
            }
            catch
            {
                TryDeleteFile(archivePath);
                throw;
            }
        }

        public static LockerArchiveMetadata ReadMetadata(string archivePath)
        {
            using var fileStream = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var header = ReadHeader(fileStream);
            return DeserializeMetadata(header.MetadataBytes);
        }

        public static LockerArchiveVerificationResult VerifyArchive(
            string archivePath,
            LockerModel locker,
            string? expectedSha256)
        {
            ArgumentNullException.ThrowIfNull(locker);

            var result = new LockerArchiveVerificationResult { ArchivePath = archivePath };
            if (!File.Exists(archivePath))
            {
                result.AddError("Locked archive does not exist.");
                return result;
            }

            result.ArchiveExists = true;
            result.ActualSha256 = ComputeSha256(archivePath);
            result.HashMatches = !string.IsNullOrWhiteSpace(expectedSha256) &&
                                 result.ActualSha256.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase);

            if (!result.HashMatches)
            {
                result.AddError(string.IsNullOrWhiteSpace(expectedSha256)
                    ? "Locked archive hash is missing from database metadata."
                    : "Locked archive hash does not match database metadata.");
            }

            try
            {
                result.Metadata = ReadMetadata(archivePath);
                result.MetadataReadable = true;
                result.MetadataMatches = MetadataMatches(result.Metadata, locker, compareLockedAtUtc: true);

                if (!result.MetadataMatches)
                {
                    result.AddError("Locked archive metadata does not match locker metadata.");
                }
            }
            catch (Exception ex)
            {
                result.AddError($"Locked archive metadata could not be read: {ex.Message}");
            }

            return result;
        }

        public static void ExtractToDirectory(
            string archivePath,
            string destinationDirectory,
            LockerModel locker,
            string password)
        {
            ArgumentNullException.ThrowIfNull(locker);
            if (Directory.Exists(destinationDirectory))
            {
                throw new IOException($"Destination directory already exists: {destinationDirectory}");
            }

            Directory.CreateDirectory(destinationDirectory);

            try
            {
                using var fileStream = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var encryptedStream = new EncryptedArchiveReadStream(fileStream, password, out var metadata);
                if (!MetadataMatches(metadata, locker, compareLockedAtUtc: true))
                {
                    throw new InvalidDataException("Locked archive metadata does not match locker metadata.");
                }

                using var gzipStream = new GZipStream(encryptedStream, CompressionMode.Decompress, leaveOpen: false);
                ExtractValidatedTar(gzipStream, destinationDirectory);
            }
            catch
            {
                TryDeleteDirectory(destinationDirectory);
                throw;
            }
        }

        public static string GetArchivePath(string lockedLockerDirectory)
        {
            return Path.Combine(lockedLockerDirectory, ArchiveFileName);
        }

        public static string ComputeSha256(string filePath)
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var hash = SHA256.HashData(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        private static List<SourceArchiveEntry> GetSourceArchiveEntries(string sourceDirectory)
        {
            var sourceRoot = Path.GetFullPath(sourceDirectory);
            var rootInfo = new DirectoryInfo(sourceRoot);
            EnsureNotReparsePoint(rootInfo, "Locker root directory");

            var entries = new List<SourceArchiveEntry>();
            var directories = new Stack<DirectoryInfo>();
            directories.Push(rootInfo);

            while (directories.Count > 0)
            {
                var directory = directories.Pop();
                EnsureNotReparsePoint(directory, "Locker directory");

                foreach (var entry in directory.EnumerateFileSystemInfos().OrderBy(entry => entry.FullName, StringComparer.Ordinal))
                {
                    EnsureNotReparsePoint(entry, "Locker entry");
                    var relativeName = GetArchiveEntryName(sourceRoot, entry.FullName);
                    if (entry is DirectoryInfo childDirectory)
                    {
                        entries.Add(new SourceArchiveEntry(relativeName, entry.FullName, IsDirectory: true, Length: 0, entry.LastWriteTimeUtc));
                        directories.Push(childDirectory);
                    }
                    else if (entry is FileInfo file)
                    {
                        entries.Add(new SourceArchiveEntry(relativeName, entry.FullName, IsDirectory: false, file.Length, file.LastWriteTimeUtc));
                    }
                    else
                    {
                        throw new InvalidDataException($"Unsupported locker entry type: {entry.FullName}");
                    }

                    if (entries.Count > MaxArchiveEntries)
                    {
                        throw new InvalidDataException("Locker contains too many entries to archive safely.");
                    }
                }
            }

            return entries.OrderBy(entry => entry.RelativeName, StringComparer.Ordinal).ToList();
        }

        private static void WriteSourceEntries(TarWriter tarWriter, IReadOnlyList<SourceArchiveEntry> entries)
        {
            foreach (var sourceEntry in entries)
            {
                if (sourceEntry.IsDirectory)
                {
                    var entry = new PaxTarEntry(TarEntryType.Directory, sourceEntry.RelativeName)
                    {
                        ModificationTime = sourceEntry.LastWriteTimeUtc
                    };
                    tarWriter.WriteEntry(entry);
                    continue;
                }

                var fileInfo = new FileInfo(sourceEntry.FullPath);
                EnsureNotReparsePoint(fileInfo, "Locker file");
                EnsureUnchanged(sourceEntry, fileInfo);

                using var sourceStream = new FileStream(sourceEntry.FullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                EnsureUnchanged(sourceEntry, new FileInfo(sourceEntry.FullPath));

                var fileEntry = new PaxTarEntry(TarEntryType.RegularFile, sourceEntry.RelativeName)
                {
                    DataStream = sourceStream,
                    ModificationTime = sourceEntry.LastWriteTimeUtc
                };
                tarWriter.WriteEntry(fileEntry);
                EnsureUnchanged(sourceEntry, new FileInfo(sourceEntry.FullPath));
            }
        }

        internal static void ExtractValidatedTar(Stream archiveStream, string destinationDirectory)
        {
            var destinationRoot = Path.GetFullPath(destinationDirectory);
            Directory.CreateDirectory(destinationRoot);
            EnsureNotReparsePoint(new DirectoryInfo(destinationRoot), "Destination directory");

            using var tarReader = new TarReader(archiveStream, leaveOpen: false);
            TarEntry? entry;
            var entryCount = 0;
            long totalExtractedBytes = 0;

            while ((entry = tarReader.GetNextEntry(copyData: false)) is not null)
            {
                entryCount++;
                if (entryCount > MaxArchiveEntries)
                {
                    throw new InvalidDataException("Locked archive contains too many entries.");
                }

                var destinationPath = GetSafeDestinationPath(destinationRoot, entry.Name);
                switch (entry.EntryType)
                {
                    case TarEntryType.Directory:
                        Directory.CreateDirectory(destinationPath);
                        EnsureNotReparsePoint(new DirectoryInfo(destinationPath), "Extracted directory");
                        break;

                    case TarEntryType.RegularFile:
                    case TarEntryType.V7RegularFile:
                        totalExtractedBytes = checked(totalExtractedBytes + entry.Length);
                        if (totalExtractedBytes > MaxExtractedBytes)
                        {
                            throw new InvalidDataException("Locked archive exceeds the maximum extracted size.");
                        }

                        var parentDirectory = Path.GetDirectoryName(destinationPath);
                        if (string.IsNullOrWhiteSpace(parentDirectory))
                        {
                            throw new InvalidDataException("Locked archive entry has an invalid parent directory.");
                        }

                        Directory.CreateDirectory(parentDirectory);
                        EnsureNotReparsePoint(new DirectoryInfo(parentDirectory), "Extracted parent directory");
                        if (entry.DataStream is null)
                        {
                            throw new InvalidDataException("Locked archive file entry is missing data.");
                        }

                        using (var output = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            CopyEntryData(entry.DataStream, output, entry.Length);
                        }

                        EnsureNotReparsePoint(new FileInfo(destinationPath), "Extracted file");
                        break;

                    default:
                        throw new InvalidDataException($"Locked archive contains unsupported entry type: {entry.EntryType}");
                }
            }
        }

        private static void CopyEntryData(Stream source, Stream destination, long expectedLength)
        {
            if (expectedLength < 0)
            {
                throw new InvalidDataException("Locked archive contains a negative entry size.");
            }

            var buffer = new byte[BufferSize];
            long copied = 0;
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                copied += read;
                if (copied > expectedLength)
                {
                    throw new InvalidDataException("Locked archive entry contains more data than expected.");
                }

                destination.Write(buffer, 0, read);
            }

            if (copied != expectedLength)
            {
                throw new InvalidDataException("Locked archive entry ended before all expected data was read.");
            }
        }

        private static string GetArchiveEntryName(string sourceRoot, string fullPath)
        {
            var relativeName = Path.GetRelativePath(sourceRoot, fullPath).Replace(Path.DirectorySeparatorChar, '/');
            if (Path.AltDirectorySeparatorChar != Path.DirectorySeparatorChar)
            {
                relativeName = relativeName.Replace(Path.AltDirectorySeparatorChar, '/');
            }

            ValidateArchiveEntryName(relativeName);
            return relativeName;
        }

        private static string GetSafeDestinationPath(string destinationRoot, string entryName)
        {
            var normalizedName = ValidateArchiveEntryName(entryName);
            var destinationRootWithSeparator = EnsureTrailingSeparator(destinationRoot);
            var destinationPath = Path.GetFullPath(Path.Combine(destinationRootWithSeparator, normalizedName.Replace('/', Path.DirectorySeparatorChar)));
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            if (!destinationPath.StartsWith(destinationRootWithSeparator, comparison))
            {
                throw new InvalidDataException("Locked archive entry attempts to write outside the destination directory.");
            }

            return destinationPath;
        }

        private static string ValidateArchiveEntryName(string entryName)
        {
            if (string.IsNullOrWhiteSpace(entryName) ||
                entryName.Length > MaxArchiveEntryNameLength ||
                entryName.Contains('\\') ||
                entryName.Contains(':') ||
                Path.IsPathRooted(entryName))
            {
                throw new InvalidDataException("Locked archive contains an unsafe entry path.");
            }

            var segments = entryName.Split('/', StringSplitOptions.None);
            if (segments.Any(segment => string.IsNullOrWhiteSpace(segment) || segment is "." or ".."))
            {
                throw new InvalidDataException("Locked archive contains an unsafe entry path.");
            }

            return string.Join('/', segments);
        }

        private static string EnsureTrailingSeparator(string path)
        {
            return path.EndsWith(Path.DirectorySeparatorChar)
                ? path
                : path + Path.DirectorySeparatorChar;
        }

        private static void EnsureNotReparsePoint(FileSystemInfo entry, string description)
        {
            entry.Refresh();
            if ((entry.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
            {
                throw new InvalidDataException($"{description} uses a link or reparse point, which is not supported in locked archives.");
            }
        }

        private static void EnsureUnchanged(SourceArchiveEntry expected, FileInfo actual)
        {
            actual.Refresh();
            if (!actual.Exists ||
                (actual.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint ||
                actual.Length != expected.Length ||
                actual.LastWriteTimeUtc != expected.LastWriteTimeUtc)
            {
                throw new IOException($"Locker file changed while it was being archived: {expected.FullPath}");
            }
        }

        private static bool MetadataMatches(LockerArchiveMetadata metadata, LockerModel locker, bool compareLockedAtUtc)
        {
            if (metadata.FormatVersion != CurrentStorageFormatVersion ||
                !metadata.LockerGuid.Equals(locker.Guid, StringComparison.Ordinal) ||
                !metadata.LockerName.Equals(locker.LockerName, StringComparison.Ordinal))
            {
                return false;
            }

            if (!compareLockedAtUtc)
            {
                return true;
            }

            return locker.LockedAtUtc is null ||
                   metadata.LockedAtUtc.ToUniversalTime() == locker.LockedAtUtc.Value.ToUniversalTime();
        }

        private static LockerArchiveMetadata DeserializeMetadata(byte[] metadataBytes)
        {
            return JsonSerializer.Deserialize<LockerArchiveMetadata>(metadataBytes, _jsonOptions)
                   ?? throw new InvalidDataException("Locked archive metadata is empty.");
        }

        private static ArchiveHeader ReadHeader(Stream stream)
        {
            var magic = new byte[_magic.Length];
            ReadExactly(stream, magic);
            if (!magic.SequenceEqual(_magic))
            {
                throw new InvalidDataException("File is not a supported ColDog Locker archive.");
            }

            Span<byte> numberBuffer = stackalloc byte[4];
            ReadExactly(stream, numberBuffer);
            var metadataLength = BinaryPrimitives.ReadInt32LittleEndian(numberBuffer);
            if (metadataLength <= 0 || metadataLength > MaxMetadataLength)
            {
                throw new InvalidDataException("Locked archive contains invalid metadata length.");
            }

            var salt = new byte[SaltSize];
            var noncePrefix = new byte[NoncePrefixSize];
            ReadExactly(stream, salt);
            ReadExactly(stream, noncePrefix);

            ReadExactly(stream, numberBuffer);
            var iterations = BinaryPrimitives.ReadInt32LittleEndian(numberBuffer);
            if (iterations != Pbkdf2Iterations)
            {
                throw new InvalidDataException("Locked archive contains unsupported key derivation settings.");
            }

            var metadataBytes = new byte[metadataLength];
            ReadExactly(stream, metadataBytes);
            return new ArchiveHeader(metadataBytes, salt, noncePrefix, iterations);
        }

        private static void WriteHeader(Stream stream, byte[] salt, byte[] noncePrefix, byte[] metadataBytes)
        {
            stream.Write(_magic);

            Span<byte> numberBuffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(numberBuffer, metadataBytes.Length);
            stream.Write(numberBuffer);
            stream.Write(salt);
            stream.Write(noncePrefix);

            BinaryPrimitives.WriteInt32LittleEndian(numberBuffer, Pbkdf2Iterations);
            stream.Write(numberBuffer);
            stream.Write(metadataBytes);
        }

        private static void WriteChunk(Stream stream, int plaintextLength, byte[] tag, ReadOnlySpan<byte> ciphertext)
        {
            Span<byte> lengthBuffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(lengthBuffer, plaintextLength);
            stream.Write(lengthBuffer);
            stream.Write(tag);
            stream.Write(ciphertext);
        }

        private static bool TryReadChunkLength(Stream stream, out int chunkLength)
        {
            Span<byte> lengthBuffer = stackalloc byte[4];
            var totalRead = 0;
            while (totalRead < lengthBuffer.Length)
            {
                var read = stream.Read(lengthBuffer[totalRead..]);
                if (read == 0)
                {
                    if (totalRead == 0)
                    {
                        chunkLength = 0;
                        return false;
                    }

                    throw new EndOfStreamException("Locked archive ended unexpectedly.");
                }

                totalRead += read;
            }

            chunkLength = BinaryPrimitives.ReadInt32LittleEndian(lengthBuffer);
            return true;
        }

        private static byte[] CreateNonce(byte[] noncePrefix, int chunkIndex)
        {
            var nonce = new byte[NonceSize];
            noncePrefix.CopyTo(nonce, 0);
            BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(NoncePrefixSize), chunkIndex);
            return nonce;
        }

        private static byte[] CreateAad(byte[] metadataBytes, int chunkIndex, int plaintextLength)
        {
            var aad = new byte[_magic.Length + metadataBytes.Length + 8];
            _magic.CopyTo(aad, 0);
            metadataBytes.CopyTo(aad.AsSpan(_magic.Length));
            BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(_magic.Length + metadataBytes.Length), chunkIndex);
            BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(_magic.Length + metadataBytes.Length + 4), plaintextLength);
            return aad;
        }

        private static void ReadExactly(Stream stream, Span<byte> buffer)
        {
            var totalRead = 0;
            while (totalRead < buffer.Length)
            {
                var read = stream.Read(buffer[totalRead..]);
                if (read == 0)
                {
                    throw new EndOfStreamException("Locked archive ended unexpectedly.");
                }

                totalRead += read;
            }
        }

        private static void SetArchiveFileProtection(string archivePath)
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    File.SetAttributes(archivePath, File.GetAttributes(archivePath) | FileAttributes.Hidden);
                }
                else
                {
                    File.SetUnixFileMode(archivePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }
            catch
            {
                // Best-effort protection must not make a valid archive unusable on filesystems with limited attribute support.
            }
        }

        private static void TryDeleteFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    File.SetAttributes(filePath, File.GetAttributes(filePath) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly);
                    File.Delete(filePath);
                }
            }
            catch
            {
                // Cleanup failures should not hide the original archive error.
            }
        }

        internal static void TryDeleteDirectory(string directoryPath)
        {
            try
            {
                if (!Directory.Exists(directoryPath))
                {
                    return;
                }

                foreach (var file in Directory.EnumerateFiles(directoryPath, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly);
                }

                foreach (var directory in Directory.EnumerateDirectories(directoryPath, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(directory, File.GetAttributes(directory) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly);
                }

                File.SetAttributes(directoryPath, File.GetAttributes(directoryPath) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly);
                Directory.Delete(directoryPath, recursive: true);
            }
            catch
            {
                // Best-effort cleanup keeps rollback code simple and preserves the primary failure.
            }
        }

        private sealed class EncryptedArchiveWriteStream : Stream
        {
            private readonly Stream _baseStream;
            private readonly byte[] _metadataBytes;
            private readonly byte[] _noncePrefix;
            private readonly byte[] _key;
            private readonly byte[] _buffer = new byte[BufferSize];
            private int _bufferLength;
            private int _chunkIndex;
            private bool _disposed;

            public EncryptedArchiveWriteStream(Stream baseStream, string password, byte[] metadataBytes)
            {
                _baseStream = baseStream;
                _metadataBytes = metadataBytes;

                var salt = new byte[SaltSize];
                _noncePrefix = new byte[NoncePrefixSize];
                RandomNumberGenerator.Fill(salt);
                RandomNumberGenerator.Fill(_noncePrefix);

                _key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);
                WriteHeader(_baseStream, salt, _noncePrefix, _metadataBytes);
            }

            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override void Write(byte[] buffer, int offset, int count)
            {
                Write(buffer.AsSpan(offset, count));
            }

            public override void Write(ReadOnlySpan<byte> buffer)
            {
                while (!buffer.IsEmpty)
                {
                    var copyLength = Math.Min(BufferSize - _bufferLength, buffer.Length);
                    buffer[..copyLength].CopyTo(_buffer.AsSpan(_bufferLength));
                    _bufferLength += copyLength;
                    buffer = buffer[copyLength..];

                    if (_bufferLength == BufferSize)
                    {
                        WriteBufferedChunk();
                    }
                }
            }

            public override void Flush()
            {
                WriteBufferedChunk();
                _baseStream.Flush();
            }

            protected override void Dispose(bool disposing)
            {
                if (!_disposed && disposing)
                {
                    Flush();
                    _baseStream.Dispose();
                    _disposed = true;
                }

                base.Dispose(disposing);
            }

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();

            private void WriteBufferedChunk()
            {
                if (_bufferLength == 0)
                {
                    return;
                }

                var ciphertext = new byte[_bufferLength];
                var tag = new byte[TagSize];
                var nonce = CreateNonce(_noncePrefix, _chunkIndex);
                var aad = CreateAad(_metadataBytes, _chunkIndex, _bufferLength);

                using var aes = new AesGcm(_key, TagSize);
                aes.Encrypt(nonce, _buffer.AsSpan(0, _bufferLength), ciphertext, tag, aad);
                WriteChunk(_baseStream, _bufferLength, tag, ciphertext);

                Array.Clear(_buffer, 0, _bufferLength);
                _bufferLength = 0;
                _chunkIndex++;
            }
        }

        private sealed class EncryptedArchiveReadStream : Stream
        {
            private readonly Stream _baseStream;
            private readonly byte[] _metadataBytes;
            private readonly byte[] _noncePrefix;
            private readonly byte[] _key;
            private byte[] _plainBuffer = [];
            private int _plainOffset;
            private int _chunkIndex;
            private bool _endOfArchive;

            public EncryptedArchiveReadStream(Stream baseStream, string password, out LockerArchiveMetadata metadata)
            {
                _baseStream = baseStream;
                var header = ReadHeader(_baseStream);
                _metadataBytes = header.MetadataBytes;
                _noncePrefix = header.NoncePrefix;
                _key = Rfc2898DeriveBytes.Pbkdf2(password, header.Salt, header.Iterations, HashAlgorithmName.SHA256, KeySize);
                metadata = DeserializeMetadata(_metadataBytes);
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override int Read(byte[] buffer, int offset, int count)
            {
                return Read(buffer.AsSpan(offset, count));
            }

            public override int Read(Span<byte> buffer)
            {
                if (buffer.IsEmpty)
                {
                    return 0;
                }

                if (_plainOffset >= _plainBuffer.Length && !LoadNextChunk())
                {
                    return 0;
                }

                var copyLength = Math.Min(buffer.Length, _plainBuffer.Length - _plainOffset);
                _plainBuffer.AsSpan(_plainOffset, copyLength).CopyTo(buffer);
                _plainOffset += copyLength;
                return copyLength;
            }

            public override void Flush()
            {
            }

            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();

            private bool LoadNextChunk()
            {
                if (_endOfArchive)
                {
                    return false;
                }

                if (!TryReadChunkLength(_baseStream, out var chunkLength))
                {
                    _endOfArchive = true;
                    return false;
                }

                if (chunkLength <= 0 || chunkLength > BufferSize)
                {
                    throw new InvalidDataException("Locked archive contains an invalid encrypted chunk length.");
                }

                var tag = new byte[TagSize];
                var ciphertext = new byte[chunkLength];
                LockerArchiveService.ReadExactly(_baseStream, tag);
                LockerArchiveService.ReadExactly(_baseStream, ciphertext);

                var plaintext = new byte[chunkLength];
                var nonce = CreateNonce(_noncePrefix, _chunkIndex);
                var aad = CreateAad(_metadataBytes, _chunkIndex, chunkLength);

                using var aes = new AesGcm(_key, TagSize);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);

                _plainBuffer = plaintext;
                _plainOffset = 0;
                _chunkIndex++;
                return true;
            }
        }

        private sealed record SourceArchiveEntry(string RelativeName, string FullPath, bool IsDirectory, long Length, DateTime LastWriteTimeUtc);

        private sealed record ArchiveHeader(byte[] MetadataBytes, byte[] Salt, byte[] NoncePrefix, int Iterations);
    }

    public sealed record LockerArchiveCreationResult(string ArchivePath, string Sha256, DateTime LockedAtUtc);

    public sealed record LockerArchiveMetadata(
        int FormatVersion,
        string LockerGuid,
        string LockerName,
        DateTime LockedAtUtc,
        string AppVersion,
        string CompressionArchiveFormat);

    public sealed class LockerArchiveVerificationResult
    {
        public string ArchivePath { get; set; } = string.Empty;
        public bool ArchiveExists { get; set; }
        public bool HashMatches { get; set; }
        public bool MetadataReadable { get; set; }
        public bool MetadataMatches { get; set; }
        public string? ActualSha256 { get; set; }
        public LockerArchiveMetadata? Metadata { get; set; }
        public List<string> Errors { get; } = [];
        public bool IsValid => ArchiveExists && HashMatches && MetadataReadable && MetadataMatches && Errors.Count == 0;

        public void AddError(string error)
        {
            Errors.Add(error);
        }
    }
}

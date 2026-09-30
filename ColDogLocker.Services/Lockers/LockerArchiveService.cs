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
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public static class LockerArchiveService
    {
        public const int CurrentStorageFormatVersion = 2;
        public const string ArchiveFileName = "locker.cdl";

        private const int BufferSize = 81920;
        private const int SaltSize = 16;
        private const int NoncePrefixSize = 8;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;
        private const int Pbkdf2Iterations = 600000;
        private const int MaxMetadataLength = 1024 * 1024;
        private const int MaxArchiveEntries = 200000;
        private const int MaxArchiveEntryNameLength = 4096;
        internal const long MaxExtractedBytes = 1L * 1024 * 1024 * 1024 * 1024;
        private const string WindowsAttributesPaxKey = "CDL.windowsAttributes";
        private const string WindowsCreationTimePaxKey = "CDL.windowsCreationTimeUtc";
        private static readonly byte[] _magic = Encoding.ASCII.GetBytes("CDLARC1");
        private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        public static LockerArchiveCreationResult CreateFromDirectory(
            string sourceDirectory,
            string archivePath,
            LockerModel locker,
            string password)
        {
            return CreateFromDirectory(sourceDirectory, archivePath, locker, password, MaxExtractedBytes);
        }

        internal static LockerArchiveCreationResult CreateFromDirectory(
            string sourceDirectory,
            string archivePath,
            LockerModel locker,
            string password,
            long maxExtractedBytes,
            Func<string, Stream>? openSource = null,
            int maxArchiveEntries = MaxArchiveEntries,
            CancellationToken cancellationToken = default,
            Action<string, int?>? reportProgress = null,
            Func<string, long?>? getAvailableBytes = null)
        {
            ArgumentNullException.ThrowIfNull(locker);
            ArgumentOutOfRangeException.ThrowIfNegative(maxExtractedBytes);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(maxExtractedBytes, MaxExtractedBytes);
            ArgumentOutOfRangeException.ThrowIfNegative(maxArchiveEntries);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(maxArchiveEntries, MaxArchiveEntries);
            if (!Directory.Exists(sourceDirectory))
            {
                throw new DirectoryNotFoundException($"Locker directory not found: {sourceDirectory}");
            }

            cancellationToken.ThrowIfCancellationRequested();
            reportProgress?.Invoke("Inspecting locker contents", 0);
            var sourcePathIdentity = FileSystemPathIdentity.CaptureDirectory(sourceDirectory);
            var sourceEntries = GetSourceArchiveEntries(sourceDirectory, maxExtractedBytes, maxArchiveEntries,
                cancellationToken, reportProgress);
            sourcePathIdentity.EnsureUnchanged();
            var logicalBytes = GetLogicalByteCount(sourceEntries);
            var requiredBytes = EstimateArchiveSpace(logicalBytes, sourceEntries.Count);
            var availableBytes = (getAvailableBytes ?? TryGetAvailableBytes)(archivePath);
            reportProgress?.Invoke(DescribeArchiveCapacity(sourceEntries.Count, logicalBytes, availableBytes), 10);
            if (availableBytes is { } available && available < requiredBytes)
            {
                throw new IOException(
                    $"Not enough free space to lock this locker. At least {FormatBytes(requiredBytes)} is required " +
                    $"at the encrypted destination, but only {FormatBytes(available)} is available.");
            }

            var archiveDirectory = Path.GetDirectoryName(archivePath);
            if (!string.IsNullOrEmpty(archiveDirectory))
            {
                Directory.CreateDirectory(archiveDirectory);
            }

            var lockedAtUtc = DateTime.UtcNow;
            var rootMode = GetSupportedUnixMode(sourceDirectory);
            var rootModifiedUtc = Directory.GetLastWriteTimeUtc(sourceDirectory);
            var rootInfo = new DirectoryInfo(sourceDirectory);
            var rootWindowsAttributes = GetSupportedWindowsAttributes(rootInfo);
            var rootCreationTimeUtc = GetSupportedCreationTimeUtc(rootInfo);
            var metadata = new LockerArchiveMetadata(
                CurrentStorageFormatVersion,
                locker.Guid,
                locker.LockerName,
                lockedAtUtc,
                AppInfo.SemanticVersion,
                "tar+gzip",
                OperatingSystem.IsWindows() ? null : rootMode,
                rootModifiedUtc,
                OperatingSystem.IsWindows() ? rootWindowsAttributes : null,
                OperatingSystem.IsWindows() ? rootCreationTimeUtc : null);

            var metadataBytes = JsonSerializer.SerializeToUtf8Bytes(metadata, _jsonOptions);

            var archiveCreated = false;
            try
            {
                string sourceTreeSha256;
                using (var sourceManifest = LockerTreeManifestDigest.Create())
                {
                    LockerTreeManifestDigest.AppendEntry(
                        sourceManifest,
                        string.Empty,
                        isDirectory: true,
                        0,
                        rootMode,
                        rootModifiedUtc,
                        rootWindowsAttributes,
                        rootCreationTimeUtc,
                        sourcePathIdentity.LeafIdentity);
                    using (var fileStream = new FileStream(archivePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        archiveCreated = true;
                        using var encryptedStream = new EncryptedArchiveWriteStream(fileStream, password, metadataBytes);
                        using var gzipStream = new GZipStream(encryptedStream, CompressionLevel.SmallestSize, false);
                        using var tarWriter = new TarWriter(gzipStream, TarEntryFormat.Pax, true);
                        if (sourceEntries.Count == 0)
                        {
                            // TarWriter emits no end records when it writes no entries.
                            // Supply the two zero blocks of a valid empty TAR ourselves.
                            gzipStream.Write(new byte[1024]);
                        }
                        else
                        {
                            WriteSourceEntries(tarWriter, sourceEntries, sourceManifest, openSource,
                                cancellationToken, reportProgress);
                        }
                    }

                    sourcePathIdentity.EnsureUnchanged();
                    sourceTreeSha256 = LockerTreeManifestDigest.Complete(sourceManifest);
                }

                SetArchiveFileProtection(archivePath);
                return new LockerArchiveCreationResult(archivePath, ComputeSha256(archivePath), lockedAtUtc, sourceTreeSha256);
            }
            catch (Exception)
            {
                if (archiveCreated)
                {
                    TryDeleteFile(archivePath);
                }

                throw;
            }
        }

        public static LockerArchiveMetadata ReadMetadata(string archivePath)
        {
            using var fileStream = FileSystemEntryPolicy.OpenRead(archivePath);
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
                result.MetadataMatches = MetadataMatches(result.Metadata, locker, true);

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
            ExtractToDirectory(archivePath, destinationDirectory, locker, password, default, null);
        }

        internal static void ExtractToDirectory(
            string archivePath,
            string destinationDirectory,
            LockerModel locker,
            string password,
            CancellationToken cancellationToken,
            Action<string, int?>? reportProgress)
        {
            ArgumentNullException.ThrowIfNull(locker);
            cancellationToken.ThrowIfCancellationRequested();
            if (Directory.Exists(destinationDirectory))
            {
                throw new IOException($"Destination directory already exists: {destinationDirectory}");
            }

            CreatePrivateDirectory(destinationDirectory);

            try
            {
                using var fileStream = FileSystemEntryPolicy.OpenRead(archivePath);
                using var encryptedStream = new EncryptedArchiveReadStream(fileStream, password, out var metadata);
                if (!MetadataMatches(metadata, locker, true))
                {
                    throw new InvalidDataException("Locked archive metadata does not match locker metadata.");
                }

                if (!OperatingSystem.IsWindows() &&
                    (metadata.RootWindowsAttributes != null || metadata.RootCreationTimeUtc != null))
                {
                    throw new PlatformNotSupportedException("This archive contains Windows filesystem metadata and must be restored on Windows.");
                }

                if (OperatingSystem.IsWindows() && metadata.RootWindowsAttributes is { } rootWindowsAttributes)
                {
                    ValidateWindowsAttributes(rootWindowsAttributes);
                }

                using var gzipStream = new GZipStream(encryptedStream, CompressionMode.Decompress, true);
                var restoredEntries = ExtractValidatedTar(gzipStream, destinationDirectory,
                    cancellationToken, reportProgress);
                // Tar EOF is not encrypted-stream EOF. Authenticate everything before publishing output.
                var trailingBytes = 0;
                int value;
                while ((value = gzipStream.ReadByte()) != -1)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (value != 0 || ++trailingBytes > MaxMetadataLength)
                    {
                        throw new InvalidDataException("Unexpected data after the tar archive.");
                    }
                }

                if (encryptedStream.ReadByte() != -1)
                {
                    throw new InvalidDataException("Unexpected encrypted payload after the compressed archive.");
                }

                // Apply permissions only after complete authentication, children before parents.
                foreach (var restored in restoredEntries.OrderByDescending(item => item.Path.Length))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (OperatingSystem.IsWindows() && restored.CreationUtc is { } creationUtc)
                    {
                        if (restored.IsDirectory)
                        {
                            Directory.SetCreationTimeUtc(restored.Path, creationUtc);
                        }
                        else
                        {
                            File.SetCreationTimeUtc(restored.Path, creationUtc);
                        }
                    }

                    if (restored.IsDirectory)
                    {
                        Directory.SetLastWriteTimeUtc(restored.Path, restored.ModifiedUtc);
                    }
                    else
                    {
                        File.SetLastWriteTimeUtc(restored.Path, restored.ModifiedUtc);
                    }

                    if (OperatingSystem.IsWindows() && restored.WindowsAttributes is { } windowsAttributes)
                    {
                        ApplyWindowsAttributes(restored.Path, windowsAttributes);
                    }
                    else if (!OperatingSystem.IsWindows())
                    {
                        File.SetUnixFileMode(restored.Path, restored.Mode);
                    }
                }

                if (OperatingSystem.IsWindows() && metadata.RootCreationTimeUtc is { } rootCreation)
                {
                    Directory.SetCreationTimeUtc(destinationDirectory, rootCreation);
                }

                if (metadata.RootLastWriteTimeUtc is { } rootModified)
                {
                    Directory.SetLastWriteTimeUtc(destinationDirectory, rootModified);
                }

                if (!OperatingSystem.IsWindows() && metadata.RootUnixMode is { } rootMode)
                {
                    ValidateUnixMode(rootMode);
                    File.SetUnixFileMode(destinationDirectory, rootMode);
                }

                else if (OperatingSystem.IsWindows() && metadata.RootWindowsAttributes is { } rootAttributes)
                {
                    ApplyWindowsAttributes(destinationDirectory, rootAttributes);
                }
            }
            catch (Exception)
            {
                TryDeleteDirectory(destinationDirectory);
                throw;
            }
        }

        public static string GetArchivePath(string lockedLockerDirectory)
        {
            return Path.Join(lockedLockerDirectory, ArchiveFileName);
        }

        public static string ComputeSha256(string filePath)
        {
            using var stream = FileSystemEntryPolicy.OpenRead(filePath);
            var hash = SHA256.HashData(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        internal static long EstimateArchiveSpace(long logicalBytes, int entryCount)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(logicalBytes);
            ArgumentOutOfRangeException.ThrowIfNegative(entryCount);

            // TAR/PAX metadata, gzip worst-case expansion, authenticated chunk tags and a fixed
            // safety margin all consume space beyond the logical file payload.
            return checked(logicalBytes + Math.Max(1024L * 1024, logicalBytes / 100) + checked((long)entryCount * 4096));
        }

        internal static long? TryGetAvailableBytes(string path)
        {
            try
            {
                var fullPath = Path.GetFullPath(path);
                var comparison = OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal;
                var drive = DriveInfo.GetDrives()
                    .Where(candidate => candidate.IsReady)
                    .Where(candidate => IsPathWithinRoot(fullPath, candidate.RootDirectory.FullName, comparison))
                    .OrderByDescending(candidate => candidate.RootDirectory.FullName.Length)
                    .FirstOrDefault();
                return drive?.AvailableFreeSpace;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                return null;
            }
        }

        internal static string DescribeAvailableSpace(string path)
        {
            var available = TryGetAvailableBytes(path);
            return available is { } bytes
                ? $"{FormatBytes(bytes)} available at the destination"
                : "available destination space could not be determined";
        }

        private static long GetLogicalByteCount(IEnumerable<SourceArchiveEntry> entries)
        {
            long total = 0;
            foreach (var entry in entries)
            {
                total = checked(total + entry.Length);
            }

            return total;
        }

        private static string DescribeArchiveCapacity(int entryCount, long logicalBytes, long? availableBytes)
        {
            var capacity = availableBytes is { } bytes
                ? $"{FormatBytes(bytes)} available at the encrypted destination"
                : "available destination space could not be determined";
            return $"Inspected {entryCount:N0} item{(entryCount == 1 ? string.Empty : "s")} " +
                   $"containing {FormatBytes(logicalBytes)}; {capacity}";
        }

        private static bool IsPathWithinRoot(string path, string root, StringComparison comparison)
        {
            var normalizedRoot = root.EndsWith(Path.DirectorySeparatorChar)
                ? root
                : root + Path.DirectorySeparatorChar;
            return path.Equals(root.TrimEnd(Path.DirectorySeparatorChar), comparison) ||
                   path.StartsWith(normalizedRoot, comparison);
        }

        private static string FormatBytes(long bytes)
        {
            string[] suffixes = ["B", "KiB", "MiB", "GiB", "TiB"];
            var value = (double)bytes;
            var suffix = 0;
            while (value >= 1024 && suffix < suffixes.Length - 1)
            {
                value /= 1024;
                suffix++;
            }

            return $"{value:0.##} {suffixes[suffix]}";
        }

        private static List<SourceArchiveEntry> GetSourceArchiveEntries(string sourceDirectory, long maxExtractedBytes,
            int maxArchiveEntries, CancellationToken cancellationToken, Action<string, int?>? reportProgress)
        {
            var sourceRoot = Path.GetFullPath(sourceDirectory);
            var rootInfo = new DirectoryInfo(sourceRoot);
            EnsureNotReparsePoint(rootInfo, "Locker root directory");
            FileSystemMetadataPolicy.EnsureSupported(rootInfo);
            _ = GetSupportedUnixMode(sourceRoot);

            var entries = new List<SourceArchiveEntry>();
            long totalBytes = 0;
            var directories = new Stack<DirectoryInfo>();
            directories.Push(rootInfo);

            while (directories.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var directory = directories.Pop();
                EnsureNotReparsePoint(directory, "Locker directory");

                foreach (var entry in directory.EnumerateFileSystemInfos())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (entries.Count >= maxArchiveEntries)
                    {
                        throw new InvalidDataException("Locker contains too many entries to archive safely.");
                    }

                    EnsureNotReparsePoint(entry, "Locker entry");
                    FileSystemMetadataPolicy.EnsureSupported(entry);
                    var relativeName = GetArchiveEntryName(sourceRoot, entry.FullName);
                    if (entry is DirectoryInfo childDirectory)
                    {
                        entries.Add(new SourceArchiveEntry(relativeName, entry.FullName, true, 0, entry.LastWriteTimeUtc,
                            GetSupportedUnixMode(entry.FullName), GetSupportedWindowsAttributes(entry), GetSupportedCreationTimeUtc(entry),
                            FileSystemIdentity.CaptureDirectory(entry.FullName)));
                        directories.Push(childDirectory);
                    }
                    else if (entry is FileInfo file)
                    {
                        totalBytes = checked(totalBytes + file.Length);
                        if (totalBytes > maxExtractedBytes)
                        {
                            throw new InvalidDataException("Locker exceeds the maximum supported extracted size. Original files have not been removed.");
                        }

                        entries.Add(new SourceArchiveEntry(relativeName, entry.FullName, false, file.Length, file.LastWriteTimeUtc,
                            GetSupportedUnixMode(file.FullName), GetSupportedWindowsAttributes(file), GetSupportedCreationTimeUtc(file),
                            FileSystemIdentity.CaptureFile(file.FullName)));
                    }
                    else
                    {
                        throw new InvalidDataException($"Unsupported locker entry type: {entry.FullName}");
                    }

                    if (entries.Count == 1 || entries.Count % 256 == 0)
                    {
                        reportProgress?.Invoke($"Inspecting locker contents ({entries.Count:N0} items)", null);
                    }
                }
            }

            // Sort only the bounded result, preserving deterministic archive order
            // without materializing an unbounded directory or a second result list.
            entries.Sort((left, right) => StringComparer.Ordinal.Compare(left.RelativeName, right.RelativeName));
            return entries;
        }

        private static void WriteSourceEntries(
            TarWriter tarWriter,
            IReadOnlyList<SourceArchiveEntry> entries,
            IncrementalHash sourceManifest,
            Func<string, Stream>? openSource,
            CancellationToken cancellationToken,
            Action<string, int?>? reportProgress)
        {
            var lastReportedPercent = -1;
            for (var index = 0; index < entries.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var sourceEntry = entries[index];
                var percent = 15 + (int)(65L * index / entries.Count);
                if (index == 0 || index == entries.Count - 1 || percent != lastReportedPercent)
                {
                    reportProgress?.Invoke($"Archiving item {index + 1:N0} of {entries.Count:N0}", percent);
                    lastReportedPercent = percent;
                }

                LockerTreeManifestDigest.AppendEntry(
                    sourceManifest,
                    sourceEntry.RelativeName,
                    sourceEntry.IsDirectory,
                    sourceEntry.Length,
                    sourceEntry.Mode,
                    sourceEntry.LastWriteTimeUtc,
                    sourceEntry.WindowsAttributes,
                    sourceEntry.CreationTimeUtc,
                    sourceEntry.Identity);
                if (sourceEntry.IsDirectory)
                {
                    if (FileSystemIdentity.CaptureDirectory(sourceEntry.FullPath) != sourceEntry.Identity)
                    {
                        throw new IOException($"Locker directory changed while it was being archived: {sourceEntry.FullPath}");
                    }

                    var entry = new PaxTarEntry(TarEntryType.Directory, sourceEntry.RelativeName, GetPlatformPaxAttributes(sourceEntry))
                    {
                        ModificationTime = sourceEntry.LastWriteTimeUtc,
                        Mode = sourceEntry.Mode
                    };
                    tarWriter.WriteEntry(entry);
                    continue;
                }

                var fileInfo = new FileInfo(sourceEntry.FullPath);
                EnsureNotReparsePoint(fileInfo, "Locker file");
                EnsureUnchanged(sourceEntry, fileInfo);

                using var sourceStream = openSource != null ? openSource(sourceEntry.FullPath)
                    : FileSystemEntryPolicy.OpenRead(sourceEntry.FullPath, rejectHardLinks: true,
                        expectedIdentity: sourceEntry.Identity);
                using var boundedSource = new ExactLengthReadStream(sourceStream, sourceEntry.Length, sourceManifest,
                    cancellationToken);
                EnsureUnchanged(sourceEntry, new FileInfo(sourceEntry.FullPath));

                var fileEntry = new PaxTarEntry(TarEntryType.RegularFile, sourceEntry.RelativeName, GetPlatformPaxAttributes(sourceEntry))
                {
                    DataStream = boundedSource,
                    ModificationTime = sourceEntry.LastWriteTimeUtc,
                    Mode = sourceEntry.Mode
                };
                tarWriter.WriteEntry(fileEntry);
                boundedSource.EnsureComplete();
                EnsureUnchanged(sourceEntry, new FileInfo(sourceEntry.FullPath));
            }
        }

        internal static List<RestoredArchiveEntry> ExtractValidatedTar(Stream archiveStream, string destinationDirectory,
            CancellationToken cancellationToken = default, Action<string, int?>? reportProgress = null)
        {
            var destinationRoot = Path.GetFullPath(destinationDirectory);
            CreatePrivateDirectory(destinationRoot);
            var restoredEntries = new List<RestoredArchiveEntry>();
            EnsureNotReparsePoint(new DirectoryInfo(destinationRoot), "Destination directory");

            using var tarReader = new TarReader(archiveStream, leaveOpen: true);
            TarEntry? entry;
            var entryCount = 0;
            long totalExtractedBytes = 0;

            while ((entry = tarReader.GetNextEntry()) is not null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                entryCount++;
                if (entryCount > MaxArchiveEntries)
                {
                    throw new InvalidDataException("Locked archive contains too many entries.");
                }

                var destinationPath = GetSafeDestinationPath(destinationRoot, entry.Name);
                ValidateUnixMode(entry.Mode);
                restoredEntries.Add(ReadRestoredEntryMetadata(entry, destinationPath));
                if (entryCount == 1 || entryCount % 128 == 0)
                {
                    reportProgress?.Invoke($"Restoring item {entryCount:N0}", null);
                }

                switch (entry.EntryType)
                {
                    case TarEntryType.Directory:
                        CreatePrivateDirectory(destinationPath);
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

                        CreatePrivateDirectory(parentDirectory);
                        EnsureNotReparsePoint(new DirectoryInfo(parentDirectory), "Extracted parent directory");
                        if (entry.DataStream is null && entry.Length != 0)
                        {
                            throw new InvalidDataException("Locked archive file entry is missing data.");
                        }

                        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                        if (!OperatingSystem.IsWindows())
                        {
                            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                        }

                        using (var output = new FileStream(destinationPath, options))
                        {
                            // TarReader represents a valid empty regular file with no data stream.
                            CopyEntryData(entry.DataStream ?? Stream.Null, output, entry.Length, cancellationToken);
                            output.Flush(flushToDisk: true);
                        }

                        EnsureNotReparsePoint(new FileInfo(destinationPath), "Extracted file");
                        break;

                    default:
                        throw new InvalidDataException($"Locked archive contains unsupported entry type: {entry.EntryType}");
                }
            }

            return restoredEntries;
        }

        internal static void CreatePrivateDirectory(string path)
        {
            PrivateDirectory.Ensure(path);
        }

        private static UnixFileMode GetSupportedUnixMode(string path)
        {
            var mode = OperatingSystem.IsWindows()
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | (Directory.Exists(path) ? UnixFileMode.UserExecute : 0)
                : File.GetUnixFileMode(path);
            ValidateUnixMode(mode);
            return mode;
        }

        private static void ValidateUnixMode(UnixFileMode mode)
        {
            if (((int)mode & ~0x1ff) != 0)
            {
                throw new InvalidDataException("Special Unix permission bits are not supported. Original files have not been removed.");
            }
        }

        private static FileAttributes GetSupportedWindowsAttributes(FileSystemInfo entry)
        {
            if (!OperatingSystem.IsWindows())
            {
                return 0;
            }

            var attributes = entry.Attributes & ~FileAttributes.Directory;
            ValidateWindowsAttributes(attributes);
            return attributes;
        }

        private static DateTime GetSupportedCreationTimeUtc(FileSystemInfo entry)
            => OperatingSystem.IsWindows() ? entry.CreationTimeUtc : DateTime.UnixEpoch;

        private static Dictionary<string, string> GetPlatformPaxAttributes(SourceArchiveEntry entry)
        {
            if (!OperatingSystem.IsWindows())
            {
                return [];
            }

            return new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [WindowsAttributesPaxKey] = ((int)entry.WindowsAttributes).ToString(CultureInfo.InvariantCulture),
                [WindowsCreationTimePaxKey] = entry.CreationTimeUtc.Ticks.ToString(CultureInfo.InvariantCulture)
            };
        }

        private static RestoredArchiveEntry ReadRestoredEntryMetadata(TarEntry entry, string destinationPath)
        {
            FileAttributes? windowsAttributes = null;
            DateTime? creationTimeUtc = null;
            if (entry is PaxTarEntry pax)
            {
                var hasAttributes = pax.ExtendedAttributes.TryGetValue(WindowsAttributesPaxKey, out var attributeText);
                var hasCreation = pax.ExtendedAttributes.TryGetValue(WindowsCreationTimePaxKey, out var creationText);
                if (hasAttributes != hasCreation)
                {
                    throw new InvalidDataException("Locked archive contains incomplete Windows filesystem metadata.");
                }

                if (hasAttributes)
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        throw new PlatformNotSupportedException("This archive contains Windows filesystem metadata and must be restored on Windows.");
                    }

                    if (!int.TryParse(attributeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var encodedAttributes) ||
                        !long.TryParse(creationText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var encodedCreation))
                    {
                        throw new InvalidDataException("Locked archive contains invalid Windows filesystem metadata.");
                    }

                    windowsAttributes = (FileAttributes)encodedAttributes;
                    ValidateWindowsAttributes(windowsAttributes.Value);
                    try
                    {
                        creationTimeUtc = new DateTime(encodedCreation, DateTimeKind.Utc);
                    }
                    catch (ArgumentOutOfRangeException ex)
                    {
                        throw new InvalidDataException("Locked archive contains an invalid Windows creation time.", ex);
                    }
                }
            }

            return new RestoredArchiveEntry(
                destinationPath,
                entry.EntryType == TarEntryType.Directory,
                entry.Mode,
                entry.ModificationTime.UtcDateTime,
                windowsAttributes,
                creationTimeUtc);
        }

        private static void ApplyWindowsAttributes(string path, FileAttributes attributes)
        {
            ValidateWindowsAttributes(attributes);
            File.SetAttributes(path, attributes == 0 ? FileAttributes.Normal : attributes);
        }

        private static void ValidateWindowsAttributes(FileAttributes attributes)
        {
            const FileAttributes Supported = FileAttributes.Normal | FileAttributes.ReadOnly | FileAttributes.Hidden |
                FileAttributes.System | FileAttributes.Archive | FileAttributes.Temporary | FileAttributes.NotContentIndexed;
            if ((attributes & ~Supported) != 0 ||
                ((attributes & FileAttributes.Normal) != 0 && attributes != FileAttributes.Normal))
            {
                throw new InvalidDataException("Locked archive contains unsupported Windows file attributes.");
            }
        }

        private static void CopyEntryData(Stream source, Stream destination, long expectedLength,
            CancellationToken cancellationToken = default)
        {
            if (expectedLength < 0)
            {
                throw new InvalidDataException("Locked archive contains a negative entry size.");
            }

            var buffer = new byte[BufferSize];
            long copied = 0;
            int read;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                read = source.Read(buffer, 0, buffer.Length);
                cancellationToken.ThrowIfCancellationRequested();
                if (read == 0)
                {
                    break;
                }

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
            var destinationPath = Path.GetFullPath(Path.Join(destinationRootWithSeparator, normalizedName.Replace('/', Path.DirectorySeparatorChar)));
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

            var segments = entryName.Split('/');
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

            FileSystemEntryPolicy.EnsureSupported(entry, rejectHardLinks: true);
        }

        private static void EnsureUnchanged(SourceArchiveEntry expected, FileInfo actual)
        {
            actual.Refresh();
            if (!actual.Exists ||
                (actual.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint ||
                actual.Length != expected.Length ||
                actual.LastWriteTimeUtc != expected.LastWriteTimeUtc ||
                GetSupportedWindowsAttributes(actual) != expected.WindowsAttributes ||
                GetSupportedCreationTimeUtc(actual) != expected.CreationTimeUtc)
            {
                throw new IOException($"Locker file changed while it was being archived: {expected.FullPath}");
            }

            if (FileSystemIdentity.CaptureFile(actual.FullName) != expected.Identity)
            {
                throw new IOException($"Locker file identity changed while it was being archived: {expected.FullPath}");
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
            var version = DeserializeMetadata(metadataBytes).FormatVersion;
            if (version != CurrentStorageFormatVersion)
            {
                throw new InvalidDataException("This archive format version is unsupported. Only the current prerelease archive format is accepted.");
            }

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
            catch (Exception)
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
                    File.SetAttributes(filePath, File.GetAttributes(filePath) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                    File.Delete(filePath);
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Failed to remove archive staging file '{filePath}'.", ex);
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
                    File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                }

                foreach (var directory in Directory.EnumerateDirectories(directoryPath, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(directory, File.GetAttributes(directory) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                }

                File.SetAttributes(directoryPath,
                    File.GetAttributes(directoryPath) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                Directory.Delete(directoryPath, true);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Failed to remove archive staging directory '{directoryPath}'. Plaintext data may remain on disk.", ex);
            }
        }

        private sealed class EncryptedArchiveWriteStream : Stream
        {
            private readonly Stream _baseStream;
            private readonly byte[] _buffer = new byte[BufferSize];
            private readonly byte[] _key;
            private readonly byte[] _metadataBytes;
            private readonly byte[] _noncePrefix;
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
                try
                {
                    WriteHeader(_baseStream, salt, _noncePrefix, _metadataBytes);
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(_key);
                    throw;
                }
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
                    _disposed = true;
                    try
                    {
                        Flush();
                        // A zero-length authenticated chunk commits the final chunk count.
                        var tag = new byte[TagSize];
                        using var aes = new AesGcm(_key, TagSize);
                        aes.Encrypt(CreateNonce(_noncePrefix, _chunkIndex), ReadOnlySpan<byte>.Empty,
                            Span<byte>.Empty, tag, CreateAad(_metadataBytes, _chunkIndex, 0));
                        WriteChunk(_baseStream, 0, tag, ReadOnlySpan<byte>.Empty);
                        _baseStream.Flush();
                        if (_baseStream is FileStream archiveFile)
                        {
                            archiveFile.Flush(flushToDisk: true);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(_key);
                        CryptographicOperations.ZeroMemory(_buffer);
                        _baseStream.Dispose();
                    }
                }

                base.Dispose(disposing);
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

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
                _chunkIndex = checked(_chunkIndex + 1);
            }
        }

        private sealed class EncryptedArchiveReadStream : Stream
        {
            private readonly Stream _baseStream;
            private readonly byte[] _key;
            private readonly byte[] _metadataBytes;
            private readonly byte[] _noncePrefix;
            private int _chunkIndex;
            private bool _endOfArchive;
            private byte[] _plainBuffer = [];
            private int _plainOffset;

            public EncryptedArchiveReadStream(Stream baseStream, string password, out LockerArchiveMetadata metadata)
            {
                _baseStream = baseStream;
                var header = ReadHeader(_baseStream);
                _metadataBytes = header.MetadataBytes;
                _noncePrefix = header.NoncePrefix;
                metadata = DeserializeMetadata(_metadataBytes);
                _key = Rfc2898DeriveBytes.Pbkdf2(password, header.Salt, header.Iterations, HashAlgorithmName.SHA256, KeySize);
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

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    CryptographicOperations.ZeroMemory(_key);
                    CryptographicOperations.ZeroMemory(_plainBuffer);
                    _baseStream.Dispose();
                }

                base.Dispose(disposing);
            }

            private bool LoadNextChunk()
            {
                if (_endOfArchive)
                {
                    return false;
                }

                if (!TryReadChunkLength(_baseStream, out var chunkLength))
                {
                    throw new InvalidDataException("Locked archive is missing its authenticated terminator.");
                }

                if (chunkLength < 0 || chunkLength > BufferSize)
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
                try
                {
                    aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                    throw;
                }

                CryptographicOperations.ZeroMemory(_plainBuffer);
                if (chunkLength == 0)
                {
                    if (_baseStream.ReadByte() != -1)
                    {
                        throw new InvalidDataException("Locked archive has data after its authenticated terminator.");
                    }

                    _endOfArchive = true;
                    return false;
                }

                _plainBuffer = plaintext;
                _plainOffset = 0;
                _chunkIndex = checked(_chunkIndex + 1);
                return true;
            }
        }

        private sealed record SourceArchiveEntry(
            string RelativeName,
            string FullPath,
            bool IsDirectory,
            long Length,
            DateTime LastWriteTimeUtc,
            UnixFileMode Mode,
            FileAttributes WindowsAttributes,
            DateTime CreationTimeUtc,
            FileSystemIdentity Identity);

        internal sealed record RestoredArchiveEntry(
            string Path,
            bool IsDirectory,
            UnixFileMode Mode,
            DateTime ModifiedUtc,
            FileAttributes? WindowsAttributes,
            DateTime? CreationUtc);

        private sealed record ArchiveHeader(byte[] MetadataBytes, byte[] Salt, byte[] NoncePrefix, int Iterations);
    }

    public sealed record LockerArchiveCreationResult(
        string ArchivePath,
        string Sha256,
        DateTime LockedAtUtc,
        string SourceTreeSha256);

    public sealed record LockerArchiveMetadata(
        int FormatVersion,
        string LockerGuid,
        string LockerName,
        DateTime LockedAtUtc,
        string AppVersion,
        string CompressionArchiveFormat,
        UnixFileMode? RootUnixMode = null,
        DateTime? RootLastWriteTimeUtc = null,
        FileAttributes? RootWindowsAttributes = null,
        DateTime? RootCreationTimeUtc = null);

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

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ColDogStudios.ColDogLocker.Services.FileSystem;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    /// <summary>Hashes the names, types, lengths and exact file bytes in a locker tree.</summary>
    internal static class LockerTreeManifestDigest
    {
        private const int MaxEntries = 200000;

        internal static IncrementalHash Create() => IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        internal static void AppendEntry(
            IncrementalHash digest,
            string relativePath,
            bool isDirectory,
            long length,
            UnixFileMode mode,
            DateTime modifiedUtc,
            FileAttributes windowsAttributes,
            DateTime creationUtc,
            FileSystemIdentity identity)
        {
            Append(digest, isDirectory ? "directory" : "file");
            Append(digest, relativePath);
            Span<byte> encodedLength = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(encodedLength, length);
            digest.AppendData(encodedLength);
            Span<byte> encodedMode = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(encodedMode, (int)mode);
            digest.AppendData(encodedMode);
            Span<byte> encodedModified = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(encodedModified, modifiedUtc.Ticks);
            digest.AppendData(encodedModified);
            Span<byte> encodedAttributes = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(encodedAttributes, (int)windowsAttributes);
            digest.AppendData(encodedAttributes);
            Span<byte> encodedCreation = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(encodedCreation, creationUtc.Ticks);
            digest.AppendData(encodedCreation);
            Span<byte> encodedIdentity = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(encodedIdentity, identity.VolumeId);
            BinaryPrimitives.WriteUInt64LittleEndian(encodedIdentity[8..], identity.ObjectId);
            digest.AppendData(encodedIdentity);
        }

        internal static string Complete(IncrementalHash digest)
            => Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();

        internal static string Compute(string directory, string? expectedMovedWindowsAccessControl = null)
        {
            var root = Path.GetFullPath(directory);
            var rootInfo = new DirectoryInfo(root);
            FileSystemEntryPolicy.EnsureSupported(rootInfo);
            if (expectedMovedWindowsAccessControl == null)
            {
                FileSystemMetadataPolicy.EnsureSupported(rootInfo);
            }
            else if (OperatingSystem.IsWindows())
            {
                FileSystemMetadataPolicy.EnsureClaimedRootSupported(rootInfo, expectedMovedWindowsAccessControl);
            }
            else
            {
                throw new PlatformNotSupportedException("Moved-root access-control validation is only used on Windows.");
            }

            var rootIdentity = FileSystemIdentity.CaptureDirectory(root);
            var entries = new List<ManifestEntry>();
            var pending = new Stack<DirectoryInfo>();
            pending.Push(rootInfo);
            while (pending.TryPop(out var folder))
            {
                FileSystemEntryPolicy.EnsureSupported(folder);
                foreach (var child in folder.EnumerateFileSystemInfos())
                {
                    if (entries.Count >= MaxEntries)
                    {
                        throw new InvalidDataException("Locker tree exceeds the supported entry limit.");
                    }

                    FileSystemEntryPolicy.EnsureSupported(child);
                    FileSystemMetadataPolicy.EnsureSupported(child);
                    var identity = child is DirectoryInfo
                        ? FileSystemIdentity.CaptureDirectory(child.FullName)
                        : FileSystemIdentity.CaptureFile(child.FullName);
                    entries.Add(new ManifestEntry(child, identity));
                    if (child is DirectoryInfo childDirectory)
                    {
                        pending.Push(childDirectory);
                    }
                }
            }

            entries.Sort((left, right) => StringComparer.Ordinal.Compare(
                Relative(root, left.Info.FullName), Relative(root, right.Info.FullName)));
            using var digest = Create();
            AppendEntry(digest, string.Empty, isDirectory: true, 0, GetMode(rootInfo), rootInfo.LastWriteTimeUtc,
                GetWindowsAttributes(rootInfo), GetCreationTimeUtc(rootInfo), rootIdentity);
            var buffer = new byte[81920];
            foreach (var manifestEntry in entries)
            {
                var entry = manifestEntry.Info;
                var relativePath = Relative(root, entry.FullName);
                if (entry is DirectoryInfo)
                {
                    AppendEntry(digest, relativePath, isDirectory: true, 0, GetMode(entry), entry.LastWriteTimeUtc,
                        GetWindowsAttributes(entry), GetCreationTimeUtc(entry), manifestEntry.Identity);
                    EnsureIdentity(entry.FullName, isDirectory: true, manifestEntry.Identity);
                    continue;
                }

                if (entry is not FileInfo file)
                {
                    throw new InvalidDataException("Unsupported locker entry type.");
                }

                var length = file.Length;
                var modified = file.LastWriteTimeUtc;
                AppendEntry(digest, relativePath, isDirectory: false, length, GetMode(file), modified,
                    GetWindowsAttributes(file), GetCreationTimeUtc(file), manifestEntry.Identity);
                using var input = FileSystemEntryPolicy.OpenRead(file.FullName, rejectHardLinks: true,
                    expectedIdentity: manifestEntry.Identity);
                using var exactInput = new ExactLengthReadStream(input, length, digest);
                // Reading to EOF feeds every byte into the manifest digest through exactInput.
                while (exactInput.Read(buffer) != 0)
                {
                }

                exactInput.EnsureComplete();
                file.Refresh();
                if (file.Length != length || file.LastWriteTimeUtc != modified ||
                    FileSystemIdentity.CaptureFile(file.FullName) != manifestEntry.Identity)
                {
                    throw new IOException("Locker contents changed during manifest verification.");
                }
            }

            return Complete(digest);
        }

        private static void EnsureIdentity(string path, bool isDirectory, FileSystemIdentity expected)
        {
            var actual = isDirectory
                ? FileSystemIdentity.CaptureDirectory(path)
                : FileSystemIdentity.CaptureFile(path);
            if (actual != expected)
            {
                throw new IOException($"Locker entry was replaced during manifest verification: {path}");
            }
        }

        private static string Relative(string root, string path)
            => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');

        private static UnixFileMode GetMode(FileSystemInfo entry)
        {
            var mode = OperatingSystem.IsWindows()
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | (entry is DirectoryInfo ? UnixFileMode.UserExecute : 0)
                : File.GetUnixFileMode(entry.FullName);
            if (((int)mode & ~0x1ff) != 0)
            {
                throw new InvalidDataException("Special Unix permission bits are not supported in lockers.");
            }

            return mode;
        }

        private static FileAttributes GetWindowsAttributes(FileSystemInfo entry)
            => OperatingSystem.IsWindows() ? entry.Attributes & ~FileAttributes.Directory : 0;

        private static DateTime GetCreationTimeUtc(FileSystemInfo entry)
            => OperatingSystem.IsWindows() ? entry.CreationTimeUtc : DateTime.UnixEpoch;

        private static void Append(IncrementalHash digest, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
            digest.AppendData(length);
            digest.AppendData(bytes);
        }

        private sealed record ManifestEntry(FileSystemInfo Info, FileSystemIdentity Identity);
    }
}

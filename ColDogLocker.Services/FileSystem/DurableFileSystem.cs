using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>Orders filesystem namespace changes before the operation journal advances.</summary>
    internal static class DurableFileSystem
    {
        private const uint MoveFileWriteThrough = 0x00000008;
        private const int LinuxDirectoryOpenFlags = 0x000B0000;
        private const int DarwinDirectoryOpenFlags = 0x01100100;

        internal static void FlushDirectoryTree(string root)
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                         .OrderByDescending(path => path.Length))
            {
                FlushDirectory(directory);
            }

            FlushDirectory(root);
        }

        internal static void FlushDirectory(string path)
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            var descriptor = OperatingSystem.IsLinux()
                ? LinuxOpen(path, LinuxDirectoryOpenFlags)
                : OperatingSystem.IsMacOS()
                    ? DarwinOpen(path, DarwinDirectoryOpenFlags)
                    : throw new PlatformNotSupportedException("Directory durability is supported on Windows, Linux, and macOS.");
            if (descriptor < 0)
            {
                throw NativeIOException($"Could not open directory '{path}' for a durable flush.");
            }

            try
            {
                var result = OperatingSystem.IsLinux() ? LinuxFsync(descriptor) : DarwinFsync(descriptor);
                if (result != 0)
                {
                    throw NativeIOException($"Could not durably flush directory '{path}'.");
                }
            }
            finally
            {
                if (OperatingSystem.IsLinux())
                {
                    LinuxClose(descriptor);
                }
                else
                {
                    DarwinClose(descriptor);
                }
            }
        }

        internal static void MoveDirectory(string source, string destination)
        {
            if (OperatingSystem.IsWindows())
            {
                if (!MoveFileEx(source, destination, MoveFileWriteThrough))
                {
                    throw NativeIOException($"Could not durably move directory '{source}' to '{destination}'.");
                }

                return;
            }

            Directory.Move(source, destination);
            FlushRenameParents(source, destination);
        }

        internal static void MoveFile(string source, string destination)
        {
            if (OperatingSystem.IsWindows())
            {
                if (!MoveFileEx(source, destination, MoveFileWriteThrough))
                {
                    throw NativeIOException($"Could not durably move file '{source}' to '{destination}'.");
                }

                return;
            }

            File.Move(source, destination);
            FlushRenameParents(source, destination);
        }

        internal static void DeleteDirectory(string path, bool recursive)
        {
            var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)))
                ?? throw new IOException($"Directory '{path}' has no parent directory.");
            Directory.Delete(path, recursive);
            FlushDirectory(parent);
        }

        internal static void DeleteOwnedDirectory(string path, FileSystemIdentity expectedIdentity, bool recursive)
        {
            if (!Directory.Exists(path))
            {
                return;
            }

            var quarantine = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)) + $".cdl-delete-{Guid.NewGuid():N}";
            MoveDirectory(path, quarantine);
            try
            {
                var actualIdentity = FileSystemIdentity.CaptureDirectory(quarantine);
                if (actualIdentity != expectedIdentity)
                {
                    throw new IOException("A directory selected for cleanup was replaced by another filesystem object. The replacement was preserved.");
                }

                ClearAttributesForDelete(quarantine);
                DeleteDirectory(quarantine, recursive);
            }
            catch
            {
                if (Directory.Exists(quarantine) && !Path.Exists(path))
                {
                    MoveDirectory(quarantine, path);
                }

                throw;
            }
        }

        private static void ClearAttributesForDelete(string path)
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
        }

        internal static void DeleteFile(string path)
        {
            var parent = Path.GetDirectoryName(Path.GetFullPath(path))
                ?? throw new IOException($"File '{path}' has no parent directory.");
            File.Delete(path);
            FlushDirectory(parent);
        }

        private static void FlushRenameParents(string source, string destination)
        {
            var sourceParent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(source)))
                ?? throw new IOException($"Source '{source}' has no parent directory.");
            var destinationParent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(destination)))
                ?? throw new IOException($"Destination '{destination}' has no parent directory.");

            FlushDirectory(destinationParent);
            if (!sourceParent.Equals(destinationParent, StringComparison.Ordinal))
            {
                FlushDirectory(sourceParent);
            }
        }

        private static IOException NativeIOException(string message)
        {
            var error = Marshal.GetLastPInvokeError();
            return new IOException(message, new Win32Exception(error));
        }

        [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileEx(string existingFileName, string newFileName, uint flags);

        [DllImport("libc", EntryPoint = "open", SetLastError = true)]
        private static extern int LinuxOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

        [DllImport("libSystem.B.dylib", EntryPoint = "open", SetLastError = true)]
        private static extern int DarwinOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

        [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
        private static extern int LinuxFsync(int descriptor);

        [DllImport("libSystem.B.dylib", EntryPoint = "fsync", SetLastError = true)]
        private static extern int DarwinFsync(int descriptor);

        [DllImport("libc", EntryPoint = "close")]
        private static extern int LinuxClose(int descriptor);

        [DllImport("libSystem.B.dylib", EntryPoint = "close")]
        private static extern int DarwinClose(int descriptor);
    }
}

using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>Stable volume/object identity used to distinguish an owned directory from a path replacement.</summary>
    internal readonly record struct FileSystemIdentity(ulong VolumeId, ulong ObjectId)
    {
        internal static FileSystemIdentity CaptureDirectory(string path) => CapturePath(path, isDirectory: true);

        internal static FileSystemIdentity CaptureFile(string path) => CapturePath(path, isDirectory: false);

        internal static FileSystemIdentity CaptureHandle(SafeFileHandle handle, bool isDirectory)
        {
            ArgumentNullException.ThrowIfNull(handle);
            if (handle.IsInvalid)
            {
                throw new IOException("Cannot capture identity from an invalid filesystem handle.");
            }

            if (OperatingSystem.IsLinux())
            {
                const uint Requested = 0x00000101;
                if (LinuxStatx(handle.DangerousGetHandle().ToInt32(), string.Empty, 0x1000, Requested, out var result) != 0)
                {
                    throw NativeFailure("Could not inspect an opened filesystem entry.");
                }

                EnsureTypeAndMask(result, Requested, isDirectory, "opened filesystem entry");
                return FromLinux(result);
            }

            if (OperatingSystem.IsMacOS())
            {
                var attributes = IdentityAttributeList();
                if (DarwinGetHandleAttributes(handle.DangerousGetHandle().ToInt32(), ref attributes, out var result, 16, 0) != 0 ||
                    result.Length != 16)
                {
                    throw NativeFailure("Could not inspect an opened filesystem entry.");
                }

                return new FileSystemIdentity(result.Device, result.FileId);
            }

            if (OperatingSystem.IsWindows())
            {
                if (!GetFileInformationByHandle(handle, out var result))
                {
                    throw NativeFailure("Could not inspect an opened filesystem entry.");
                }

                EnsureWindowsType(result, isDirectory, "opened filesystem entry");
                return FromWindows(result);
            }

            throw new PlatformNotSupportedException("Filesystem identity is supported on Windows, Linux, and macOS.");
        }

        private static FileSystemIdentity CapturePath(string path, bool isDirectory)
        {
            path = Path.GetFullPath(path);
            FileSystemEntryPolicy.EnsureSupported(isDirectory ? new DirectoryInfo(path) : new FileInfo(path));

            try
            {
                if (OperatingSystem.IsLinux())
                {
                    const uint Requested = 0x00000101; // STATX_TYPE | STATX_INO
                    if (LinuxStatx(-100, path, 0x100, Requested, out var result) != 0)
                    {
                        throw NativeFailure($"Could not inspect directory '{path}'.");
                    }

                    EnsureTypeAndMask(result, Requested, isDirectory, path);
                    return FromLinux(result);
                }

                if (OperatingSystem.IsMacOS())
                {
                    // ATTR_CMN_DEVID | ATTR_CMN_FILEID, returned as length, dev_t and uint64_t.
                    var attributes = IdentityAttributeList();
                    if (DarwinGetAttributeList(path, ref attributes, out var result, 16, 1) != 0)
                    {
                        throw NativeFailure($"Could not inspect directory '{path}'.");
                    }

                    if (result.Length != 16)
                    {
                        throw new IOException($"The filesystem did not provide stable directory identity for '{path}'.");
                    }

                    return new FileSystemIdentity(result.Device, result.FileId);
                }

                if (OperatingSystem.IsWindows())
                {
                    const uint ShareAll = 0x00000001 | 0x00000002 | 0x00000004;
                    const uint OpenExisting = 3;
                    const uint BackupSemantics = 0x02000000;
                    const uint OpenReparsePoint = 0x00200000;
                    var flags = OpenReparsePoint | (isDirectory ? BackupSemantics : 0);
                    using var handle = CreateFile(path, 0, ShareAll, 0, OpenExisting, flags, 0);
                    if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var result))
                    {
                        throw NativeFailure($"Could not inspect directory '{path}'.");
                    }

                    EnsureWindowsType(result, isDirectory, path);
                    return FromWindows(result);
                }

                throw new PlatformNotSupportedException("Filesystem identity is supported on Windows, Linux, and macOS.");
            }
            catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
            {
                throw new PlatformNotSupportedException("Required filesystem identity inspection is unavailable. Operation was refused.", ex);
            }
        }

        private static IOException NativeFailure(string message) => new(message, new Win32Exception(Marshal.GetLastPInvokeError()));

        private static DarwinAttributeList IdentityAttributeList() => new()
        {
            BitmapCount = 5,
            CommonAttributes = 0x02000002
        };

        private static FileSystemIdentity FromLinux(LinuxStatxResult result) => new(((ulong)result.DeviceMajor << 32) | result.DeviceMinor, result.Inode);

        private static FileSystemIdentity FromWindows(WindowsFileInformation result) => new(result.VolumeSerialNumber, ((ulong)result.FileIndexHigh << 32) | result.FileIndexLow);

        private static void EnsureTypeAndMask(LinuxStatxResult result, uint requested, bool isDirectory, string path)
        {
            var expectedType = isDirectory ? 0x4000 : 0x8000;
            if ((result.Mask & requested) != requested || (result.Mode & 0xF000) != expectedType)
            {
                throw new IOException($"The filesystem did not provide stable {(isDirectory ? "directory" : "file")} identity for '{path}'.");
            }
        }

        private static void EnsureWindowsType(WindowsFileInformation result, bool isDirectory, string path)
        {
            var actualDirectory = (result.FileAttributes & 0x10) != 0;
            if ((result.FileAttributes & 0x400) != 0 || actualDirectory != isDirectory)
            {
                throw new InvalidDataException($"Entry '{path}' was replaced by a link, reparse point or unexpected entry type.");
            }
        }

        [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
        private static extern int LinuxStatx(int directoryDescriptor, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            int flags, uint mask, out LinuxStatxResult result);

        [DllImport("libSystem.B.dylib", EntryPoint = "getattrlist", SetLastError = true)]
        private static extern int DarwinGetAttributeList([MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            ref DarwinAttributeList attributes, out DarwinIdentityResult result, nuint bufferSize, nuint options);

        [DllImport("libSystem.B.dylib", EntryPoint = "fgetattrlist", SetLastError = true)]
        private static extern int DarwinGetHandleAttributes(int descriptor, ref DarwinAttributeList attributes,
            out DarwinIdentityResult result, nuint bufferSize, nuint options);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess, uint shareMode,
            nint securityAttributes, uint creationDisposition, uint flagsAndAttributes, nint templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out WindowsFileInformation result);

        [StructLayout(LayoutKind.Explicit, Size = 256)]
        private struct LinuxStatxResult
        {
            [FieldOffset(0)] public uint Mask;
            [FieldOffset(28)] public ushort Mode;
            [FieldOffset(32)] public ulong Inode;
            [FieldOffset(136)] public uint DeviceMajor;
            [FieldOffset(140)] public uint DeviceMinor;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DarwinAttributeList
        {
            public ushort BitmapCount;
            public ushort Reserved;
            public uint CommonAttributes;
            public uint VolumeAttributes;
            public uint DirectoryAttributes;
            public uint FileAttributes;
            public uint ForkAttributes;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct DarwinIdentityResult
        {
            [FieldOffset(0)] public uint Length;
            [FieldOffset(4)] public uint Device;
            [FieldOffset(8)] public ulong FileId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct WindowsFileInformation
        {
            public uint FileAttributes;
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
    }
}

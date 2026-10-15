using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>Rejects non-regular entries before data reads. Path checks do not establish stable filesystem identity.</summary>
    internal static class FileSystemEntryPolicy
    {
        internal static FileStream OpenRead(string path, Action? beforeOpen = null, bool rejectHardLinks = false,
            FileSystemIdentity? expectedIdentity = null)
        {
            path = Path.GetFullPath(path);
            EnsureSupported(new FileInfo(path));
            var inspectedIdentity = expectedIdentity ?? FileSystemIdentity.CaptureFile(path);
            beforeOpen?.Invoke();
            if (OperatingSystem.IsWindows())
            {
                var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                try
                {
                    if (rejectHardLinks)
                    {
                        EnsureSingleLink(stream.SafeFileHandle);
                    }

                    EnsureIdentity(stream.SafeFileHandle, inspectedIdentity);

                    return stream;
                }
                catch
                {
                    stream.Dispose();
                    throw;
                }
            }

            // O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_NOCTTY.
            var flags = OperatingSystem.IsLinux() ? 0xA0900 : 0x1020104;
            var descriptor = OperatingSystem.IsLinux() ? LinuxOpen(path, flags) : DarwinOpen(path, flags);
            if (descriptor < 0)
            {
                throw NativeFailure();
            }

            var handle = new SafeFileHandle((nint)descriptor, ownsHandle: true);
            try
            {
                bool regular;
                if (OperatingSystem.IsLinux())
                {
                    // AT_EMPTY_PATH inspects the opened descriptor, not the pathname.
                    if (LinuxStatx(descriptor, string.Empty, 0x1000, 1, out var result) != 0)
                    {
                        throw NativeFailure();
                    }

                    regular = (result.Mask & 1) != 0 && (result.Mode & 0xF000) == 0x8000;
                }
                else
                {
                    var attributes = new DarwinAttributeList { BitmapCount = 5, CommonAttributes = 8 };
                    if (DarwinGetHandleAttributes(descriptor, ref attributes, out var result, 8, 0) != 0)
                    {
                        throw NativeFailure();
                    }

                    regular = result.Length == 8 && result.Value == 1;
                }

                if (!regular)
                {
                    throw new InvalidDataException("The opened entry is not a regular file. No data was read.");
                }

                if (rejectHardLinks)
                {
                    EnsureSingleLink(handle);
                }

                EnsureIdentity(handle, inspectedIdentity);

                // Preserve the managed reader's advisory shared lock. O_NONBLOCK has
                // no effect on regular-file data reads; the managed wrapper stays synchronous.
                if ((OperatingSystem.IsLinux() ? LinuxFlock(descriptor, 1 | 4) : DarwinFlock(descriptor, 1 | 4)) != 0)
                {
                    throw NativeFailure();
                }

                return new FileStream(handle, FileAccess.Read, bufferSize: 4096, isAsync: false);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        internal static void EnsureSupported(FileSystemInfo entry, bool rejectHardLinks = false)
        {
            entry.Refresh();
            if (!entry.Exists)
            {
                throw new InvalidDataException("Missing entries, links, reparse points and devices are not supported in lockers.");
            }

            // On macOS use one authoritative type check: getattrlist with
            // FSOPT_NOFOLLOW rejects links without the managed/native metadata
            // disagreement seen for ordinary APFS entries.
            if (!OperatingSystem.IsMacOS() && (entry.LinkTarget != null ||
                (entry.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0))
            {
                throw new InvalidDataException("Missing entries, links, reparse points and devices are not supported in lockers.");
            }

            bool supported;
            try
            {
                if (OperatingSystem.IsLinux())
                {
                    // Linux UAPI statx: fixed 256-byte layout across supported architectures.
                    // AT_FDCWD=-100, AT_SYMLINK_NOFOLLOW=0x100, STATX_TYPE=1.
                    if (LinuxStatx(-100, entry.FullName, 0x100, 1, out var result) != 0)
                    {
                        throw NativeFailure();
                    }

                    if ((result.Mask & 1) == 0)
                    {
                        throw new IOException("The filesystem did not provide an entry type. Operation was refused.");
                    }

                    var type = result.Mode & 0xF000;
                    supported = entry is DirectoryInfo ? type == 0x4000 : type == 0x8000;
                }
                else if (OperatingSystem.IsMacOS())
                {
                    // ATTR_CMN_OBJTYPE, FSOPT_NOFOLLOW; returned buffer is length + fsobj_type_t.
                    var attributes = new DarwinAttributeList { BitmapCount = 5, CommonAttributes = 8 };
                    if (DarwinGetAttributeList(entry.FullName, ref attributes, out var result, 8, 1) != 0)
                    {
                        throw NativeFailure();
                    }

                    supported = result.Length == 8 && (entry is DirectoryInfo ? result.Value == 2 : result.Value == 1);
                }
                else if (OperatingSystem.IsWindows())
                {
                    supported = entry is DirectoryInfo or FileInfo;
                }
                else
                {
                    throw new PlatformNotSupportedException("Filesystem entry validation is not implemented on this platform.");
                }
            }
            catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
            {
                throw new PlatformNotSupportedException("Required filesystem type inspection is unavailable. Operation was refused.", ex);
            }

            if (!supported)
            {
                throw new InvalidDataException("Only regular files and directories are supported. FIFOs, sockets and device files must be excluded.");
            }

            if (rejectHardLinks && entry is FileInfo)
            {
                using var stream = OpenRead(entry.FullName, rejectHardLinks: true);
            }
        }

        private static void EnsureSingleLink(SafeFileHandle handle)
        {
            uint links;
            if (OperatingSystem.IsLinux())
            {
                // AT_EMPTY_PATH, STATX_NLINK: inspect the descriptor that will be read.
                if (LinuxStatx(handle.DangerousGetHandle().ToInt32(), string.Empty, 0x1000, 4, out var result) != 0)
                {
                    throw NativeFailure();
                }

                if ((result.Mask & 4) == 0)
                {
                    throw new IOException("The filesystem did not provide a link count. Operation was refused.");
                }

                links = result.LinkCount;
            }
            else if (OperatingSystem.IsMacOS())
            {
                // ATTR_FILE_LINKCOUNT only: uint buffer length followed by uint link count.
                var attributes = new DarwinAttributeList { BitmapCount = 5, FileAttributes = 1 };
                if (DarwinGetHandleAttributes(handle.DangerousGetHandle().ToInt32(), ref attributes, out var result, 8, 0) != 0)
                {
                    throw NativeFailure();
                }

                if (result.Length != 8)
                {
                    throw new IOException("The filesystem did not provide a link count. Operation was refused.");
                }

                links = result.Value;
            }
            else if (OperatingSystem.IsWindows())
            {
                if (!GetFileInformationByHandleEx(handle, 1, out var result, 24))
                {
                    throw NativeFailure();
                }

                links = result.LinkCount;
            }
            else
            {
                throw new PlatformNotSupportedException("Link-count inspection is not implemented on this platform.");
            }

            if (links != 1)
            {
                throw new InvalidDataException("Hard-linked or unlinked files are not supported in lockers. Operation was refused.");
            }
        }

        private static void EnsureIdentity(SafeFileHandle handle, FileSystemIdentity expectedIdentity)
        {
            if (FileSystemIdentity.CaptureHandle(handle, isDirectory: false) != expectedIdentity)
            {
                throw new IOException("The file was replaced between inspection and opening. No replacement data was read.");
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass,
            out WindowsStandardInfo result, uint bufferSize);

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        private struct WindowsStandardInfo
        {
            [FieldOffset(16)] public uint LinkCount;
        }

        [DllImport("libSystem.B.dylib", EntryPoint = "flock", SetLastError = true)]
        private static extern int DarwinFlock(int descriptor, int operation);

        private static IOException NativeFailure() => new($"Cannot safely open or inspect filesystem entry (native error {Marshal.GetLastPInvokeError()}). Operation was refused.");

        [DllImport("libc", EntryPoint = "open", SetLastError = true)]
        private static extern int LinuxOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

        [DllImport("libSystem.B.dylib", EntryPoint = "open", SetLastError = true)]
        private static extern int DarwinOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

        [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
        private static extern int LinuxFlock(int descriptor, int operation);

        [DllImport("libSystem.B.dylib", EntryPoint = "fgetattrlist", SetLastError = true)]
        private static extern int DarwinGetHandleAttributes(int descriptor, ref DarwinAttributeList attributes,
            out DarwinAttributeResult result, nuint bufferSize, nuint options);

        [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
        private static extern int LinuxStatx(int directoryDescriptor, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            int flags, uint mask, out LinuxStatxResult result);

        [DllImport("libSystem.B.dylib", EntryPoint = "getattrlist", SetLastError = true)]
        private static extern int DarwinGetAttributeList([MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            ref DarwinAttributeList attributes, out DarwinAttributeResult result, nuint bufferSize, nuint options);

        [StructLayout(LayoutKind.Explicit, Size = 256)]
        private struct LinuxStatxResult
        {
            [FieldOffset(0)] public uint Mask;
            [FieldOffset(16)] public uint LinkCount;
            [FieldOffset(28)] public ushort Mode;
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

        [StructLayout(LayoutKind.Sequential)]
        private struct DarwinAttributeResult
        {
            public uint Length;
            public uint Value;
        }
    }
}

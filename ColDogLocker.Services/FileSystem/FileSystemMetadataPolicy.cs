using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>Rejects filesystem metadata that the current archive format cannot reproduce safely.</summary>
    internal static class FileSystemMetadataPolicy
    {
        private const int AtFdcwd = -100;
        private const int AtSymlinkNoFollow = 0x100;
        private const uint StatxUid = 0x8;
        private const uint StatxGid = 0x10;
        private const int DarwinNoFollow = 0x1;
        private const uint DarwinOwnerAndGroup = 0x00018000;
        private const int DarwinAclTypeExtended = 0x100;
        private const int DarwinAclFirstEntry = 0;
        private const int ErrorNoEntry = 2;
        private const int ErrorHandleEof = 38;
        private static readonly nint _invalidHandle = new(-1);

        internal static void EnsureTreeSupported(string root)
        {
            var rootInfo = new DirectoryInfo(Path.GetFullPath(root));
            EnsureSupported(rootInfo);
            var directories = new Stack<DirectoryInfo>();
            directories.Push(rootInfo);
            while (directories.Count > 0)
            {
                var directory = directories.Pop();
                foreach (var entry in directory.EnumerateFileSystemInfos())
                {
                    FileSystemEntryPolicy.EnsureSupported(entry, rejectHardLinks: true);
                    EnsureSupported(entry);
                    if (entry is DirectoryInfo child)
                    {
                        directories.Push(child);
                    }
                }
            }
        }

        internal static void NormalizePublishedTree(string root)
        {
            if (!OperatingSystem.IsWindows())
            {
                return;
            }

            var rootInfo = new DirectoryInfo(Path.GetFullPath(root));
            NormalizeInheritedWindowsAccessControl(rootInfo);
            EnsureTreeSupported(root);
        }

        [SupportedOSPlatform("windows")]
        internal static void EnsureExpectedRootSupported(FileSystemInfo entry, string expectedAccessControl)
        {
            EnsureWindowsMetadataSupported(entry, allowExplicitRules: true, allowProtectedRules: true);
            if (!CaptureWindowsAccessControl(entry).Equals(expectedAccessControl, StringComparison.Ordinal))
            {
                throw new IOException("The locker root access-control list changed during filesystem validation.");
            }
        }

        internal static void EnsureSupported(FileSystemInfo entry)
        {
            entry.Refresh();
            if (OperatingSystem.IsWindows())
            {
                EnsureWindowsMetadataSupported(entry);
                return;
            }

            if (OperatingSystem.IsLinux())
            {
                EnsureLinuxOwnership(entry.FullName);
            }
            else if (OperatingSystem.IsMacOS())
            {
                EnsureDarwinOwnership(entry.FullName);
                EnsureDarwinAclAbsent(entry.FullName);
            }
            else
            {
                throw new PlatformNotSupportedException("Filesystem metadata inspection is not implemented on this platform.");
            }

            var unsupported = ListExtendedAttributes(entry.FullName)
                .Where(name => !(OperatingSystem.IsLinux() && name.Equals("security.selinux", StringComparison.Ordinal)))
                .ToList();
            if (unsupported.Count != 0)
            {
                throw new InvalidDataException(
                    $"Extended attributes are not supported in lockers ({string.Join(", ", unsupported)}). Original files have not been removed.");
            }
        }

        private static IReadOnlyList<string> ListExtendedAttributes(string path)
        {
            nint length = OperatingSystem.IsLinux()
                ? LinuxListExtendedAttributes(path, nint.Zero, 0)
                : DarwinListExtendedAttributes(path, nint.Zero, 0, DarwinNoFollow);
            if (length < 0)
            {
                throw NativeIOException($"Could not inspect extended attributes for '{path}'.");
            }

            if (length == 0)
            {
                return [];
            }

            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                var actual = OperatingSystem.IsLinux()
                    ? LinuxListExtendedAttributes(path, buffer, checked((nuint)length))
                    : DarwinListExtendedAttributes(path, buffer, checked((nuint)length), DarwinNoFollow);
                if (actual < 0)
                {
                    throw NativeIOException($"Could not read extended attributes for '{path}'.");
                }

                var bytes = new byte[checked((int)actual)];
                Marshal.Copy(buffer, bytes, 0, bytes.Length);
                return Encoding.UTF8.GetString(bytes)
                    .Split('\0', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void EnsureLinuxOwnership(string path)
        {
            if (LinuxStatx(AtFdcwd, path, AtSymlinkNoFollow, StatxUid | StatxGid, out var result) != 0)
            {
                throw NativeIOException($"Could not inspect ownership for '{path}'.");
            }

            if ((result.Mask & (StatxUid | StatxGid)) != (StatxUid | StatxGid))
            {
                throw new IOException($"The filesystem did not provide ownership for '{path}'. Operation was refused.");
            }

            if (result.UserId != LinuxEffectiveUserId() || result.GroupId != LinuxEffectiveGroupId())
            {
                throw new InvalidDataException($"Non-current ownership is not supported in lockers: {path}");
            }
        }

        private static void EnsureDarwinOwnership(string path)
        {
            var attributes = new DarwinAttributeList { BitmapCount = 5, CommonAttributes = DarwinOwnerAndGroup };
            if (DarwinGetAttributeList(path, ref attributes, out var result, 12, DarwinNoFollow) != 0 || result.Length != 12)
            {
                throw NativeIOException($"Could not inspect ownership for '{path}'.");
            }

            if (result.UserId != DarwinEffectiveUserId() || result.GroupId != DarwinEffectiveGroupId())
            {
                throw new InvalidDataException($"Non-current ownership is not supported in lockers: {path}");
            }
        }

        private static void EnsureDarwinAclAbsent(string path)
        {
            var acl = DarwinGetAcl(path, DarwinAclTypeExtended);
            if (acl == nint.Zero)
            {
                // macOS reports ENOENT when the entry exists but has no extended
                // ACL. The following no-follow xattr inspection still detects a
                // path that actually disappeared between metadata checks.
                if (Marshal.GetLastPInvokeError() == ErrorNoEntry)
                {
                    return;
                }

                throw NativeIOException($"Could not inspect the access-control list for '{path}'.");
            }

            try
            {
                var result = DarwinGetAclEntry(acl, DarwinAclFirstEntry, out _);
                if (result == 0)
                {
                    throw new InvalidDataException($"Extended access-control lists are not supported in lockers: {path}");
                }

                if (result < 0)
                {
                    throw NativeIOException($"Could not inspect the access-control list for '{path}'.");
                }
            }
            finally
            {
                DarwinFreeAcl(acl);
            }
        }

        [SupportedOSPlatform("windows")]
        internal static string CaptureWindowsAccessControl(FileSystemInfo entry)
        {
            var security = ReadWindowsSecurity(entry);
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
                ?? throw new UnauthorizedAccessException("Cannot identify the filesystem entry owner.");
            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Select(rule => string.Join('|',
                    ((SecurityIdentifier)rule.IdentityReference).Value,
                    (int)rule.AccessControlType,
                    (int)rule.FileSystemRights,
                    (int)rule.InheritanceFlags,
                    (int)rule.PropagationFlags))
                .OrderBy(rule => rule, StringComparer.Ordinal);
            return string.Join('\n',
                new[] { owner.Value, security.AreAccessRulesProtected ? "protected" : "inherited" }.Concat(rules));
        }

        [SupportedOSPlatform("windows")]
        private static void EnsureWindowsMetadataSupported(
            FileSystemInfo entry,
            bool allowExplicitRules = false,
            bool allowProtectedRules = false)
        {
            const FileAttributes SupportedAttributes = FileAttributes.Directory | FileAttributes.Normal |
                FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System | FileAttributes.Archive |
                FileAttributes.Temporary | FileAttributes.NotContentIndexed;
            if ((entry.Attributes & ~SupportedAttributes) != 0 ||
                ((entry.Attributes & FileAttributes.Normal) != 0 && entry.Attributes != FileAttributes.Normal))
            {
                throw new InvalidDataException($"This entry has Windows attributes that are not supported in lockers: {entry.FullName}");
            }

            using var identity = WindowsIdentity.GetCurrent();
            var user = identity.User
                ?? throw new UnauthorizedAccessException("Cannot identify the current user for filesystem metadata inspection.");
            var tokenOwner = identity.Owner ?? user;
            var security = ReadWindowsSecurity(entry);
            var actualOwner = security.GetOwner(typeof(SecurityIdentifier));
            if ((!user.Equals(actualOwner) && !tokenOwner.Equals(actualOwner)) ||
                (!allowProtectedRules && security.AreAccessRulesProtected))
            {
                throw new InvalidDataException($"Custom ownership or protected access-control lists are not supported in lockers: {entry.FullName}");
            }

            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
            if (!allowExplicitRules && rules.Cast<FileSystemAccessRule>().Any(rule => !rule.IsInherited))
            {
                throw new InvalidDataException($"Explicit access-control rules are not supported in lockers: {entry.FullName}");
            }

            EnsureNoAlternateDataStreams(entry.FullName);
        }

        [SupportedOSPlatform("windows")]
        private static FileSystemSecurity ReadWindowsSecurity(FileSystemInfo entry) => entry switch
        {
            DirectoryInfo directory => directory.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            FileInfo file => file.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            _ => throw new InvalidDataException($"Unsupported filesystem entry: {entry.FullName}")
        };

        [SupportedOSPlatform("windows")]
        private static void NormalizeInheritedWindowsAccessControl(FileSystemInfo entry)
        {
            var security = ReadWindowsSecurity(entry);
            var explicitRules = security
                .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();
            foreach (var rule in explicitRules)
            {
                security.RemoveAccessRuleSpecific(rule);
            }

            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            switch (entry)
            {
                case DirectoryInfo directory:
                    directory.SetAccessControl((DirectorySecurity)security);
                    break;
                case FileInfo file:
                    file.SetAccessControl((FileSecurity)security);
                    break;
                default:
                    throw new InvalidDataException($"Unsupported filesystem entry: {entry.FullName}");
            }

            entry.Refresh();
            EnsureWindowsMetadataSupported(entry);
        }

        [SupportedOSPlatform("windows")]
        private static void EnsureNoAlternateDataStreams(string path)
        {
            var handle = FindFirstStream(path, 0, out var data, 0);
            if (handle == _invalidHandle)
            {
                var error = Marshal.GetLastPInvokeError();
                if (error == ErrorHandleEof)
                {
                    return;
                }

                throw new IOException($"Could not inspect alternate data streams for '{path}'.", new Win32Exception(error));
            }

            try
            {
                do
                {
                    if (!data.StreamName.Equals("::$DATA", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException($"Alternate data streams are not supported in lockers: {path}{data.StreamName}");
                    }
                } while (FindNextStream(handle, out data));

                var error = Marshal.GetLastPInvokeError();
                if (error != ErrorHandleEof)
                {
                    throw new IOException($"Could not finish inspecting alternate data streams for '{path}'.", new Win32Exception(error));
                }
            }
            finally
            {
                FindClose(handle);
            }
        }

        private static IOException NativeIOException(string message)
        {
            var error = Marshal.GetLastPInvokeError();
            return new IOException(message, new Win32Exception(error));
        }

        [DllImport("libc", EntryPoint = "llistxattr", SetLastError = true)]
        private static extern nint LinuxListExtendedAttributes([MarshalAs(UnmanagedType.LPUTF8Str)] string path, nint list, nuint size);

        [DllImport("libSystem.B.dylib", EntryPoint = "listxattr", SetLastError = true)]
        private static extern nint DarwinListExtendedAttributes([MarshalAs(UnmanagedType.LPUTF8Str)] string path, nint list, nuint size, int options);

        [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
        private static extern int LinuxStatx(int directoryDescriptor, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            int flags, uint mask, out LinuxStatxResult result);

        [DllImport("libc", EntryPoint = "geteuid")]
        private static extern uint LinuxEffectiveUserId();

        [DllImport("libc", EntryPoint = "getegid")]
        private static extern uint LinuxEffectiveGroupId();

        [DllImport("libSystem.B.dylib", EntryPoint = "geteuid")]
        private static extern uint DarwinEffectiveUserId();

        [DllImport("libSystem.B.dylib", EntryPoint = "getegid")]
        private static extern uint DarwinEffectiveGroupId();

        [DllImport("libSystem.B.dylib", EntryPoint = "getattrlist", SetLastError = true)]
        private static extern int DarwinGetAttributeList([MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            ref DarwinAttributeList attributes, out DarwinOwnerGroupResult result, nuint bufferSize, nuint options);

        [DllImport("libSystem.B.dylib", EntryPoint = "acl_get_file", SetLastError = true)]
        private static extern nint DarwinGetAcl([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int type);

        [DllImport("libSystem.B.dylib", EntryPoint = "acl_get_entry", SetLastError = true)]
        private static extern int DarwinGetAclEntry(nint acl, int entryId, out nint entry);

        [DllImport("libSystem.B.dylib", EntryPoint = "acl_free")]
        private static extern int DarwinFreeAcl(nint acl);

        [DllImport("kernel32.dll", EntryPoint = "FindFirstStreamW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern nint FindFirstStream(string fileName, int infoLevel, out WindowsFindStreamData data, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "FindNextStreamW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindNextStream(nint handle, out WindowsFindStreamData data);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(nint handle);

        [StructLayout(LayoutKind.Explicit, Size = 256)]
        private struct LinuxStatxResult
        {
            [FieldOffset(0)] public uint Mask;
            [FieldOffset(20)] public uint UserId;
            [FieldOffset(24)] public uint GroupId;
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
        private struct DarwinOwnerGroupResult
        {
            public uint Length;
            public uint UserId;
            public uint GroupId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WindowsFindStreamData
        {
            public long StreamSize;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string StreamName;
        }
    }
}

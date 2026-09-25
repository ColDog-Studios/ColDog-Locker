using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ColDogStudios.ColDogLocker.Core.Validation;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    internal static class PrivateDirectory
    {
        private const UnixFileMode OwnerOnly =
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

        internal static string Ensure(string path)
        {
            var fullPath = Path.GetFullPath(path);
            if (File.Exists(fullPath))
            {
                throw new IOException($"Private directory path is occupied by a file: {fullPath}");
            }

            if (LockerPathFilter.FindLinkedAncestor(fullPath) is { } linkedPath)
            {
                throw new InvalidDataException($"Private directory contains a link or reparse point: {linkedPath}");
            }

            if (OperatingSystem.IsWindows())
            {
                EnsureWindowsOwnerOnly(fullPath);
            }
            else
            {
                Directory.CreateDirectory(fullPath, OwnerOnly);
                File.SetUnixFileMode(fullPath, OwnerOnly);
                if (File.GetUnixFileMode(fullPath) != OwnerOnly)
                {
                    throw new UnauthorizedAccessException($"Private directory permissions could not be enforced: {fullPath}");
                }
            }

            FileSystemEntryPolicy.EnsureSupported(new DirectoryInfo(fullPath));
            return fullPath;
        }

        [SupportedOSPlatform("windows")]
        private static void EnsureWindowsOwnerOnly(string path)
        {
            var owner = WindowsIdentity.GetCurrent().User
                ?? throw new UnauthorizedAccessException("Cannot identify the current user for private staging.");
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(owner);
            security.AddAccessRule(new FileSystemAccessRule(
                owner,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            var directory = new DirectoryInfo(path);
            if (directory.Exists)
            {
                directory.SetAccessControl(security);
            }
            else
            {
                directory.Create(security);
            }

            var applied = directory.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            if (!applied.AreAccessRulesProtected || !owner.Equals(applied.GetOwner(typeof(SecurityIdentifier))))
            {
                throw new UnauthorizedAccessException($"Private directory permissions could not be enforced: {path}");
            }
        }
    }
}

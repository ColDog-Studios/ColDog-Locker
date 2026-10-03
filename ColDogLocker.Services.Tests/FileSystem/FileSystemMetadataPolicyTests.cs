using System.Diagnostics;
using System.Formats.Tar;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public sealed class FileSystemMetadataPolicyTests : IDisposable
    {
        private const string Password = "Metadata-policy@5821!";
        private readonly string _root = Directory.CreateDirectory(Path.Join(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), $"cdl-metadata-policy-{Guid.NewGuid():N}")).FullName;

        [Fact]
        public void OrdinaryOwnedTree_IsSupported()
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            File.WriteAllText(Path.Join(source, "plain.txt"), "plain");

            FileSystemMetadataPolicy.EnsureTreeSupported(source);
        }

        [UnixFact]
        public void ArchiveCreation_RejectsUserExtendedAttributeWithoutChangingSource()
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            var file = Path.Join(source, "secret.txt");
            File.WriteAllText(file, "secret");
            SetUserExtendedAttribute(file, "user.coldog-test", "unsupported");
            var archive = Path.Join(_root, "locker.cdl");
            var locker = new LockerModel("Vault", "unused", source);

            var error = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.CreateFromDirectory(source, archive, locker, Password));

            Assert.Contains("Extended attributes", error.Message);
            Assert.Equal("secret", File.ReadAllText(file));
            Assert.False(File.Exists(archive));
        }

        [WindowsFact]
        [SupportedOSPlatform("windows")]
        public void ArchiveCreation_RejectsAlternateDataStreamWithoutChangingSource()
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            var file = Path.Join(source, "secret.txt");
            File.WriteAllText(file, "secret");
            File.WriteAllText(file + ":metadata", "unsupported");
            var archive = Path.Join(_root, "locker.cdl");
            var locker = new LockerModel("Vault", "unused", source);

            var error = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.CreateFromDirectory(source, archive, locker, Password));

            Assert.Contains("Alternate data streams", error.Message);
            Assert.Equal("secret", File.ReadAllText(file));
            Assert.Equal("unsupported", File.ReadAllText(file + ":metadata"));
            Assert.False(File.Exists(archive));
        }

        [WindowsFact]
        [SupportedOSPlatform("windows")]
        public void ArchiveCreation_RejectsExplicitAccessRuleWithoutChangingSource()
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            var file = Path.Join(source, "secret.txt");
            File.WriteAllText(file, "secret");
            var info = new FileInfo(file);
            var security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                WindowsIdentity.GetCurrent().User!,
                FileSystemRights.ReadData,
                AccessControlType.Allow));
            info.SetAccessControl(security);
            var archive = Path.Join(_root, "locker.cdl");
            var locker = new LockerModel("Vault", "unused", source);

            var error = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.CreateFromDirectory(source, archive, locker, Password));

            Assert.Contains("Explicit access-control", error.Message);
            Assert.Equal("secret", File.ReadAllText(file));
            Assert.False(File.Exists(archive));
        }

        [WindowsFact]
        [SupportedOSPlatform("windows")]
        public void ArchiveCreation_RejectsProtectedAccessRulesWithoutChangingSource()
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            var file = Path.Join(source, "secret.txt");
            File.WriteAllText(file, "secret");
            var info = new FileInfo(file);
            var security = info.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: true);
            info.SetAccessControl(security);
            var archive = Path.Join(_root, "locker.cdl");
            var locker = new LockerModel("Vault", "unused", source);

            var error = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.CreateFromDirectory(source, archive, locker, Password));

            Assert.Contains("protected access-control", error.Message);
            Assert.Equal("secret", File.ReadAllText(file));
            Assert.False(File.Exists(archive));
        }

        [MacOSFact]
        [SupportedOSPlatform("macos")]
        public void ArchiveCreation_RejectsExtendedAclWithoutChangingSource()
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            var file = Path.Join(source, "secret.txt");
            File.WriteAllText(file, "secret");
            using (var process = Process.Start(CreateChmodStartInfo("+a", "everyone allow read", file))!)
            {
                process.WaitForExit();
                Assert.Equal(0, process.ExitCode);
            }

            var archive = Path.Join(_root, "locker.cdl");
            var locker = new LockerModel("Vault", "unused", source);

            var error = Assert.Throws<InvalidDataException>(() =>
                LockerArchiveService.CreateFromDirectory(source, archive, locker, Password));

            Assert.Contains("Extended access-control", error.Message);
            Assert.Equal("secret", File.ReadAllText(file));
            Assert.False(File.Exists(archive));
        }

        [WindowsFact]
        [SupportedOSPlatform("windows")]
        public void RoundTrip_PreservesWindowsAttributesCreationAndModificationTimes()
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            var child = Directory.CreateDirectory(Path.Join(source, "nested")).FullName;
            var file = Path.Join(source, "secret.txt");
            var nestedFile = Path.Join(child, "nested.txt");
            File.WriteAllText(file, "secret");
            File.WriteAllText(nestedFile, "nested");
            var rootCreation = new DateTime(2000, 1, 2, 3, 4, 6, DateTimeKind.Utc);
            var fileCreation = new DateTime(2001, 2, 3, 4, 5, 6, DateTimeKind.Utc);
            var modified = new DateTime(2002, 3, 4, 5, 6, 8, DateTimeKind.Utc);
            Directory.SetCreationTimeUtc(source, rootCreation);
            File.SetCreationTimeUtc(file, fileCreation);
            File.SetLastWriteTimeUtc(file, modified);
            File.SetAttributes(file, FileAttributes.Hidden | FileAttributes.ReadOnly | FileAttributes.Archive);
            File.SetAttributes(source, File.GetAttributes(source) | FileAttributes.Hidden);
            var archive = Path.Join(_root, "locker.cdl");
            var locker = new LockerModel("Vault", "unused", source);

            LockerArchiveService.CreateFromDirectory(source, archive, locker, Password);
            var restored = Path.Join(_root, "restored");
            LockerArchiveService.ExtractToDirectory(archive, restored, locker, Password);

            var restoredFile = Path.Join(restored, "secret.txt");
            Assert.Equal(fileCreation, File.GetCreationTimeUtc(restoredFile));
            Assert.Equal(modified, File.GetLastWriteTimeUtc(restoredFile));
            Assert.Equal(
                FileAttributes.Hidden | FileAttributes.ReadOnly | FileAttributes.Archive,
                File.GetAttributes(restoredFile) & ~FileAttributes.Directory);
            Assert.Equal(rootCreation, Directory.GetCreationTimeUtc(restored));
            Assert.True((File.GetAttributes(restored) & FileAttributes.Hidden) != 0);
            var restoredChildSecurity = new DirectoryInfo(Path.Join(restored, "nested"))
                .GetAccessControl(AccessControlSections.Access);
            Assert.False(restoredChildSecurity.AreAccessRulesProtected);
            Assert.Empty(restoredChildSecurity
                .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>());
            var restoredAccessControl = FileSystemMetadataPolicy.CaptureWindowsAccessControl(new DirectoryInfo(restored));
            Assert.Equal(64, LockerTreeDigest.Compute(restored, restoredAccessControl).Length);
        }

        [UnixFact]
        public void Extraction_RejectsWindowsMetadataOnUnsupportedPlatform()
        {
            var tar = new MemoryStream();
            using (var writer = new TarWriter(tar, leaveOpen: true))
            {
                writer.WriteEntry(new PaxTarEntry(
                    TarEntryType.RegularFile,
                    "secret.txt",
                    new Dictionary<string, string>
                    {
                        ["CDL.windowsAttributes"] = ((int)FileAttributes.Hidden).ToString(),
                        ["CDL.windowsCreationTimeUtc"] = DateTime.UtcNow.Ticks.ToString()
                    })
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes("secret"))
                });
            }

            tar.Position = 0;
            Assert.Throws<PlatformNotSupportedException>(() =>
                LockerArchiveService.ExtractValidatedTar(tar, Path.Join(_root, "restored")));
        }

        private static void SetUserExtendedAttribute(string path, string name, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            var result = OperatingSystem.IsLinux()
                ? LinuxSetExtendedAttribute(path, name, bytes, (nuint)bytes.Length, 0)
                : DarwinSetExtendedAttribute(path, name, bytes, (nuint)bytes.Length, 0, 0);
            Assert.Equal(0, result);
        }

        private static ProcessStartInfo CreateChmodStartInfo(params string[] arguments)
        {
            var start = new ProcessStartInfo("/bin/chmod")
            {
                UseShellExecute = false
            };
            foreach (var argument in arguments)
            {
                start.ArgumentList.Add(argument);
            }

            return start;
        }

        [DllImport("libc", EntryPoint = "setxattr", SetLastError = true)]
        private static extern int LinuxSetExtendedAttribute(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
            byte[] value,
            nuint size,
            int flags);

        [DllImport("libSystem.B.dylib", EntryPoint = "setxattr", SetLastError = true)]
        private static extern int DarwinSetExtendedAttribute(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
            byte[] value,
            nuint size,
            uint position,
            int options);

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                foreach (var file in Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, File.GetAttributes(file) &
                        ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                }

                foreach (var directory in Directory.EnumerateDirectories(_root, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(directory, File.GetAttributes(directory) &
                        ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                }

                File.SetAttributes(_root, File.GetAttributes(_root) &
                    ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                Directory.Delete(_root, recursive: true);
            }
        }
    }

    public sealed class MacOSFactAttribute : FactAttribute
    {
        public MacOSFactAttribute()
        {
            if (!OperatingSystem.IsMacOS())
            {
                Skip = "macOS ACL validation requires a macOS host.";
            }
        }
    }
}

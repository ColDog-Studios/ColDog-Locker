using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ColDogStudios.ColDogLocker.Services.FileSystem;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public sealed class PrivateDirectoryTests : IDisposable
    {
        private readonly string _root = Path.Join(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            $"cdl-private-directory-tests-{Guid.NewGuid():N}");

        public PrivateDirectoryTests() => Directory.CreateDirectory(_root);

        [UnixFact]
        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        public void Ensure_TightensExistingUnixDirectoryToOwnerOnly()
        {
            var path = Directory.CreateDirectory(Path.Join(_root, "staging")).FullName;
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);

            Assert.Equal(path, PrivateDirectory.Ensure(path));

            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                File.GetUnixFileMode(path));
        }

        [UnixFact]
        public void Ensure_RejectsLinkedAncestorWithoutChangingTarget()
        {
            var target = Directory.CreateDirectory(Path.Join(_root, "target")).FullName;
            var link = Path.Join(_root, "link");
            Directory.CreateSymbolicLink(link, target);

            Assert.Throws<InvalidDataException>(() => PrivateDirectory.Ensure(Path.Join(link, "staging")));
            Assert.Empty(Directory.EnumerateFileSystemEntries(target));
        }

        [Fact]
        public void Ensure_RejectsFileAtDirectoryPath()
        {
            var path = Path.Join(_root, "occupied");
            File.WriteAllText(path, "unrelated");

            Assert.Throws<IOException>(() => PrivateDirectory.Ensure(path));
            Assert.Equal("unrelated", File.ReadAllText(path));
        }

        [WindowsFact]
        [SupportedOSPlatform("windows")]
        public void Ensure_AppliesProtectedOwnerOnlyWindowsAcl()
        {
            var path = PrivateDirectory.Ensure(Path.Join(_root, "staging"));
            var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            var owner = WindowsIdentity.GetCurrent().User;

            Assert.True(security.AreAccessRulesProtected);
            Assert.Equal(owner, security.GetOwner(typeof(SecurityIdentifier)));
            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();
            Assert.All(rules, rule => Assert.Equal(owner, rule.IdentityReference));
            Assert.Contains(rules, rule => rule.AccessControlType == AccessControlType.Allow &&
                (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl);
        }

        [WindowsFact]
        [SupportedOSPlatform("windows")]
        public void NormalizePublishedTree_ReplacesPrivateAclWithInheritedAcl()
        {
            var path = PrivateDirectory.Ensure(Path.Join(_root, "staging"));
            var child = Path.Join(path, "secret.txt");
            File.WriteAllText(child, "secret");
            var privateAccessControl = FileSystemMetadataPolicy.CaptureWindowsAccessControl(new DirectoryInfo(path));

            FileSystemMetadataPolicy.EnsureExpectedRootSupported(new DirectoryInfo(path), privateAccessControl);

            FileSystemMetadataPolicy.NormalizePublishedTree(path);

            FileSystemMetadataPolicy.EnsureTreeSupported(path);
            var rootSecurity = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
            Assert.False(rootSecurity.AreAccessRulesProtected);
            Assert.Empty(
                rootSecurity.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                    .Cast<FileSystemAccessRule>());
        }

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }

    public sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Windows ACL validation requires a Windows host.";
            }
        }
    }
}

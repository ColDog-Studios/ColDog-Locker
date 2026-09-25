using ColDogStudios.ColDogLocker.Services.FileSystem;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public class FileSystemIdentityTests
    {
        [Fact]
        public void CaptureDirectory_FollowsDirectoryAcrossRename()
        {
            using var workspace = new TestDirectory();
            var source = Path.Join(workspace.Path, "source");
            var destination = Path.Join(workspace.Path, "destination");
            Directory.CreateDirectory(source);

            var before = FileSystemIdentity.CaptureDirectory(source);
            Directory.Move(source, destination);

            Assert.Equal(before, FileSystemIdentity.CaptureDirectory(destination));
        }

        [Fact]
        public void CaptureDirectory_DistinguishesReplacementAtSamePath()
        {
            using var workspace = new TestDirectory();
            var path = Path.Join(workspace.Path, "owned");
            var moved = Path.Join(workspace.Path, "moved");
            Directory.CreateDirectory(path);
            var owned = FileSystemIdentity.CaptureDirectory(path);

            Directory.Move(path, moved);
            Directory.CreateDirectory(path);

            Assert.NotEqual(owned, FileSystemIdentity.CaptureDirectory(path));
            Assert.Equal(owned, FileSystemIdentity.CaptureDirectory(moved));
        }

        [Fact]
        public void DeleteOwnedDirectory_PreservesReplacementAndRestoresItsPath()
        {
            using var workspace = new TestDirectory();
            var path = Path.Join(workspace.Path, "owned");
            var moved = Path.Join(workspace.Path, "actual-owned");
            Directory.CreateDirectory(path);
            var owned = FileSystemIdentity.CaptureDirectory(path);
            Directory.Move(path, moved);
            Directory.CreateDirectory(path);
            File.WriteAllText(Path.Join(path, "unrelated.txt"), "preserve");

            Assert.Throws<IOException>(() => DurableFileSystem.DeleteOwnedDirectory(path, owned, recursive: true));

            Assert.Equal("preserve", File.ReadAllText(Path.Join(path, "unrelated.txt")));
            Assert.True(Directory.Exists(moved));
            Assert.Empty(Directory.EnumerateDirectories(workspace.Path, "*.cdl-delete-*"));
        }

        private sealed class TestDirectory : IDisposable
        {
            internal TestDirectory()
            {
                Path = System.IO.Path.Join(System.IO.Path.GetTempPath(), $"cdl-identity-{Guid.NewGuid():N}");
                Directory.CreateDirectory(Path);
            }

            internal string Path { get; }

            public void Dispose()
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }
            }
        }
    }
}

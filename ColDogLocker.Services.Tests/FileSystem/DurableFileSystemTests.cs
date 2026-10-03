using ColDogStudios.ColDogLocker.Services.FileSystem;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public sealed class DurableFileSystemTests : IDisposable
    {
        private readonly string _root = Path.Join(Path.GetTempPath(), $"cdl-durability-{Guid.NewGuid():N}");

        public DurableFileSystemTests() => Directory.CreateDirectory(_root);

        [Fact]
        public void MoveAndDeleteDirectory_PreserveExpectedNamespaceState()
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "source")).FullName;
            File.WriteAllText(Path.Join(source, "value.txt"), "preserved");
            DurableFileSystem.FlushDirectoryTree(source);
            var destination = Path.Join(_root, "destination");

            DurableFileSystem.MoveDirectory(source, destination);

            Assert.False(Directory.Exists(source));
            Assert.Equal("preserved", File.ReadAllText(Path.Join(destination, "value.txt")));

            DurableFileSystem.DeleteDirectory(destination, recursive: true);
            Assert.False(Directory.Exists(destination));
        }

        [Fact]
        public void MoveAndDeleteFile_PreserveExpectedNamespaceState()
        {
            var source = Path.Join(_root, "source.txt");
            var destination = Path.Join(_root, "destination.txt");
            File.WriteAllText(source, "preserved");

            DurableFileSystem.MoveFile(source, destination);

            Assert.False(File.Exists(source));
            Assert.Equal("preserved", File.ReadAllText(destination));

            DurableFileSystem.DeleteFile(destination);
            Assert.False(File.Exists(destination));
        }

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }
}

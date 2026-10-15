using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public sealed class DirectoryContentScannerTests : IDisposable
    {
        private readonly string _root = Directory.CreateDirectory(Path.Join(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), $"cdl-count-{Guid.NewGuid():N}")).FullName;

        [Fact]
        public void CountsEveryEntryOnceAndExcludesRoot()
        {
            Assert.Equal((0, 0), DirectoryContentScanner.Count(_root));
            var child = Directory.CreateDirectory(Path.Join(_root, "child")).FullName;
            Directory.CreateDirectory(Path.Join(_root, "empty"));
            File.WriteAllText(Path.Join(_root, "one"), "one");
            File.WriteAllText(Path.Join(child, "two"), "two");
            Assert.Equal((2, 2), DirectoryContentScanner.Count(_root));
            Assert.Equal((2, 2), DirectoryContentScanner.Count(_root, 4, 1, TimeSpan.FromSeconds(5)));
        }

        [Fact]
        public void EntryLimitDoesNotReturnPartialCounts()
        {
            File.WriteAllText(Path.Join(_root, "one"), "one");
            File.WriteAllText(Path.Join(_root, "two"), "two");
            Assert.Throws<IOException>(() => DirectoryContentScanner.Count(_root, 1, 5, TimeSpan.FromSeconds(5)));
        }

        [Fact]
        public void DepthLimitIncludesEmptyDescendants()
        {
            Directory.CreateDirectory(Path.Join(_root, "child", "deeper"));
            Assert.Throws<IOException>(() => DirectoryContentScanner.Count(_root, 10, 1, TimeSpan.FromSeconds(5)));
        }

        [Fact]
        public void ExpiredBudgetRefusesEvenAnEmptyTree()
        {
            Assert.Throws<IOException>(() => DirectoryContentScanner.Count(_root, 10, 1, TimeSpan.Zero));
        }

        [Fact]
        public void MissingDirectoryIsNotReportedAsEmpty()
        {
            Assert.Throws<InvalidDataException>(() => DirectoryContentScanner.Count(Path.Join(_root, "missing")));
        }

        [UnixTheory]
        [InlineData("root")]
        [InlineData("ancestor")]
        [InlineData("cycle")]
        public void LinksAreRefusedAndVerificationDoesNotPublishCounts(string kind)
        {
            var source = Directory.CreateDirectory(Path.Join(_root, "Vault")).FullName;
            File.WriteAllText(Path.Join(source, "preserved"), "unchanged");
            var alias = Path.Join(_root, "alias");
            var path = source;
            if (kind == "root")
            {
                Directory.CreateSymbolicLink(alias, source);
                path = alias;
            }
            else if (kind == "ancestor")
            {
                Directory.CreateSymbolicLink(alias, _root);
                path = Path.Join(alias, "Vault");
            }
            else
            {
                Directory.CreateSymbolicLink(Path.Join(source, "cycle"), source);
            }

            try
            {
                var error = Record.Exception(() => DirectoryContentScanner.Count(path));
                Assert.True(error is IOException or InvalidDataException);
                var result = LockerService.Verify(new LockerModel("Vault", "unused", path));
                Assert.False(result.IsValid);
                Assert.False(result.CountsComplete);
                Assert.NotEmpty(result.Errors);
                Assert.Equal("unchanged", File.ReadAllText(Path.Join(source, "preserved")));
            }
            finally
            {
                Directory.Delete(kind == "cycle" ? Path.Join(source, "cycle") : alias);
            }
        }

        public void Dispose() => Directory.Delete(_root, true);
    }
}

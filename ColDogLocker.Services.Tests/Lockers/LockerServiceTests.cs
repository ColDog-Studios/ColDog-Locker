/*
**  Copyright (C) 2026 ColDog Studios
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  long with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public class LockerServiceTests
    {
        [Fact]
        public void Verify_NullLocker_ShouldThrowArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => LockerService.Verify(null!));
        }

        [Fact]
        public void AddLocker_WithInvalidName_ShouldThrowArgumentException()
        {
            var locker = new LockerModel("bad/name", "hash", Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));

            var exception = Assert.Throws<ArgumentException>(() => LockerService.AddLocker(locker));

            Assert.Contains("Locker name must be a valid file name", exception.Message);
        }

        [Fact]
        public void AddLocker_WithProtectedPath_ShouldThrowUnauthorizedAccessException()
        {
            var locker = new LockerModel(
                "Protected",
                "hash",
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

            Assert.Throws<UnauthorizedAccessException>(() => LockerService.AddLocker(locker));
        }

        [Fact]
        public void DeleteLockerDirectory_WithMismatchedDirectoryName_ShouldThrowUnauthorizedAccessException()
        {
            using var directory = TestDirectory.CreateAllowed("ActualDirectory");
            var locker = new LockerModel("MetadataName", "hash", directory.Path);

            Assert.Throws<UnauthorizedAccessException>(() => LockerService.DeleteLockerDirectory(locker));
            Assert.True(Directory.Exists(directory.Path));
        }

        [Fact]
        public void Verify_MissingDirectory_ShouldReturnInvalidResult()
        {
            var locker = new LockerModel("Missing", "hash", Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));

            var result = LockerService.Verify(locker);

            Assert.Equal("Missing", result.LockerName);
            Assert.Equal(locker.Guid, result.Guid);
            Assert.False(result.DirectoryExists);
            Assert.False(result.HasAccess);
            Assert.False(result.IsValid);
            Assert.Contains("Directory does not exist at specified location", result.Errors);
        }

        [Fact]
        public void Verify_UnlockedDirectory_ShouldCountFilesAndDirectories()
        {
            using var directory = TestDirectory.Create("Unlocked");
            File.WriteAllText(Path.Join(directory.Path, "file.txt"), "content");
            var childDirectory = Directory.CreateDirectory(Path.Combine(directory.Path, "child"));
            File.WriteAllText(Path.Join(childDirectory.FullName, "nested.txt"), "content");
            var locker = new LockerModel("Unlocked", "hash", directory.Path);

            var result = LockerService.Verify(locker);

            Assert.True(result.DirectoryExists);
            Assert.True(result.HasAccess);
            Assert.True(result.IsValid);
            Assert.Equal(2, result.FileCount);
            Assert.Equal(1, result.DirectoryCount);
            Assert.Empty(result.Errors);
            Assert.Empty(result.Warnings);
        }

        [Fact]
        public void Verify_UnlockedDirectoryWithHiddenName_ShouldAddWarning()
        {
            using var directory = TestDirectory.Create(".Unlocked");
            var locker = new LockerModel("Unlocked", "hash", directory.Path);

            var result = LockerService.Verify(locker);

            Assert.True(result.IsValid);
            Assert.Contains(result.Warnings, warning => warning.Contains("Unlocked locker directory name should not start"));
        }

        [Fact]
        public void Verify_LockedDirectoryWithoutHiddenName_ShouldAddWarning()
        {
            using var directory = TestDirectory.Create("Locked");
            var locker = new LockerModel("Locked", "hash", directory.Path) { IsLocked = true };

            var result = LockerService.Verify(locker);

            Assert.True(result.IsValid);
            Assert.Contains(result.Warnings, warning => warning.Contains("Locked locker directory name should start"));
        }

        [Fact]
        public void LockerVerificationResult_IsValid_ShouldRequireNoErrorsDirectoryAndAccess()
        {
            var result = new LockerVerificationResult
            {
                DirectoryExists = true,
                HasAccess = true
            };

            Assert.True(result.IsValid);

            result.AddWarning("warning");
            Assert.True(result.IsValid);

            result.AddError("error");
            Assert.False(result.IsValid);
        }

        private sealed class TestDirectory : IDisposable
        {
            private TestDirectory(string path)
            {
                Path = path;
            }

            public string Path { get; }

            public static TestDirectory Create(string name)
            {
                var parent = System.IO.Path.Join(System.IO.Path.GetTempPath(), $"cdlocker-tests-{Guid.NewGuid():N}");
                var path = System.IO.Path.Combine(parent, name);
                Directory.CreateDirectory(path);
                return new TestDirectory(path);
            }

            public static TestDirectory CreateAllowed(string name)
            {
                var parent = System.IO.Path.Combine(
                    System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile),
                    $"cdlocker-tests-{Guid.NewGuid():N}");
                var path = System.IO.Path.Combine(parent, name);
                Directory.CreateDirectory(path);
                return new TestDirectory(path);
            }

            public void Dispose()
            {
                var parent = System.IO.Directory.GetParent(Path)?.FullName;
                if (parent != null && System.IO.Directory.Exists(parent))
                {
                    System.IO.Directory.Delete(parent, recursive: true);
                }
            }
        }
    }
}

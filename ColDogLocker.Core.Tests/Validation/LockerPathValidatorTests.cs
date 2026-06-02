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

using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Core.Validation;

namespace ColDogStudios.ColDogLocker.Core.Tests.Validation
{
    public sealed class WindowsOnlyFactAttribute : FactAttribute
    {
        public WindowsOnlyFactAttribute()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Skip = "Windows only test";
            }
        }
    }

    public class LockerPathValidatorTests
    {
        [Fact]
        public void ValidatePath_WithAllowedPath_ShouldReturnNull()
        {
            // Arrange - A safe subdirectory under Documents is now allowed
            var safePath = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.MyDocuments), "ColDog Locker", "TestLocker");

            // Act
            var result = LockerPathValidator.ValidatePath(safePath);

            // Assert - Should be allowed now (subdirectories of Documents are OK)
            Assert.Null(result);
        }

        [WindowsOnlyFact]
        public void ValidatePath_WithDriveRoot_ShouldReturnError()
        {
            // Arrange
            var drivePath = "C:\\";

            // Act
            var result = LockerPathValidator.ValidatePath(drivePath);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("Cannot lock an entire drive", result);
        }

        [WindowsOnlyFact]
        public void ValidatePath_WithWindowsDirectory_ShouldReturnError()
        {
            // Arrange
            var windowsPath = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows);

            // Act
            var result = LockerPathValidator.ValidatePath(windowsPath);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("protected", result, StringComparison.OrdinalIgnoreCase);
        }

        [WindowsOnlyFact]
        public void ValidatePath_WithProgramFiles_ShouldReturnError()
        {
            // Arrange
            var programFilesPath = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFiles);

            // Act
            var result = LockerPathValidator.ValidatePath(programFilesPath);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("protected", result, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void ValidatePath_WithUserProfile_ShouldReturnError()
        {
            // Arrange
            var userProfilePath = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

            // Act
            var result = LockerPathValidator.ValidatePath(userProfilePath);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("protected", result, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void ValidatePath_WithDocuments_ShouldReturnError()
        {
            // Arrange - Exact Documents folder
            var documentsPath = System.Environment.GetFolderPath(System.Environment.SpecialFolder.MyDocuments);

            // Act
            var result = LockerPathValidator.ValidatePath(documentsPath);

            // Assert - Should block (Documents is under %USERPROFILE%)
            Assert.NotNull(result);
        }

        [Fact]
        public void ValidatePath_WithDesktop_ShouldReturnError()
        {
            // Arrange - Exact Desktop folder
            var desktopPath = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop);

            // Act
            var result = LockerPathValidator.ValidatePath(desktopPath);

            // Assert - Should block (Desktop is under %USERPROFILE%)
            Assert.NotNull(result);
        }

        [Fact]
        public void ValidatePath_WithAppData_ShouldReturnError()
        {
            // Arrange - Exact AppData root folder
            var appDataPath = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile), "AppData");

            // Act
            var result = LockerPathValidator.ValidatePath(appDataPath);

            // Assert - Should block the exact AppData folder
            Assert.NotNull(result);
            Assert.Contains("protected", result, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void ValidatePath_WithAppDataSubdirectory_ShouldReturnNull()
        {
            // Arrange - Subdirectory under AppData (like C:\Users\ColDog\AppData\MyHiddenLocker)
            var appDataSubPath = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile), "AppData", "MyHiddenLocker");

            // Act
            var result = LockerPathValidator.ValidatePath(appDataSubPath);

            // Assert - Should be allowed (not under Roaming/Local)
            Assert.Null(result);
        }

        [Fact]
        public void ValidatePath_WithAppDataRoaming_ShouldReturnError()
        {
            // Arrange - AppData\Roaming (system path, blocks subdirectories)
            var appDataRoaming = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData);

            // Act
            var result = LockerPathValidator.ValidatePath(appDataRoaming);

            // Assert - Should block
            Assert.NotNull(result);
        }

        [Fact]
        public void ValidatePath_WithUserProfileSubdirectory_ShouldReturnNull()
        {
            // Arrange - Subdirectory under user profile (like C:\Users\ColDog\MyLocker)
            var userProfileSub = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile), "MyLocker");

            // Act
            var result = LockerPathValidator.ValidatePath(userProfileSub);

            // Assert - Should be allowed
            Assert.Null(result);
        }

        [WindowsOnlyFact]
        public void ValidatePath_WithSubdirectoryOfProtectedPath_ShouldReturnError()
        {
            // Arrange - Try to lock a subdirectory of Windows
            var windowsSubPath = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows), "System32");

            // Act
            var result = LockerPathValidator.ValidatePath(windowsSubPath);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("Cannot lock directories under", result);
        }

        [Fact]
        public void ValidatePath_WithEmptyPath_ShouldReturnError()
        {
            // Act
            var result = LockerPathValidator.ValidatePath(string.Empty);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("Path cannot be empty", result);
        }

        [Fact]
        public void ValidatePath_WithNullPath_ShouldReturnError()
        {
            // Act
            var result = LockerPathValidator.ValidatePath(null!);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("Path cannot be empty", result);
        }

        [WindowsOnlyFact]
        public void GetProtectedPaths_ShouldReturnNonEmptyList()
        {
            // Act
            var protectedPaths = LockerPathValidator.GetProtectedPaths();

            // Assert
            Assert.NotNull(protectedPaths);
            Assert.NotEmpty(protectedPaths);
            Assert.Contains(protectedPaths, p => p.Contains("Windows", StringComparison.OrdinalIgnoreCase));
        }
    }
}

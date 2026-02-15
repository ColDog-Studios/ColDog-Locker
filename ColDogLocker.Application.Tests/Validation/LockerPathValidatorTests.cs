using ColDogStudios.ColDogLocker.Application.Validation;

namespace ColDogStudios.ColDogLocker.Application.Tests.Validation
{
    public class LockerPathValidatorTests
    {
        [Fact]
        public void ValidatePath_WithAllowedPath_ShouldReturnNull()
        {
            // Arrange - A safe subdirectory under Documents is now allowed
            var safePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ColDog Locker", "TestLocker");

            // Act
            var result = LockerPathValidator.ValidatePath(safePath);

            // Assert - Should be allowed now (subdirectories of Documents are OK)
            Assert.Null(result);
        }

        [Fact]
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

        [Fact]
        public void ValidatePath_WithWindowsDirectory_ShouldReturnError()
        {
            // Arrange
            var windowsPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            // Act
            var result = LockerPathValidator.ValidatePath(windowsPath);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("protected", result, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void ValidatePath_WithProgramFiles_ShouldReturnError()
        {
            // Arrange
            var programFilesPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

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
            var userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

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
            var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            // Act
            var result = LockerPathValidator.ValidatePath(documentsPath);

            // Assert - Should block (Documents is under %USERPROFILE%)
            Assert.NotNull(result);
        }

        [Fact]
        public void ValidatePath_WithDesktop_ShouldReturnError()
        {
            // Arrange - Exact Desktop folder
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            // Act
            var result = LockerPathValidator.ValidatePath(desktopPath);

            // Assert - Should block (Desktop is under %USERPROFILE%)
            Assert.NotNull(result);
        }

        [Fact]
        public void ValidatePath_WithAppData_ShouldReturnError()
        {
            // Arrange - Exact AppData root folder
            var appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData");

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
            var appDataSubPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "MyHiddenLocker");

            // Act
            var result = LockerPathValidator.ValidatePath(appDataSubPath);

            // Assert - Should be allowed (not under Roaming/Local)
            Assert.Null(result);
        }

        [Fact]
        public void ValidatePath_WithAppDataRoaming_ShouldReturnError()
        {
            // Arrange - AppData\Roaming (system path, blocks subdirectories)
            var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Act
            var result = LockerPathValidator.ValidatePath(appDataRoaming);

            // Assert - Should block
            Assert.NotNull(result);
        }

        [Fact]
        public void ValidatePath_WithUserProfileSubdirectory_ShouldReturnNull()
        {
            // Arrange - Subdirectory under user profile (like C:\Users\ColDog\MyLocker)
            var userProfileSub = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "MyLocker");

            // Act
            var result = LockerPathValidator.ValidatePath(userProfileSub);

            // Assert - Should be allowed
            Assert.Null(result);
        }

        [Fact]
        public void ValidatePath_WithSubdirectoryOfProtectedPath_ShouldReturnError()
        {
            // Arrange - Try to lock a subdirectory of Windows
            var windowsSubPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");

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

        [Fact]
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

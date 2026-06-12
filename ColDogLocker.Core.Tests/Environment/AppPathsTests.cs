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

using ColDogStudios.ColDogLocker.Core.Environment;

namespace ColDogStudios.ColDogLocker.Core.Tests.Environment
{
    public class AppPathsTests
    {
        [Fact]
        public void LocalConfig_ShouldNotBeNull()
        {
            // Act
            var localConfig = AppPaths.LocalConfig;

            // Assert
            Assert.NotNull(localConfig);
            Assert.NotEmpty(localConfig);
        }

        [Fact]
        public void LocalConfig_ShouldContainExpectedPathComponents()
        {
            // Act
            var localConfig = AppPaths.LocalConfig;

            // Assert
            Assert.Contains("ColDog Studios", localConfig);
            Assert.Contains("ColDog Locker", localConfig);
        }

        [Fact]
        public void LocalConfig_ShouldBeInLocalApplicationData()
        {
            // Arrange
            var expectedBasePath = GetExpectedSpecialFolderBase(
                System.Environment.SpecialFolder.LocalApplicationData,
                System.Environment.SpecialFolder.UserProfile);

            // Act
            var localConfig = AppPaths.LocalConfig;

            // Assert
            Assert.StartsWith(expectedBasePath, localConfig);
        }

        [Fact]
        public void CdlDir_ShouldNotBeNull()
        {
            // Act
            var cdlDir = AppPaths.CdlDir;

            // Assert
            Assert.NotNull(cdlDir);
            Assert.NotEmpty(cdlDir);
        }

        [Fact]
        public void CdlDir_ShouldContainColDogLocker()
        {
            // Act
            var cdlDir = AppPaths.CdlDir;

            // Assert
            Assert.Contains("ColDog Locker", cdlDir);
        }

        [Fact]
        public void CdlDir_ShouldBeInMyDocumentsOrUserProfileFallback()
        {
            // Arrange
            var expectedBasePath = GetExpectedSpecialFolderBase(
                System.Environment.SpecialFolder.MyDocuments,
                System.Environment.SpecialFolder.UserProfile);

            // Act
            var cdlDir = AppPaths.CdlDir;

            // Assert
            Assert.StartsWith(expectedBasePath, cdlDir);
        }

        [Fact]
        public void LocalConfig_AndCdlDir_ShouldBeDifferent()
        {
            // Act
            var localConfig = AppPaths.LocalConfig;
            var cdlDir = AppPaths.CdlDir;

            // Assert
            Assert.NotEqual(localConfig, cdlDir);
        }

        [Fact]
        public void AllPaths_ShouldBeAbsolutePaths()
        {
            // Act & Assert
            Assert.True(Path.IsPathRooted(AppPaths.LocalConfig), "localConfig should be an absolute path");
            Assert.True(Path.IsPathRooted(AppPaths.CdlDir), "cdlDir should be an absolute path");
        }

        [Fact]
        public void AllPaths_ShouldBeConsistentAcrossMultipleAccesses()
        {
            // Act - Access the properties multiple times
            var localConfig1 = AppPaths.LocalConfig;
            var localConfig2 = AppPaths.LocalConfig;
            var cdlDir1 = AppPaths.CdlDir;
            var cdlDir2 = AppPaths.CdlDir;

            // Assert - Should return the same values
            Assert.Equal(localConfig1, localConfig2);
            Assert.Equal(cdlDir1, cdlDir2);
            Assert.Equal(cdlDir1, cdlDir2);
        }

        [Fact]
        public void LocalConfig_ShouldEndWithCorrectFolderStructure()
        {
            // Act
            var localConfig = AppPaths.LocalConfig;

            // Assert
            Assert.EndsWith(Path.Combine("ColDog Studios", "ColDog Locker"), localConfig);
        }

        [Fact]
        public void CdlDir_ShouldEndWithColDogLocker()
        {
            // Act
            var cdlDir = AppPaths.CdlDir;

            // Assert
            Assert.EndsWith("ColDog Locker", cdlDir);
        }

        private static string GetExpectedSpecialFolderBase(
            System.Environment.SpecialFolder preferredFolder,
            System.Environment.SpecialFolder fallbackFolder)
        {
            var path = System.Environment.GetFolderPath(preferredFolder);
            if (!string.IsNullOrWhiteSpace(path) && Path.IsPathRooted(path))
            {
                return path;
            }

            path = System.Environment.GetFolderPath(fallbackFolder);
            if (!string.IsNullOrWhiteSpace(path) && Path.IsPathRooted(path))
            {
                return path;
            }

            return Path.GetFullPath(".");
        }
    }
}

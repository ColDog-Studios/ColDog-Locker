using ColDogStudios.ColDogLocker.Core.Constants;

namespace ColDogStudios.ColDogLocker.Core.Tests.Constants
{
    public class VariablesTests
    {
        [Fact]
        public void LocalConfig_ShouldNotBeNull()
        {
            // Act
            var localConfig = Variables.LocalConfig;

            // Assert
            Assert.NotNull(localConfig);
            Assert.NotEmpty(localConfig);
        }

        [Fact]
        public void LocalConfig_ShouldContainExpectedPathComponents()
        {
            // Act
            var localConfig = Variables.LocalConfig;

            // Assert
            Assert.Contains("ColDog Studios", localConfig);
            Assert.Contains("ColDog Locker", localConfig);
        }

        [Fact]
        public void LocalConfig_ShouldBeInLocalApplicationData()
        {
            // Arrange
            var expectedBasePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            // Act
            var localConfig = Variables.LocalConfig;

            // Assert
            Assert.StartsWith(expectedBasePath, localConfig);
        }

        [Fact]
        public void CdlDir_ShouldNotBeNull()
        {
            // Act
            var cdlDir = Variables.CdlDir;

            // Assert
            Assert.NotNull(cdlDir);
            Assert.NotEmpty(cdlDir);
        }

        [Fact]
        public void CdlDir_ShouldContainColDogLocker()
        {
            // Act
            var cdlDir = Variables.CdlDir;

            // Assert
            Assert.Contains("ColDog Locker", cdlDir);
        }

        [Fact]
        public void CdlDir_ShouldBeInMyDocuments()
        {
            // Arrange
            var expectedBasePath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            // Act
            var cdlDir = Variables.CdlDir;

            // Assert
            Assert.StartsWith(expectedBasePath, cdlDir);
        }

        [Fact]
        public void LocalConfig_AndCdlDir_ShouldBeDifferent()
        {
            // Act
            var localConfig = Variables.LocalConfig;
            var cdlDir = Variables.CdlDir;

            // Assert
            Assert.NotEqual(localConfig, cdlDir);
        }

        [Fact]
        public void AllPaths_ShouldBeAbsolutePaths()
        {
            // Act & Assert
            Assert.True(Path.IsPathRooted(Variables.LocalConfig), "localConfig should be an absolute path");
            Assert.True(Path.IsPathRooted(Variables.CdlDir), "cdlDir should be an absolute path");
        }

        [Fact]
        public void AllPaths_ShouldBeConsistentAcrossMultipleAccesses()
        {
            // Act - Access the properties multiple times
            var localConfig1 = Variables.LocalConfig;
            var localConfig2 = Variables.LocalConfig;
            var cdlDir1 = Variables.CdlDir;
            var cdlDir2 = Variables.CdlDir;

            // Assert - Should return the same values
            Assert.Equal(localConfig1, localConfig2);
            Assert.Equal(cdlDir1, cdlDir2);
            Assert.Equal(cdlDir1, cdlDir2);
        }

        [Fact]
        public void LocalConfig_ShouldEndWithCorrectFolderStructure()
        {
            // Act
            var localConfig = Variables.LocalConfig;

            // Assert
            Assert.EndsWith(Path.Combine("ColDog Studios", "ColDog Locker"), localConfig);
        }

        [Fact]
        public void CdlDir_ShouldEndWithColDogLocker()
        {
            // Act
            var cdlDir = Variables.CdlDir;

            // Assert
            Assert.EndsWith("ColDog Locker", cdlDir);
        }
    }
}

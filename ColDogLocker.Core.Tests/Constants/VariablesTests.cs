using ColDogStudios.ColDogLocker.Core.Constants;

namespace ColDogStudios.ColDogLocker.Core.Tests.Constants
{
    public class VariablesTests
    {
        [Fact]
        public void LocalConfig_ShouldNotBeNull()
        {
            // Act
            var localConfig = Variables.localConfig;

            // Assert
            Assert.NotNull(localConfig);
            Assert.NotEmpty(localConfig);
        }

        [Fact]
        public void LocalConfig_ShouldContainExpectedPathComponents()
        {
            // Act
            var localConfig = Variables.localConfig;

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
            var localConfig = Variables.localConfig;

            // Assert
            Assert.StartsWith(expectedBasePath, localConfig);
        }

        [Fact]
        public void RoamingConfig_ShouldNotBeNull()
        {
            // Act
            var roamingConfig = Variables.roamingConfig;

            // Assert
            Assert.NotNull(roamingConfig);
            Assert.NotEmpty(roamingConfig);
        }

        [Fact]
        public void RoamingConfig_ShouldContainExpectedPathComponents()
        {
            // Act
            var roamingConfig = Variables.roamingConfig;

            // Assert
            Assert.Contains("ColDog Studios", roamingConfig);
            Assert.Contains("ColDog Locker", roamingConfig);
        }

        [Fact]
        public void RoamingConfig_ShouldBeInApplicationData()
        {
            // Arrange
            var expectedBasePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Act
            var roamingConfig = Variables.roamingConfig;

            // Assert
            Assert.StartsWith(expectedBasePath, roamingConfig);
        }

        [Fact]
        public void CdlDir_ShouldNotBeNull()
        {
            // Act
            var cdlDir = Variables.cdlDir;

            // Assert
            Assert.NotNull(cdlDir);
            Assert.NotEmpty(cdlDir);
        }

        [Fact]
        public void CdlDir_ShouldContainColDogLocker()
        {
            // Act
            var cdlDir = Variables.cdlDir;

            // Assert
            Assert.Contains("ColDog Locker", cdlDir);
        }

        [Fact]
        public void CdlDir_ShouldBeInMyDocuments()
        {
            // Arrange
            var expectedBasePath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            // Act
            var cdlDir = Variables.cdlDir;

            // Assert
            Assert.StartsWith(expectedBasePath, cdlDir);
        }

        [Fact]
        public void LocalConfig_AndRoamingConfig_ShouldBeDifferent()
        {
            // Act
            var localConfig = Variables.localConfig;
            var roamingConfig = Variables.roamingConfig;

            // Assert
            Assert.NotEqual(localConfig, roamingConfig);
        }

        [Fact]
        public void LocalConfig_AndCdlDir_ShouldBeDifferent()
        {
            // Act
            var localConfig = Variables.localConfig;
            var cdlDir = Variables.cdlDir;

            // Assert
            Assert.NotEqual(localConfig, cdlDir);
        }

        [Fact]
        public void AllPaths_ShouldBeAbsolutePaths()
        {
            // Act & Assert
            Assert.True(Path.IsPathRooted(Variables.localConfig), "localConfig should be an absolute path");
            Assert.True(Path.IsPathRooted(Variables.roamingConfig), "roamingConfig should be an absolute path");
            Assert.True(Path.IsPathRooted(Variables.cdlDir), "cdlDir should be an absolute path");
        }

        [Fact]
        public void AllPaths_ShouldBeConsistentAcrossMultipleAccesses()
        {
            // Act - Access the properties multiple times
            var localConfig1 = Variables.localConfig;
            var localConfig2 = Variables.localConfig;
            var roamingConfig1 = Variables.roamingConfig;
            var roamingConfig2 = Variables.roamingConfig;
            var cdlDir1 = Variables.cdlDir;
            var cdlDir2 = Variables.cdlDir;

            // Assert - Should return the same values
            Assert.Equal(localConfig1, localConfig2);
            Assert.Equal(roamingConfig1, roamingConfig2);
            Assert.Equal(cdlDir1, cdlDir2);
        }

        [Fact]
        public void LocalConfig_ShouldEndWithCorrectFolderStructure()
        {
            // Act
            var localConfig = Variables.localConfig;

            // Assert
            Assert.EndsWith(Path.Combine("ColDog Studios", "ColDog Locker"), localConfig);
        }

        [Fact]
        public void RoamingConfig_ShouldEndWithCorrectFolderStructure()
        {
            // Act
            var roamingConfig = Variables.roamingConfig;

            // Assert
            Assert.EndsWith(Path.Combine("ColDog Studios", "ColDog Locker"), roamingConfig);
        }

        [Fact]
        public void CdlDir_ShouldEndWithColDogLocker()
        {
            // Act
            var cdlDir = Variables.cdlDir;

            // Assert
            Assert.EndsWith("ColDog Locker", cdlDir);
        }
    }
}

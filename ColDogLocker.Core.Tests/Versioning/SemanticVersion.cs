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

using ColDogStudios.ColDogLocker.Core.Versioning;

namespace ColDogStudios.ColDogLocker.Core.Tests.Versioning
{
    public class SemanticVersionTests
    {
        #region Constructor Tests - Valid Versions

        [Theory]
        [InlineData("0.1.2-alpha", 0, 1, 2, "alpha")]
        [InlineData("0.3.4-beta", 0, 3, 4, "beta")]
        [InlineData("1.0.0-rc.2", 1, 0, 0, "rc.2")]
        [InlineData("2.56.789", 2, 56, 789, null)]
        [InlineData("1.2.3-beta.1", 1, 2, 3, "beta.1")]
        [InlineData("10.20.30-alpha.1.2", 10, 20, 30, "alpha.1.2")]
        public void Constructor_WithValidVersion_ShouldParseCorrectly(
            string versionString, int expectedMajor, int expectedMinor, int expectedPatch, string? expectedPreRelease)
        {
            // Act
            var version = new SemanticVersion(versionString);

            // Assert
            Assert.Equal(expectedMajor, version.Major);
            Assert.Equal(expectedMinor, version.Minor);
            Assert.Equal(expectedPatch, version.Patch);
            Assert.Equal(expectedPreRelease, version.PreRelease);
        }

        #endregion

        #region Constructor Tests - Invalid Input

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void Constructor_WithNullOrWhitespace_ShouldThrowFormatException(string? invalidVersion)
        {
            // Act & Assert
            Assert.Throws<FormatException>(() => new SemanticVersion(invalidVersion!));
        }

        [Theory]
        [InlineData("invalid.version")]
        [InlineData("1.2")]
        [InlineData("1.2.3.4")]
        [InlineData("a.b.c")]
        [InlineData("1.2.3-")]
        [InlineData("1.2.-1")]
        [InlineData("-1.2.3")]
        public void Constructor_WithInvalidFormat_ShouldThrowFormatException(string? invalidVersion)
        {
            // Act & Assert
            Assert.Throws<FormatException>(() => new SemanticVersion(invalidVersion!));
        }

        [Theory]
        [InlineData("1.0.0-01")]
        [InlineData("1.0.0-alpha.01")]
        [InlineData("1.0.0-01.beta")]
        public void Constructor_WithLeadingZerosInPreRelease_ShouldThrowFormatException(string invalidVersion)
        {
            // Act & Assert
            Assert.Throws<FormatException>(() => new SemanticVersion(invalidVersion));
        }

        #endregion

        #region TryParse Tests - Valid Versions

        [Theory]
        [InlineData("0.1.2-alpha")]
        [InlineData("1.0.0-rc.2")]
        [InlineData("2.56.789")]
        [InlineData("1.2.3-beta.1")]
        public void TryParse_WithValidVersion_ShouldReturnTrueAndParsedVersion(string versionString)
        {
            // Act
            var result = SemanticVersion.TryParse(versionString, out var version);

            // Assert
            Assert.True(result);
            Assert.NotNull(version);
        }

        #endregion

        #region TryParse Tests - Invalid Input

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void TryParse_WithNullOrWhitespace_ShouldReturnFalseAndNull(string? invalidVersion)
        {
            // Act
            var result = SemanticVersion.TryParse(invalidVersion!, out var version);

            // Assert
            Assert.False(result);
            Assert.Null(version);
        }

        [Theory]
        [InlineData("invalid.version")]
        [InlineData("1.2")]
        [InlineData("1.2.3.4")]
        [InlineData("a.b.c")]
        [InlineData("1.2.3-")]
        [InlineData("1.2.-1")]
        [InlineData("-1.2.3")]
        public void TryParse_WithInvalidFormat_ShouldReturnFalseAndNull(string invalidVersion)
        {
            // Act
            var result = SemanticVersion.TryParse(invalidVersion, out var version);

            // Assert
            Assert.False(result);
            Assert.Null(version);
        }

        [Theory]
        [InlineData("1.0.0-01")]
        [InlineData("1.0.0-alpha.01")]
        [InlineData("1.0.0-01.beta")]
        public void TryParse_WithLeadingZerosInPreRelease_ShouldReturnFalseAndNull(string invalidVersion)
        {
            // Act
            var result = SemanticVersion.TryParse(invalidVersion, out var version);

            // Assert
            Assert.False(result);
            Assert.Null(version);
        }

        #endregion

        #region Comparison Tests

        [Theory]
        [InlineData("2.0.0", "1.0.0", 1)]
        [InlineData("1.2.0", "1.1.0", 1)]
        [InlineData("1.0.2", "1.0.1", 1)]
        [InlineData("1.0.0", "2.0.0", -1)]
        [InlineData("1.0.0", "1.0.0", 0)]
        public void CompareTo_WithDifferentVersions_ShouldCompareCorrectly(
            string versionA, string versionB, int expectedSign)
        {
            // Arrange
            var version1 = new SemanticVersion(versionA);
            var version2 = new SemanticVersion(versionB);

            // Act
            var result = version1.CompareTo(version2);

            // Assert
            Assert.Equal(expectedSign, Math.Sign(result));
        }

        [Theory]
        [InlineData("1.0.0", "1.0.0-alpha", 1)]
        [InlineData("1.0.0-alpha", "1.0.0", -1)]
        [InlineData("1.0.0-alpha", "1.0.0-beta", -1)]
        [InlineData("1.0.0-beta", "1.0.0-alpha", 1)]
        [InlineData("1.0.0-1", "1.0.0-2", -1)]
        [InlineData("1.0.0-alpha.1", "1.0.0-alpha.2", -1)]
        public void CompareTo_WithPreReleaseVersions_ShouldHandleCorrectly(
            string versionA, string versionB, int expectedSign)
        {
            // Arrange
            var version1 = new SemanticVersion(versionA);
            var version2 = new SemanticVersion(versionB);

            // Act
            var result = version1.CompareTo(version2);

            // Assert
            Assert.Equal(expectedSign, Math.Sign(result));
        }

        [Fact]
        public void CompareTo_WithNull_ShouldReturnPositive()
        {
            // Arrange
            var version = new SemanticVersion("1.0.0");

            // Act
            var result = version.CompareTo(null);

            // Assert
            Assert.True(result > 0);
        }

        #endregion

        #region Equality Tests

        [Theory]
        [InlineData("1.0.0", "1.0.0")]
        [InlineData("1.2.3-alpha", "1.2.3-alpha")]
        public void Equals_WithSameVersions_ShouldReturnTrue(string versionA, string versionB)
        {
            // Arrange
            var version1 = new SemanticVersion(versionA);
            var version2 = new SemanticVersion(versionB);

            // Act & Assert
            Assert.True(version1.Equals(version2));
            Assert.True(version1 == version2);
            Assert.False(version1 != version2);
        }

        [Theory]
        [InlineData("1.0.0", "1.0.1")]
        [InlineData("1.0.0", "1.0.0-alpha")]
        [InlineData("1.0.0-alpha", "1.0.0-beta")]
        public void Equals_WithDifferentVersions_ShouldReturnFalse(string versionA, string versionB)
        {
            // Arrange
            var version1 = new SemanticVersion(versionA);
            var version2 = new SemanticVersion(versionB);

            // Act & Assert
            Assert.False(version1.Equals(version2));
            Assert.False(version1 == version2);
            Assert.True(version1 != version2);
        }

        [Fact]
        public void Equals_WithNull_ShouldReturnFalse()
        {
            // Arrange
            var version = new SemanticVersion("1.0.0");

            // Act & Assert
            Assert.False(version.Equals(null));
        }

        [Fact]
        public void EqualsOperator_WithBothNull_ShouldReturnTrue()
        {
            // Act & Assert
            SemanticVersion v1 = null!;
            SemanticVersion v2 = null!;
            Assert.True(v1 == v2);
        }

        [Fact]
        public void EqualsOperator_WithOneNull_ShouldReturnFalse()
        {
            // Arrange
            SemanticVersion v1 = new SemanticVersion("1.0.0");
            SemanticVersion v2 = null!;

            // Act & Assert
            Assert.False(v1 == v2);
            Assert.False(v2 == v1);
            Assert.True(v1 != v2);
            Assert.True(v2 != v1);
        }

        [Fact]
        public void GetHashCode_WithSameVersion_ShouldMatch()
        {
            // Arrange
            var version1 = new SemanticVersion("1.0.0-alpha");
            var version2 = new SemanticVersion("1.0.0-alpha");

            // Act & Assert
            Assert.Equal(version1.GetHashCode(), version2.GetHashCode());
        }

        #endregion

        #region Comparison Operator Tests

        [Theory]
        [InlineData("2.0.0", "1.0.0", true)]
        [InlineData("1.0.0", "2.0.0", false)]
        public void GreaterThan_ShouldWorkCorrectly(string versionA, string versionB, bool expected)
        {
            // Arrange
            var version1 = new SemanticVersion(versionA);
            var version2 = new SemanticVersion(versionB);

            // Act & Assert
            Assert.Equal(expected, version1 > version2);
        }

        [Theory]
        [InlineData("1.0.0", "2.0.0", true)]
        [InlineData("2.0.0", "1.0.0", false)]
        public void LessThan_ShouldWorkCorrectly(string versionA, string versionB, bool expected)
        {
            // Arrange
            var version1 = new SemanticVersion(versionA);
            var version2 = new SemanticVersion(versionB);

            // Act & Assert
            Assert.Equal(expected, version1 < version2);
        }

        [Theory]
        [InlineData("2.0.0", "1.0.0", true)]
        [InlineData("1.0.0", "1.0.0", true)]
        [InlineData("1.0.0", "2.0.0", false)]
        public void GreaterThanOrEqual_ShouldWorkCorrectly(string versionA, string versionB, bool expected)
        {
            // Arrange
            var version1 = new SemanticVersion(versionA);
            var version2 = new SemanticVersion(versionB);

            // Act & Assert
            Assert.Equal(expected, version1 >= version2);
        }

        [Theory]
        [InlineData("1.0.0", "2.0.0", true)]
        [InlineData("1.0.0", "1.0.0", true)]
        [InlineData("2.0.0", "1.0.0", false)]
        public void LessThanOrEqual_ShouldWorkCorrectly(string versionA, string versionB, bool expected)
        {
            // Arrange
            var version1 = new SemanticVersion(versionA);
            var version2 = new SemanticVersion(versionB);

            // Act & Assert
            Assert.Equal(expected, version1 <= version2);
        }

        #endregion

        #region ToString Tests

        [Theory]
        [InlineData("1.0.0", "1.0.0")]
        [InlineData("1.2.3-alpha", "1.2.3-alpha")]
        [InlineData("2.56.789", "2.56.789")]
        [InlineData("1.0.0-rc.2", "1.0.0-rc.2")]
        public void ToString_ShouldFormatCorrectly(string versionString, string expected)
        {
            // Arrange
            var version = new SemanticVersion(versionString);

            // Act
            var result = version.ToString();

            // Assert
            Assert.Equal(expected, result);
        }

        #endregion

        #region Immutability Tests

        [Fact]
        public void Properties_ShouldBeReadOnly()
        {
            // Arrange
            var version = new SemanticVersion("1.2.3-alpha");

            // Act & Assert - attempting to set properties should not compile
            // This is verified at compile-time, but we document the expected behavior here
            Assert.Equal(1, version.Major);
            Assert.Equal(2, version.Minor);
            Assert.Equal(3, version.Patch);
            Assert.Equal("alpha", version.PreRelease);
        }

        #endregion
    }
}

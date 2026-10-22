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

using ColDogStudios.ColDogLocker.Services.Security;

namespace ColDogStudios.ColDogLocker.Services.Tests.Security
{
    public class EncryptionHelperTests
    {
        #region HashPassword Tests

        [Fact]
        public void HashPassword_WithValidPassword_ShouldReturnNonEmptyHash()
        {
            // Arrange
            var password = "MySecurePassword123!";

            // Act
            var hash = EncryptionHelper.HashPassword(password);

            // Assert
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
        }

        [Fact]
        public void HashPassword_WithNullPassword_ShouldThrowArgumentException()
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentException>(() => EncryptionHelper.HashPassword(null!));
            Assert.Equal("Password cannot be null or empty. (Parameter 'password')", exception.Message);
        }

        [Fact]
        public void HashPassword_WithEmptyPassword_ShouldThrowArgumentException()
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentException>(() => EncryptionHelper.HashPassword(string.Empty));
            Assert.Equal("Password cannot be null or empty. (Parameter 'password')", exception.Message);
        }

        [Fact]
        public void HashPassword_ShouldReturnVersionedFullPasswordVerifier()
        {
            // Arrange
            var password = "TestPassword123!";

            // Act
            var hash = EncryptionHelper.HashPassword(password);

            // Assert
            // The version and work factor are explicit; unsupported verifiers are refused.
            Assert.StartsWith("$cdl-pbkdf2-sha256$v1$600000$", hash);
        }

        [Fact]
        public void HashPassword_SamePasswordTwice_ShouldProduceDifferentHashes()
        {
            // Arrange
            var password = "SamePassword123!";

            // Act
            var hash1 = EncryptionHelper.HashPassword(password);
            var hash2 = EncryptionHelper.HashPassword(password);

            // Assert
            Assert.NotEqual(hash1, hash2); // Each verifier uses a fresh random salt.
        }

        [Theory]
        [InlineData("short")]
        [InlineData("VeryLongPasswordWith1234567890SpecialChars!@#$%^&*()")]
        [InlineData("123456")]
        [InlineData("P@ssw0rd!")]
        public void HashPassword_WithVariousPasswords_ShouldReturnValidHash(string password)
        {
            // Act
            var hash = EncryptionHelper.HashPassword(password);

            // Assert
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.StartsWith("$cdl-pbkdf2-sha256$v1$600000$", hash);
        }

        #endregion

        [Theory]
        [InlineData("x")]
        [InlineData("é")]
        [InlineData("🔐")]
        public void VerifyPassword_DifferentSuffixBeyondBcryptLimitMustFail(string character)
        {
            var prefix = "Kestrel!8" + string.Concat(Enumerable.Repeat(character, 72));
            var hash = EncryptionHelper.HashPassword(prefix + "A");
            Assert.True(EncryptionHelper.VerifyPassword(prefix + "A", hash));
            Assert.False(EncryptionHelper.VerifyPassword(prefix + "B", hash));
        }

        [Fact]
        public void VerifyPassword_RejectsLegacyBcryptVerifier()
        {
            const string Legacy = "$2a$04$b9STetOS4I7Zinp/E655pO6q0DttM8rC0frGST6cq81p0LIJsCLBC";
            Assert.Throws<InvalidDataException>(() => EncryptionHelper.VerifyPassword("Legacy!Pass582", Legacy));
            Assert.Throws<InvalidDataException>(() => EncryptionHelper.VerifyPassword("Different!Pass582", Legacy));
        }

        #region VerifyPassword Tests

        [Fact]
        public void VerifyPassword_WithCorrectPassword_ShouldReturnTrue()
        {
            // Arrange
            var password = "MySecurePassword123!";
            var hash = EncryptionHelper.HashPassword(password);

            // Act
            var result = EncryptionHelper.VerifyPassword(password, hash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyPassword_WithIncorrectPassword_ShouldReturnFalse()
        {
            // Arrange
            var correctPassword = "CorrectPassword123!";
            var incorrectPassword = "WrongPassword456!";
            var hash = EncryptionHelper.HashPassword(correctPassword);

            // Act
            var result = EncryptionHelper.VerifyPassword(incorrectPassword, hash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyPassword_WithNullPassword_ShouldReturnFalse()
        {
            // Arrange
            var hash = EncryptionHelper.HashPassword("SomePassword");

            // Act
            var result = EncryptionHelper.VerifyPassword(null!, hash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyPassword_WithEmptyPassword_ShouldReturnFalse()
        {
            // Arrange
            var hash = EncryptionHelper.HashPassword("SomePassword");

            // Act
            var result = EncryptionHelper.VerifyPassword(string.Empty, hash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyPassword_WithNullHash_ShouldReturnFalse()
        {
            // Act
            var result = EncryptionHelper.VerifyPassword("SomePassword", null!);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyPassword_WithEmptyHash_ShouldReturnFalse()
        {
            // Act
            var result = EncryptionHelper.VerifyPassword("SomePassword", string.Empty);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyPassword_WithInvalidHash_ShouldThrowException()
        {
            // Act & Assert
            // Unsupported verifier formats must not silently authenticate.
            Assert.Throws<InvalidDataException>(() =>
                EncryptionHelper.VerifyPassword("SomePassword", "InvalidHashFormat"));
        }

        [Theory]
        [InlineData("$cdl-pbkdf2-sha256$v1$600000$not-base64$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
        [InlineData("$cdl-pbkdf2-sha256$v1$600000$AAAAAAAAAAAAAAAAAAAAAA==$not-base64")]
        public void VerifyPassword_WithMalformedCurrentVerifier_ShouldThrowInvalidDataException(string verifier)
        {
            Assert.Throws<InvalidDataException>(() => EncryptionHelper.VerifyPassword("SomePassword", verifier));
        }

        [Fact]
        public void VerifyPassword_CaseSensitive_ShouldReturnFalse()
        {
            // Arrange
            var password = "CaseSensitivePassword";
            var hash = EncryptionHelper.HashPassword(password);

            // Act
            var result = EncryptionHelper.VerifyPassword("casesensitivepassword", hash);

            // Assert
            Assert.False(result);
        }

        [Theory]
        [InlineData("Short1")]
        [InlineData("MediumPassword123!")]
        [InlineData("VeryLongPasswordWithLotsOfCharacters1234567890!@#$%^&*()")]
        public void VerifyPassword_WithVariousValidPasswords_ShouldReturnTrue(string password)
        {
            // Arrange
            var hash = EncryptionHelper.HashPassword(password);

            // Act
            var result = EncryptionHelper.VerifyPassword(password, hash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyPassword_WithSpecialCharacters_ShouldWorkCorrectly()
        {
            // Arrange
            var password = "P@$$w0rd!#%&*()_+-=[]{}|;:',.<>?/~`";
            var hash = EncryptionHelper.HashPassword(password);

            // Act
            var result = EncryptionHelper.VerifyPassword(password, hash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyPassword_WithUnicodeCharacters_ShouldWorkCorrectly()
        {
            // Arrange
            var password = "Pāsswørd™123!";
            var hash = EncryptionHelper.HashPassword(password);

            // Act
            var result = EncryptionHelper.VerifyPassword(password, hash);

            // Assert
            Assert.True(result);
        }

        #endregion

    }
}

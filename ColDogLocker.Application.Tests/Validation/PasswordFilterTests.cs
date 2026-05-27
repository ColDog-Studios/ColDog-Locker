using ColDogStudios.ColDogLocker.Application.Validation;

namespace ColDogStudios.ColDogLocker.Application.Tests.Validation
{
    public class PasswordFilterTests
    {
        #region ValidatePassword Tests

        [Fact]
        public void ValidatePassword_WithValidPassword_ShouldReturnNull()
        {
            // Arrange
            var validPassword = "ValidPass123!";

            // Act
            var result = PasswordFilter.ValidatePassword(validPassword);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ValidatePassword_WithNullPassword_ShouldReturnError()
        {
            // Act
            var result = PasswordFilter.ValidatePassword(null!);

            // Assert
            Assert.Equal("Password cannot be null or empty.", result);
        }

        [Fact]
        public void ValidatePassword_WithEmptyPassword_ShouldReturnError()
        {
            // Act
            var result = PasswordFilter.ValidatePassword(string.Empty);

            // Assert
            Assert.Equal("Password cannot be null or empty.", result);
        }

        [Theory]
        [InlineData("short")]
        [InlineData("Pass1!")]
        [InlineData("123456789")]
        public void ValidatePassword_WithPasswordLessThan10Characters_ShouldReturnError(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Equal("At least 12 characters", result);
        }

        [Theory]
        [InlineData("validpass123!")]
        [InlineData("nouppercasehere1!")]
        public void ValidatePassword_WithoutUppercaseLetter_ShouldReturnError(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Equal("At least one uppercase letter", result);
        }

        [Theory]
        [InlineData("VALIDPASS123!")]
        [InlineData("NOLOWERCASEHERE1!")]
        public void ValidatePassword_WithoutLowercaseLetter_ShouldReturnError(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Equal("At least one lowercase letter", result);
        }

        [Theory]
        [InlineData("ValidPassword!")]
        [InlineData("NoDigitsHere!")]
        public void ValidatePassword_WithoutDigit_ShouldReturnError(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Equal("At least one digit", result);
        }

        [Theory]
        [InlineData("ValidPass123")]
        [InlineData("NoSpecialChar1")]
        public void ValidatePassword_WithoutSpecialCharacter_ShouldReturnError(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Equal("At least one special character", result);
        }

        [Theory]
        [InlineData("MySecureP@ssw0rd")]
        [InlineData("C0mpl3x!Phrase")]
        [InlineData("Str0ng#Encrypt3d")]
        [InlineData("T3st$UniqueKey")]
        public void ValidatePassword_WithValidPasswords_ShouldReturnNull(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Null(result);
        }

        [Theory]
        [InlineData("Abcdefghij12!")] // 13 chars
        [InlineData("Abcdefghij1!")] // 12 chars
        public void ValidatePassword_WithMinimumAndAboveLength_ShouldReturnNull(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Null(result);
        }

        [Theory]
        [InlineData("Valid!Pass123")] // ! is special, 13 chars
        [InlineData("Valid@Pass123")] // @ is special, 13 chars
        [InlineData("Valid#Pass123")] // # is special, 13 chars
        [InlineData("Valid$Pass123")] // $ is special, 13 chars
        [InlineData("Valid%Pass123")] // % is special, 13 chars
        [InlineData("Valid&Pass123")] // & is special, 13 chars
        [InlineData("Valid*Pass123")] // * is special, 13 chars
        public void ValidatePassword_WithVariousSpecialCharacters_ShouldReturnNull(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Null(result);
        }

        #endregion

        #region Common Words Tests

        [Fact]
        public void ValidatePassword_WithNoCommonWords_ShouldReturnNull()
        {
            // Arrange
            var validPassword = "MyUniqueP@ssw0rd";

            // Act
            var result = PasswordFilter.ValidatePassword(validPassword);

            // Assert
            Assert.Null(result);
        }

        [Theory]
        [InlineData("password123!1A", "password")]
        [InlineData("MyPassword!1A", "password")]
        public void ValidatePassword_WithPasswordWord_ShouldReturnError(string password, string expectedCommonWord)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.NotNull(result);
            Assert.Contains(expectedCommonWord, result, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("is considered a common word", result);
        }

        [Theory]
        [InlineData("Admin123!Admin")]
        [InlineData("MyLocker1234!")]
        [InlineData("Root123!Root12")]
        [InlineData("Secret1!Secret")]
        [InlineData("Qwerty123456!")]
        [InlineData("Welcome12345!")]
        public void ValidatePassword_WithCommonWords_ShouldReturnError(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.NotNull(result);
            Assert.Contains("is considered a common word", result);
        }

        [Theory]
        [InlineData("MyUnique!Pass123")]
        [InlineData("Str0ng#Encrypt3d")]
        [InlineData("C0mpl3x!Phrase99")]
        [InlineData("Secure$Vault99")]
        public void ValidatePassword_WithoutCommonWords_ShouldReturnNull(string password)
        {
            // Act
            var result = PasswordFilter.ValidatePassword(password);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ValidatePassword_IsCaseInsensitive()
        {
            // Arrange - Test with various cases containing 'password' word
            var passwords = new[] { "PASSWORD123!1A", "PaSsWoRd123!1A", "password123!1A" };

            // Act & Assert - All should fail due to containing the common word "password"
            foreach (var password in passwords)
            {
                var result = PasswordFilter.ValidatePassword(password);
                Assert.NotNull(result);
                // The error could be about lowercase letter (for all caps) or the password word
                Assert.True(result.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                            result.Contains("lowercase", StringComparison.OrdinalIgnoreCase));
            }
        }

        #endregion

        #region GetPasswordRequirements Tests

        [Fact]
        public void GetPasswordRequirements_WithValidPassword_AllRequirementsMet()
        {
            // Arrange
            var password = "ValidPass123!";

            // Act
            var requirements = PasswordFilter.GetPasswordRequirements(password);

            // Assert
            Assert.NotEmpty(requirements);
            Assert.All(requirements, req => Assert.True(req.IsMet));
        }

        [Fact]
        public void GetPasswordRequirements_WithEmptyPassword_NoRequirementsMet()
        {
            // Arrange
            var password = string.Empty;

            // Act
            var requirements = PasswordFilter.GetPasswordRequirements(password);

            // Assert
            Assert.NotEmpty(requirements);
            // All requirements except "No common words" should not be met
            var securityRequirements = requirements.Where(r => !r.Description.Contains("common word"));
            Assert.All(securityRequirements, req => Assert.False(req.IsMet));

            // Common word requirement should be met (empty string has no common words)
            var commonWordRequirement = requirements.First(r => r.Description.Contains("common word"));
            Assert.True(commonWordRequirement.IsMet);
        }

        [Fact]
        public void GetPasswordRequirements_WithShortPassword_LengthRequirementNotMet()
        {
            // Arrange
            var password = "Short1!";

            // Act
            var requirements = PasswordFilter.GetPasswordRequirements(password);

            // Assert
            var lengthRequirement = requirements.First(r => r.Description.Contains("12 characters"));
            Assert.False(lengthRequirement.IsMet);
        }

        [Fact]
        public void GetPasswordRequirements_WithCommonWord_CommonWordRequirementNotMet()
        {
            // Arrange
            var password = "Password123!";

            // Act
            var requirements = PasswordFilter.GetPasswordRequirements(password);

            // Assert
            var commonWordRequirement = requirements.First(r => r.Description.Contains("common word"));
            Assert.False(commonWordRequirement.IsMet);
        }

        #endregion
    }
}

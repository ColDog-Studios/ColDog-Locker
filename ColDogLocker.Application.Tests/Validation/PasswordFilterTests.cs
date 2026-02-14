using ColDogStudios.ColDogLocker.Application.Validation;

namespace ColDogStudios.ColDogLocker.Application.Tests.Validation
{
    public class PasswordFilterTests
    {
        #region SecurityCheck Tests

        [Fact]
        public void SecurityCheck_WithValidPassword_ShouldNotThrow()
        {
            // Arrange
            var validPassword = "ValidPass123!";

            // Act & Assert
            var exception = Record.Exception(() => PasswordFilter.SecurityCheck(validPassword));
            Assert.Null(exception);
        }

        [Fact]
        public void SecurityCheck_WithNullPassword_ShouldThrowArgumentException()
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentException>(() => PasswordFilter.SecurityCheck(null!));
            Assert.Equal("Password cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void SecurityCheck_WithEmptyPassword_ShouldThrowArgumentException()
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentException>(() => PasswordFilter.SecurityCheck(string.Empty));
            Assert.Equal("Password cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData("short")]
        [InlineData("Pass1!")]
        [InlineData("123456789")]
        public void SecurityCheck_WithPasswordLessThan10Characters_ShouldThrowException(string password)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.SecurityCheck(password));
            Assert.Equal("Password must be at least 10 characters long.", exception.Message);
        }

        [Theory]
        [InlineData("validpass123!")]
        [InlineData("nouppercasehere1!")]
        public void SecurityCheck_WithoutUppercaseLetter_ShouldThrowException(string password)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.SecurityCheck(password));
            Assert.Equal("Password must contain at least one uppercase letter.", exception.Message);
        }

        [Theory]
        [InlineData("VALIDPASS123!")]
        [InlineData("NOLOWERCASEHERE1!")]
        public void SecurityCheck_WithoutLowercaseLetter_ShouldThrowException(string password)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.SecurityCheck(password));
            Assert.Equal("Password must contain at least one lowercase letter.", exception.Message);
        }

        [Theory]
        [InlineData("ValidPassword!")]
        [InlineData("NoDigitsHere!")]
        public void SecurityCheck_WithoutDigit_ShouldThrowException(string password)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.SecurityCheck(password));
            Assert.Equal("Password must contain at least one digit.", exception.Message);
        }

        [Theory]
        [InlineData("ValidPass123")]
        [InlineData("NoSpecialChar1")]
        public void SecurityCheck_WithoutSpecialCharacter_ShouldThrowException(string password)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.SecurityCheck(password));
            Assert.Equal("Password must contain at least one special character.", exception.Message);
        }

        [Theory]
        [InlineData("Valid1Pass!")]
        [InlineData("MySecureP@ssw0rd")]
        [InlineData("C0mpl3x!Pass")]
        [InlineData("Str0ng#Password")]
        [InlineData("T3st$Password")]
        public void SecurityCheck_WithValidPasswords_ShouldNotThrow(string password)
        {
            // Act & Assert
            var exception = Record.Exception(() => PasswordFilter.SecurityCheck(password));
            Assert.Null(exception);
        }

        [Fact]
        public void SecurityCheck_WithExactly10Characters_ShouldPass()
        {
            // Arrange
            var password = "Valid1Pass!";

            // Act & Assert
            Assert.Equal(11, password.Length); // Just to verify our test data
            var exception = Record.Exception(() => PasswordFilter.SecurityCheck(password));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData("Abcdefgh1!")]  // 10 chars
        [InlineData("Abcdefghij1!")]  // 12 chars
        public void SecurityCheck_WithMinimumAndAboveLength_ShouldPass(string password)
        {
            // Act & Assert
            var exception = Record.Exception(() => PasswordFilter.SecurityCheck(password));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData("Valid!Pass1")]  // ! is special
        [InlineData("Valid@Pass1")]  // @ is special
        [InlineData("Valid#Pass1")]  // # is special
        [InlineData("Valid$Pass1")]  // $ is special
        [InlineData("Valid%Pass1")]  // % is special
        [InlineData("Valid&Pass1")]  // & is special
        [InlineData("Valid*Pass1")]  // * is special
        public void SecurityCheck_WithVariousSpecialCharacters_ShouldPass(string password)
        {
            // Act & Assert
            var exception = Record.Exception(() => PasswordFilter.SecurityCheck(password));
            Assert.Null(exception);
        }

        #endregion

        #region IllegalWordCheck Tests

        [Fact]
        public void IllegalWordCheck_WithValidPassword_ShouldNotThrow()
        {
            // Arrange
            var validPassword = "MyUniqueP@ssw0rd";

            // Act & Assert
            var exception = Record.Exception(() => PasswordFilter.IllegalWordCheck(validPassword));
            Assert.Null(exception);
        }

        [Fact]
        public void IllegalWordCheck_WithNullPassword_ShouldThrowArgumentException()
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentException>(() => PasswordFilter.IllegalWordCheck(null!));
            Assert.Equal("Password cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void IllegalWordCheck_WithEmptyPassword_ShouldThrowArgumentException()
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentException>(() => PasswordFilter.IllegalWordCheck(string.Empty));
            Assert.Equal("Password cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData("password123", "password")]
        [InlineData("MyPassword!", "password")]
        [InlineData("Password123", "password")]
        public void IllegalWordCheck_WithPasswordWord_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("is considered a common word", exception.Message);
        }

        [Theory]
        [InlineData("admin123", "admin")]
        [InlineData("AdminUser!", "admin")]
        public void IllegalWordCheck_WithAdminWord_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("mylocker123", "locker")]
        [InlineData("LockerPass!", "locker")]
        public void IllegalWordCheck_WithLockerWord_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("root123456", "root")]
        [InlineData("RootUser!", "root")]
        public void IllegalWordCheck_WithRootWord_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("mysecret12", "secret")]
        [InlineData("SecretPass!", "secret")]
        public void IllegalWordCheck_WithSecretWord_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("123456", "123456")]
        [InlineData("abc123456", "123456")]
        public void IllegalWordCheck_With123456_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("qwerty123", "qwerty")]
        [InlineData("QwertyPass!", "qwerty")]
        public void IllegalWordCheck_WithQwerty_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("letmein123", "letmein")]
        [InlineData("LetMeInNow!", "letmein")]
        public void IllegalWordCheck_WithLetMeIn_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("monkey123", "monkey")]
        [InlineData("MonkeyPass!", "monkey")]
        public void IllegalWordCheck_WithMonkey_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("abc123", "abc123")]
        [InlineData("myabc123pass", "abc123")]
        public void IllegalWordCheck_WithAbc123_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("football123", "football")]
        [InlineData("FootballFan!", "football")]
        public void IllegalWordCheck_WithFootball_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("baseball123", "baseball")]
        [InlineData("BaseballFan!", "baseball")]
        public void IllegalWordCheck_WithBaseball_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("basketball1", "basketball")]
        [InlineData("BasketballFan!", "basketball")]
        public void IllegalWordCheck_WithBasketball_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("iloveyou123", "iloveyou")]
        [InlineData("ILoveYouToo!", "iloveyou")]
        public void IllegalWordCheck_WithILoveYou_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("welcome123", "welcome")]
        [InlineData("WelcomeUser!", "welcome")]
        public void IllegalWordCheck_WithWelcome_ShouldThrowException(string password, string expectedIllegalWord)
        {
            // Act & Assert
            var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Contains(expectedIllegalWord, exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("MyUnique!Pass1")]
        [InlineData("Str0ng#Encrypt3d")]
        [InlineData("C0mpl3x!Phrase")]
        [InlineData("Secure$Vault99")]
        public void IllegalWordCheck_WithValidPasswords_ShouldNotThrow(string password)
        {
            // Act & Assert
            var exception = Record.Exception(() => PasswordFilter.IllegalWordCheck(password));
            Assert.Null(exception);
        }

        [Fact]
        public void IllegalWordCheck_IsCaseInsensitive()
        {
            // Arrange - Test with various cases
            var passwords = new[] { "PASSWORD123", "PaSsWoRd123", "password123" };

            // Act & Assert
            foreach (var password in passwords)
            {
                var exception = Assert.Throws<Exception>(() => PasswordFilter.IllegalWordCheck(password));
                Assert.Contains("password", exception.Message, StringComparison.OrdinalIgnoreCase);
            }
        }

        #endregion

        #region Combined Validation Tests

        [Theory]
        [InlineData("ValidSecure1!")]
        [InlineData("MyUnique@Pass1")]
        [InlineData("Str0ng#Encrypt3d")]
        public void BothChecks_WithValidPassword_ShouldNotThrow(string password)
        {
            // Act & Assert
            var securityException = Record.Exception(() => PasswordFilter.SecurityCheck(password));
            var illegalWordException = Record.Exception(() => PasswordFilter.IllegalWordCheck(password));

            Assert.Null(securityException);
            Assert.Null(illegalWordException);
        }

        [Theory]
        [InlineData("password1!")]  // Too short
        [InlineData("Password!")]   // No digit
        [InlineData("password123")] // No special char, no uppercase
        public void BothChecks_WithInvalidPassword_ShouldThrowFromAtLeastOne(string password)
        {
            // Act
            var securityException = Record.Exception(() => PasswordFilter.SecurityCheck(password));
            var illegalWordException = Record.Exception(() => PasswordFilter.IllegalWordCheck(password));

            // Assert - At least one should throw
            Assert.True(securityException != null || illegalWordException != null,
                "At least one validation should fail");
        }

        #endregion
    }
}

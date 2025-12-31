using ColDogStudios.ColDogLocker.Infrastructure.Encryption;

namespace ColDogStudios.ColDogLocker.Infrastructure.Tests.Encryption;

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
    public void HashPassword_ShouldReturnBcryptFormattedHash()
    {
        // Arrange
        var password = "TestPassword123!";

        // Act
        var hash = EncryptionHelper.HashPassword(password);

        // Assert
        // BCrypt hashes start with $2a$, $2b$, $2x$, or $2y$ followed by cost factor
        Assert.Matches(@"^\$2[abxy]\$\d{2}\$", hash);
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
        Assert.NotEqual(hash1, hash2); // BCrypt uses random salts, so hashes should differ
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
        Assert.Matches(@"^\$2[abxy]\$\d{2}\$", hash);
    }

    #endregion

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
        // BCrypt throws an exception when given an invalid hash format
        Assert.ThrowsAny<Exception>(() =>
            EncryptionHelper.VerifyPassword("SomePassword", "InvalidHashFormat"));
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

    #region LegacyHashPassword Tests

    [Fact]
    public void LegacyHashPassword_WithValidPassword_ShouldReturnNonEmptyHash()
    {
        // Arrange
        var password = "MySecurePassword123!";

        // Act
        var hash = EncryptionHelper.LegacyHashPassword(password);

        // Assert
        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
    }

    [Fact]
    public void LegacyHashPassword_ShouldReturn128CharacterHash()
    {
        // Arrange
        var password = "TestPassword";

        // Act
        var hash = EncryptionHelper.LegacyHashPassword(password);

        // Assert
        // SHA-512 produces 64 bytes = 128 hex characters
        Assert.Equal(128, hash.Length);
    }

    [Fact]
    public void LegacyHashPassword_ShouldReturnHexString()
    {
        // Arrange
        var password = "TestPassword";

        // Act
        var hash = EncryptionHelper.LegacyHashPassword(password);

        // Assert
        Assert.Matches("^[0-9a-f]+$", hash);
    }

    [Fact]
    public void LegacyHashPassword_SamePasswordTwice_ShouldProduceSameHash()
    {
        // Arrange
        var password = "ConsistentPassword123";

        // Act
        var hash1 = EncryptionHelper.LegacyHashPassword(password);
        var hash2 = EncryptionHelper.LegacyHashPassword(password);

        // Assert
        Assert.Equal(hash1, hash2); // Legacy hash is deterministic (no salt)
    }

    [Fact]
    public void LegacyHashPassword_DifferentPasswords_ShouldProduceDifferentHashes()
    {
        // Arrange
        var password1 = "Password1";
        var password2 = "Password2";

        // Act
        var hash1 = EncryptionHelper.LegacyHashPassword(password1);
        var hash2 = EncryptionHelper.LegacyHashPassword(password2);

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("VeryLongPasswordWith1234567890SpecialChars!@#$%^&*()")]
    [InlineData("123456")]
    [InlineData("P@ssw0rd!")]
    public void LegacyHashPassword_WithVariousPasswords_ShouldReturn128CharHash(string password)
    {
        // Act
        var hash = EncryptionHelper.LegacyHashPassword(password);

        // Assert
        Assert.Equal(128, hash.Length);
        Assert.Matches("^[0-9a-f]+$", hash);
    }

    [Fact]
    public void LegacyHashPassword_WithEmptyString_ShouldReturnHash()
    {
        // Arrange
        var password = string.Empty;

        // Act
        var hash = EncryptionHelper.LegacyHashPassword(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(128, hash.Length);
    }

    #endregion

    #region File Operation Exception Tests

    [Fact]
    public void EncryptFile_WithNullFilePath_ShouldThrowArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            EncryptionHelper.EncryptFile(null!, "password"));
        Assert.Equal("Input file path cannot be null or empty. (Parameter 'inputFile')", exception.Message);
    }

    [Fact]
    public void EncryptFile_WithEmptyFilePath_ShouldThrowArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            EncryptionHelper.EncryptFile(string.Empty, "password"));
        Assert.Equal("Input file path cannot be null or empty. (Parameter 'inputFile')", exception.Message);
    }

    [Fact]
    public void EncryptFile_WithNullPassword_ShouldThrowArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            EncryptionHelper.EncryptFile("somefile.txt", null!));
        Assert.Equal("Password cannot be null or empty. (Parameter 'password')", exception.Message);
    }

    [Fact]
    public void EncryptFile_WithEmptyPassword_ShouldThrowArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            EncryptionHelper.EncryptFile("somefile.txt", string.Empty));
        Assert.Equal("Password cannot be null or empty. (Parameter 'password')", exception.Message);
    }

    [Fact]
    public void EncryptFile_WithNonExistentFile_ShouldThrowFileNotFoundException()
    {
        // Arrange
        var nonExistentFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".txt");

        // Act & Assert
        var exception = Assert.Throws<FileNotFoundException>(() =>
            EncryptionHelper.EncryptFile(nonExistentFile, "password"));
        Assert.Contains("Input file not found", exception.Message);
    }

    [Fact]
    public void DecryptFile_WithNullFilePath_ShouldThrowArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            EncryptionHelper.DecryptFile(null!, "password"));
        Assert.Equal("Input file path cannot be null or empty. (Parameter 'inputFile')", exception.Message);
    }

    [Fact]
    public void DecryptFile_WithEmptyFilePath_ShouldThrowArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            EncryptionHelper.DecryptFile(string.Empty, "password"));
        Assert.Equal("Input file path cannot be null or empty. (Parameter 'inputFile')", exception.Message);
    }

    [Fact]
    public void DecryptFile_WithNullPassword_ShouldThrowArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            EncryptionHelper.DecryptFile("somefile.txt", null!));
        Assert.Equal("Password cannot be null or empty. (Parameter 'password')", exception.Message);
    }

    [Fact]
    public void DecryptFile_WithEmptyPassword_ShouldThrowArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            EncryptionHelper.DecryptFile("somefile.txt", string.Empty));
        Assert.Equal("Password cannot be null or empty. (Parameter 'password')", exception.Message);
    }

    [Fact]
    public void DecryptFile_WithNonExistentFile_ShouldThrowFileNotFoundException()
    {
        // Arrange
        var nonExistentFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".txt");

        // Act & Assert
        var exception = Assert.Throws<FileNotFoundException>(() =>
            EncryptionHelper.DecryptFile(nonExistentFile, "password"));
        Assert.Contains("Input file not found", exception.Message);
    }

    #endregion
}

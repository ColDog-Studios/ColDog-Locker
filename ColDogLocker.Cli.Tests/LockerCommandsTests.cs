using ColDogStudios.ColDogLocker.Cli.Commands;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Security;

namespace ColDogStudios.ColDogLocker.Cli.Tests
{
    public sealed class LockerCommandsTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ChangePassword_RejectsCurrentPasswordBeforeRequestingOrValidatingReplacement(bool provided)
        {
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword("Violet!River9Moon"), "unused");
            LockerService.ReplaceLockersForTesting([locker]);
            using var output = new StringWriter();
            using var error = new StringWriter();
            var originalOutput = Console.Out;
            var originalError = Console.Error;
            var reads = 0;
            try
            {
                Console.SetOut(output);
                Console.SetError(error);
                string[] args = provided
                    ? ["change-password", "Vault", "--old-password", "wrong", "--new-password", "weak"]
                    : ["change-password", "Vault"];
                var exitCode = LockerCommands.ChangePassword(args, () =>
                {
                    Assert.Equal(0, reads++);
                    return "wrong";
                });
                Assert.Equal(1, exitCode);
                Assert.Equal(provided ? 0 : 1, reads);
                Assert.Contains("Incorrect current password", error.ToString());
                Assert.DoesNotContain("validation failed", error.ToString());
                Assert.DoesNotContain("Enter new password", output.ToString());
                Assert.DoesNotContain("Password Requirements", output.ToString());
                Assert.Equal(locker.Password, LockerService.FindLockerByName("Vault")!.Password);
            }
            finally
            {
                Console.SetOut(originalOutput);
                Console.SetError(originalError);
                LockerService.ClearLockersForTesting();
            }
        }

        [Fact]
        public void ChangePassword_ShowsAllRequirementsAndRejectsWeakAndMismatchedReplacements()
        {
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword("Violet!River9Moon"), "unused");
            LockerService.ReplaceLockersForTesting([locker]);
            var responses = new Queue<string>(["Violet!River9Moon", "weak", "Copper!River8Moon", "different"]);
            using var output = new StringWriter();
            using var error = new StringWriter();
            var originalOutput = Console.Out;
            var originalError = Console.Error;
            try
            {
                Console.SetOut(output);
                Console.SetError(error);
                Assert.Equal(1, LockerCommands.ChangePassword(["change-password", "Vault"], responses.Dequeue));
                Assert.Empty(responses);
                foreach (var requirement in PasswordFilter.Validate(string.Empty))
                {
                    Assert.Contains(requirement.Description, output.ToString());
                }

                Assert.Contains("Password validation failed", output.ToString());
                Assert.Contains("Passwords do not match", error.ToString());
                Assert.Equal(locker.Password, LockerService.FindLockerByName("Vault")!.Password);
            }
            finally
            {
                Console.SetOut(originalOutput);
                Console.SetError(originalError);
                LockerService.ClearLockersForTesting();
            }
        }

        [Theory]
        [InlineData("bad/name", "Locker name must be a valid file name")]
        [InlineData("..", "Locker name must be a valid file name")]
        [InlineData("", "Locker name cannot be empty")]
        public void New_WithInvalidLockerName_ReturnsErrorBeforeCreatingLocker(string lockerName, string expectedError)
        {
            using var errorWriter = new StringWriter();
            var originalError = Console.Error;

            try
            {
                Console.SetError(errorWriter);

                var exitCode = LockerCommands.New(["new", lockerName, "--password", "ValidPassword123!"]);

                Assert.Equal(1, exitCode);
                Assert.Contains(expectedError, errorWriter.ToString());
            }
            finally
            {
                Console.SetError(originalError);
            }
        }
    }
}

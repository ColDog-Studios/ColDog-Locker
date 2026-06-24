using ColDogStudios.ColDogLocker.Cli.Commands;

namespace ColDogStudios.ColDogLocker.Cli.Tests
{
    public sealed class LockerCommandsTests
    {
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

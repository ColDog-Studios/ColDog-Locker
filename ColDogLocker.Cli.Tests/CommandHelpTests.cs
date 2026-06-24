using ColDogStudios.ColDogLocker.Cli;

namespace ColDogStudios.ColDogLocker.Cli.Tests
{
    public sealed class CommandHelpTests
    {
        [Fact]
        public void ShowGeneralHelp_IncludesCliEntryPointsAndAliases()
        {
            var output = CaptureOutput(CommandHelp.ShowGeneralHelp);

            Assert.Contains("USAGE:", output);
            Assert.Contains("cdlocker gui", output);
            Assert.Contains("cdlocker tui", output);
            Assert.Contains("update [--download]", output);
            Assert.Contains("--version, -v", output);
        }

        [Theory]
        [InlineData("new", "CREATE NEW LOCKER:")]
        [InlineData("remove", "REMOVE LOCKER:")]
        [InlineData("lock", "LOCK LOCKER:")]
        [InlineData("unlock", "UNLOCK LOCKER:")]
        [InlineData("list", "LIST LOCKERS:")]
        [InlineData("status", "SHOW LOCKER STATUS:")]
        [InlineData("change-password", "CHANGE LOCKER PASSWORD:")]
        [InlineData("verify", "VERIFY LOCKER:")]
        [InlineData("settings", "MANAGE SETTINGS:")]
        [InlineData("db-vacuum", "VACUUM DATABASE:")]
        [InlineData("db-info", "DATABASE INFORMATION:")]
        [InlineData("update", "CHECK FOR UPDATES:")]
        [InlineData("gui", "LAUNCH GUI:")]
        [InlineData("tui", "LAUNCH TERMINAL UI:")]
        public void ShowCommandHelp_ForKnownCommand_PrintsExpectedHeading(string command, string expectedHeading)
        {
            var output = CaptureOutput(() => CommandHelp.ShowCommandHelp(command));

            Assert.Contains($"Help for command: {command}", output);
            Assert.Contains(expectedHeading, output);
        }

        [Fact]
        public void ShowCommandHelp_ForUnknownCommand_PrintsCompleteCommandList()
        {
            var output = CaptureOutput(() => CommandHelp.ShowCommandHelp("missing-command"));

            Assert.Contains("No help available for command: missing-command", output);
            Assert.Contains("update", output);
            Assert.Contains("tui", output);
        }

        private static string CaptureOutput(Action action)
        {
            using var outputWriter = new StringWriter();
            var originalOutput = Console.Out;

            try
            {
                Console.SetOut(outputWriter);
                action();
                return outputWriter.ToString();
            }
            finally
            {
                Console.SetOut(originalOutput);
            }
        }
    }
}

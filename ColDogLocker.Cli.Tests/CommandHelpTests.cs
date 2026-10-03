using ColDogStudios.ColDogLocker.Cli;

namespace ColDogStudios.ColDogLocker.Cli.Tests
{
    public sealed class CommandHelpTests
    {
        [Fact]
        public void Recovery_RestoresWithoutInitializingDatabaseAndNeverOverwrites()
        {
            var root = Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), $"cdl-recovery-test-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            try
            {
                var source = Directory.CreateDirectory(Path.Join(root, "Source")).FullName;
                File.WriteAllText(Path.Join(source, "original.txt"), "recover me");
                var archive = Path.Join(root, "locker.cdl");
                var destination = Path.Join(root, "Recovered");
                var locker = new ColDogStudios.ColDogLocker.Core.Models.LockerModel("Source", "unused", source);
                ColDogStudios.ColDogLocker.Services.Lockers.LockerArchiveService.CreateFromDirectory(source, archive, locker, "Recovery!Pass724");
                var originalHash = ColDogStudios.ColDogLocker.Services.Lockers.LockerArchiveService.ComputeSha256(archive);
                var initialized = false;
                void UnavailableDatabase()
                {
                    initialized = true;
                    throw new IOException("Database unavailable");
                }

                CaptureOutput(() => Assert.Equal(1, Program.Run(["recover", archive, destination, "--password", "wrong"], UnavailableDatabase)));
                Assert.False(Directory.Exists(destination));

                var corruptArchive = Path.Join(root, "corrupt.cdl");
                File.Copy(archive, corruptArchive);
                File.SetAttributes(corruptArchive, FileAttributes.Normal);
                var corruptBytes = File.ReadAllBytes(corruptArchive);
                corruptBytes[^1] ^= 0x01;
                File.WriteAllBytes(corruptArchive, corruptBytes);
                var corruptDestination = Path.Join(root, "CorruptRecovery");
                CaptureOutput(() => Assert.Equal(1, Program.Run(
                    ["recover", corruptArchive, corruptDestination, "--password", "Recovery!Pass724"],
                    UnavailableDatabase)));
                Assert.False(Directory.Exists(corruptDestination));
                Assert.Equal(corruptBytes, File.ReadAllBytes(corruptArchive));

                CaptureOutput(() => Assert.Equal(0, Program.Run(["recover", archive, destination, "--password", "Recovery!Pass724"], UnavailableDatabase)));
                Assert.Equal("recover me", File.ReadAllText(Path.Join(destination, "original.txt")));
                CaptureOutput(() => Assert.Equal(1, Program.Run(["recover", archive, destination, "--password", "Recovery!Pass724"], UnavailableDatabase)));
                Assert.False(initialized);
                Assert.Equal(originalHash, ColDogStudios.ColDogLocker.Services.Lockers.LockerArchiveService.ComputeSha256(archive));
                Assert.Equal("recover me", File.ReadAllText(Path.Join(destination, "original.txt")));
            }
            finally
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }

                Directory.Delete(root, true);
            }
        }

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
        [InlineData("recover", "USAGE: cdlocker recover")]
        [InlineData("settings", "MANAGE SETTINGS:")]
        [InlineData("db-vacuum", "VACUUM DATABASE:")]
        [InlineData("db-info", "DATABASE INFORMATION:")]
        [InlineData("db-backup", "USAGE: cdlocker db-backup")]
        [InlineData("db-restore", "USAGE: cdlocker db-restore")]
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

        [Theory]
        [InlineData("help")]
        [InlineData("--version")]
        [InlineData("-v")]
        [InlineData("")]
        public void StatelessCommands_DoNotInitializeApplication(string command)
        {
            var initialized = false;
            var output = CaptureOutput(() =>
            {
                var exit = Program.Run(command.Length == 0 ? [] : [command], () =>
                {
                    initialized = true;
                    throw new IOException("Application state is unavailable");
                });
                Assert.Equal(0, exit);
            });

            Assert.False(initialized);
            Assert.Contains(command is "--version" or "-v" ? "ColDog Locker" : "USAGE:", output);
        }

        [Fact]
        public void OperationalCommand_InitializationFailureReturnsError()
        {
            var output = CaptureOutput(() =>
                Assert.Equal(1, Program.Run(["list"], () => throw new IOException("Cannot open database"))));
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

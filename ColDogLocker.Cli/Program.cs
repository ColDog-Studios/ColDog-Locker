using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Cli.Commands;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Logging;
using ColDogStudios.ColDogLocker.Gui;
using ColDogStudios.ColDogLocker.Services.Startup;
using ColDogStudios.ColDogLocker.Tui;

namespace ColDogStudios.ColDogLocker.Cli
{
    internal class Program
    {
        private static int Main(string[] args)
        {
            // Initialize the application
            Initialization.InitializeAsync().GetAwaiter().GetResult();

            // New line for better readability in console output
            Console.WriteLine();

            try
            {
                int result;

                // No arguments - show help
                if (args.Length == 0)
                {
                    Logger.Log(LogLevel.Debug, "No CLI command provided");
                    result = HelpCommand(args);
                }
                else
                {
                    // Parse the first argument as the command/subcommand
                    var command = args[0].ToLowerInvariant();
                    Logger.Log(LogLevel.Debug, $"Received CLI command: {command}");

                    result = command switch
                    {
                        "gui" => LaunchGui(),
                        "terminal" or "tui" => LaunchTui(),
                        "new" => LockerCommands.New(args),
                        "remove" => LockerCommands.Remove(args),
                        "lock" => LockerCommands.Lock(args),
                        "unlock" => LockerCommands.Unlock(args),
                        "list" => LockerCommands.List(args),
                        "status" => LockerCommands.Status(args),
                        "change-password" => LockerCommands.ChangePassword(args),
                        "verify" => LockerCommands.Verify(args),
                        "settings" => SettingsCommands.Settings(args),
                        "db-vacuum" => DatabaseCommands.DbVacuum(args),
                        "db-info" => DatabaseCommands.DbInfo(args),
                        "help" => HelpCommand(args),
                        "dev" => DevCommand(),
                        "--version" or "-v" => VersionCommand(),
                        _ => UnknownCommand(command)
                    };
                }

                Console.WriteLine();
                return result;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"Error: {ex.Message}");
#if DEBUG
                Console.Error.WriteLine($"Stack trace:\n{ex.StackTrace}");
#endif
                Console.ResetColor();
                Logger.Log(LogLevel.Fatal, "Unhandled exception", ex);
                Console.WriteLine();
                return 1;
            }
        }

        #region UI Launchers

        private static int LaunchGui()
        {
            try
            {
                var launcher = GuiLauncher.CreateLauncher();
                return launcher.Launch(Array.Empty<string>());
            }
            catch (PlatformNotSupportedException ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Error.WriteLine($"GUI not available: {ex.Message}");
                Console.ResetColor();
                Logger.Log(LogLevel.Warning, $"GUI not available: {ex.Message}");
                return 1;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"Error launching GUI: {ex.Message}");
                Console.ResetColor();
                Logger.Log(LogLevel.Error, $"Error launching GUI {ex}");
                return 1;
            }
        }

        private static int LaunchTui()
        {
            return TuiLauncher.Launch();
        }

        #endregion

        #region Simple Command Handlers

        private static int HelpCommand(string[] args)
        {
            if (args.Length <= 1)
            {
                HelpSystem.ShowGeneralHelp();
                return 0;
            }

            var command = args[1].ToLowerInvariant();
            HelpSystem.ShowCommandHelp(command);
            return 0;
        }

        private static int DevCommand()
        {
            Console.WriteLine($"Environment: {Environment.OSVersion.Platform}");
            Console.WriteLine($"Architecture: {RuntimeInformation.ProcessArchitecture}");
            Console.WriteLine($"Runtime Identifier: {RuntimeInformation.RuntimeIdentifier}");
            Console.WriteLine($"Framework: {RuntimeInformation.FrameworkDescription}");
#if DEBUG
            Console.WriteLine("Build: DEBUG");
#else
            Console.WriteLine("Build: RELEASE");
#endif

            Console.WriteLine($"\nUser: {Environment.UserName}");

            Console.WriteLine($"\nLocal Config Location: {Variables.LocalConfig}");
            Console.WriteLine($"Current Directory: {Variables.CdlDir}");
            var logPath = Path.Join(Variables.LocalConfig, "logs");
            Console.WriteLine($"Log Directory: {logPath}");
            Console.WriteLine($"Log Directory Exists: {Directory.Exists(logPath)}");

            var configDrive = new DriveInfo(new DirectoryInfo(Variables.LocalConfig).Root.Name);
            Console.WriteLine($"\nAvailable Disk Space: {configDrive.AvailableFreeSpace / (1024 * 1024 * 1024)} GB");
            Console.WriteLine($"Process Memory: {GC.GetTotalMemory(false) / 1024} KB");

            return 0;
        }

        private static int VersionCommand()
        {
            var version = typeof(Program).Assembly.GetName().Version;
            Console.WriteLine($"ColDog Locker {AppInfo.SemanticVersion}");
            Console.WriteLine($"Build Version: {AppInfo.BuildVersion}");
            Console.WriteLine($"Assembly Version: {version}");
            Console.WriteLine($"Build Date: {AppInfo.BuildDate}");
            Console.WriteLine($"Build Time: {AppInfo.BuildTime}");
            return 0;
        }

        private static int UnknownCommand(string command)
        {
            Logger.Log(LogLevel.Debug, $"Unknown command: {command}");
            Console.Error.WriteLine($"Error: Unknown command '{command}'");
            Console.WriteLine();
            HelpSystem.ShowGeneralHelp();
            return 1;
        }

        #endregion
    }
}

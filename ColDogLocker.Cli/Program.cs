using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Cli.Commands;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
using System.Runtime.InteropServices;

namespace ColDogStudios.ColDogLocker.Cli
{
    internal class Program
    {
        private static int Main(string[] args)
        {
            Console.WriteLine();

            try
            {
                // Initialize application for CLI commands (except for UI launchers)
                if (args.Length > 0 && args[0].ToLowerInvariant() is not "gui" and not "terminal" and not "tui")
                {
                    InitializeCli();
                }

                int result;

                // No arguments - show help
                if (args.Length == 0)
                {
                    result = HandleHelpCommand(args);
                }
                else
                {
                    // Parse the first argument as the command/subcommand
                    var command = args[0].ToLowerInvariant();
                    Logger.AddEntry($"Received command: {command}", LogLevel.Debug);

                    result = command switch
                    {
                        "gui" => LaunchGui(),
                        "terminal" or "tui" => LaunchTui(),
                        "new" => LockerCommandHandlers.HandleNew(args),
                        "remove" => LockerCommandHandlers.HandleRemove(args),
                        "lock" => LockerCommandHandlers.HandleLock(args),
                        "unlock" => LockerCommandHandlers.HandleUnlock(args),
                        "list" => LockerCommandHandlers.HandleList(args),
                        "status" => LockerCommandHandlers.HandleStatus(args),
                        "change-password" => LockerCommandHandlers.HandleChangePassword(args),
                        "verify" => LockerCommandHandlers.HandleVerify(args),
                        "settings" => SettingsCommandHandlers.HandleSettings(args),
                        "db-vacuum" => DatabaseCommandHandlers.HandleDbVacuum(args),
                        "db-info" => DatabaseCommandHandlers.HandleDbInfo(args),
                        "help" => HandleHelpCommand(args),
                        "dev" => HandleDevCommand(),
                        "--version" or "-v" => HandleVersionCommand(),
                        _ => HandleUnknownCommand(command)
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
                Logger.AddEntry($"Unhandled exception: {ex}", LogLevel.Fatal);
                Console.WriteLine();
                return 1;
            }
        }

        private static void InitializeCli()
        {
            Logger.AddEntry("Initializing ColDog Locker CLI", LogLevel.Debug);

            // Create directories if needed
            if (!Directory.Exists(Variables.localConfig))
            {
                Directory.CreateDirectory(Variables.localConfig);
            }

            // Initialize database and migrate from JSON if needed
            Infrastructure.Data.LockerRepository.InitializeDatabase();

            // Load settings and lockers (minimal initialization for CLI)
            SettingsManager.LoadSettings();
            LockerService.LoadLockers();
        }

        #region UI Launchers

        private static int LaunchGui()
        {
            try
            {
                var launcher = Gui.GuiLauncher.CreateLauncher();
                return launcher.Launch(Array.Empty<string>());
            }
            catch (PlatformNotSupportedException ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Error.WriteLine($"GUI not available: {ex.Message}");
                Console.ResetColor();
                Logger.AddEntry($"GUI not available: {ex.Message}", LogLevel.Warning);
                return 1;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"Error launching GUI: {ex.Message}");
                Console.ResetColor();
                Logger.AddEntry($"Error launching GUI: {ex}", LogLevel.Error);
                return 1;
            }
        }

        private static int LaunchTui()
        {
            return Tui.TuiLauncher.Launch();
        }

        #endregion

        #region Simple Command Handlers

        private static int HandleHelpCommand(string[] args)
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

        private static int HandleDevCommand()
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
        
            Console.WriteLine($"\nLocal Config Location: {Variables.localConfig}");
            Console.WriteLine($"Current Directory: {Variables.cdlDir}");
            var logPath = Path.Combine(Variables.localConfig, "logs");
            Console.WriteLine($"Log Directory: {logPath}");
            Console.WriteLine($"Log Directory Exists: {Directory.Exists(logPath)}");
        
            var configDrive = new DriveInfo(new DirectoryInfo(Variables.localConfig).Root.Name);
            Console.WriteLine($"\nAvailable Disk Space: {configDrive.AvailableFreeSpace / (1024 * 1024 * 1024)} GB");
            Console.WriteLine($"Process Memory: {GC.GetTotalMemory(false) / 1024} KB");
        
            return 0;
        }

        private static int HandleVersionCommand()
        {
            var version = typeof(Program).Assembly.GetName().Version;
            Console.WriteLine($"ColDog Locker {BuildInfo.Version}");
            Console.WriteLine($"Build Version: {BuildInfo.BuildVersion}");
            Console.WriteLine($"Assembly Version: {version}");
            Console.WriteLine($"Build Date: {BuildInfo.BuildDate}");
            Console.WriteLine($"Build Time: {BuildInfo.BuildTime}");
            return 0;
        }

        private static int HandleUnknownCommand(string command)
        {
            Logger.AddEntry($"Unknown command: {command}", LogLevel.Debug);
            Console.Error.WriteLine($"Error: Unknown command '{command}'");
            Console.WriteLine();
            HelpSystem.ShowGeneralHelp();
            return 1;
        }

        #endregion
    }
}

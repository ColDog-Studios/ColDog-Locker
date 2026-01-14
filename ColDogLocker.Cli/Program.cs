using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Cli.Commands;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using System.Diagnostics;

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
                    InitializeForCli();
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
                Console.ResetColor();
                Console.WriteLine();
                return 1;
            }
        }

        private static void InitializeForCli()
        {
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
                // Find the GUI executable in the same directory or nearby
                var cliDirectory = AppContext.BaseDirectory;
                var guiExeName = "ColDogLocker.exe";
                
                // Check common locations relative to CLI executable
                var possiblePaths = new[]
                {
                    Path.Combine(cliDirectory, guiExeName),
                    Path.Combine(cliDirectory, "..", "ColDogLocker.Gui.WPF", "bin", "Debug", "net10.0-windows", guiExeName),
                    Path.Combine(cliDirectory, "..", "ColDogLocker.Gui.WPF", "bin", "Release", "net10.0-windows", guiExeName)
                };

                string? guiPath = null;
                foreach (var path in possiblePaths)
                {
                    var normalizedPath = Path.GetFullPath(path);
                    if (File.Exists(normalizedPath))
                    {
                        guiPath = normalizedPath;
                        break;
                    }
                }

                if (guiPath == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Error.WriteLine($"Error: Could not find {guiExeName}");
                    Console.Error.WriteLine("Please ensure the GUI application is built.");
                    Console.ResetColor();
                    return 1;
                }

                // Launch the GUI application as a separate process
                var startInfo = new ProcessStartInfo
                {
                    FileName = guiPath,
                    UseShellExecute = true
                };

                Process.Start(startInfo);
                Console.WriteLine($"Launching GUI: {guiExeName}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"Error launching GUI: {ex.Message}");
                Console.ResetColor();
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
            if (args.Length == 1)
            {
                HelpSystem.ShowGeneralHelp();
                return 0;
            }

            var command = args[1].ToLowerInvariant();
            HelpSystem.ShowCommandHelp(command);
            return 0;
        }

        private static int HandleVersionCommand()
        {
            var version = typeof(Program).Assembly.GetName().Version;
            Console.WriteLine($"ColDog Locker v{version}");
            return 0;
        }

        private static int HandleUnknownCommand(string command)
        {
            Console.Error.WriteLine($"Error: Unknown command '{command}'");
            Console.WriteLine();
            HelpSystem.ShowGeneralHelp();
            return 1;
        }

        #endregion
    }
}

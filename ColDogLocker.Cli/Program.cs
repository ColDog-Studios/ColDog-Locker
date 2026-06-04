/*
**  Copyright (C) 2026 ColDog Studios
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  long with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Cli.Commands;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Logging;
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
                        "update" => UpdateCommands.Update(args),
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
            return GuiLauncher.Launch(Array.Empty<string>());
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
                CommandHelp.ShowGeneralHelp();
                return 0;
            }

            var command = args[1].ToLowerInvariant();
            CommandHelp.ShowCommandHelp(command);
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

            Console.WriteLine($"\nLocal Config Location: {AppPaths.LocalConfig}");
            Console.WriteLine($"Current Directory: {AppPaths.CdlDir}");
            var logPath = Path.Join(AppPaths.LocalConfig, "logs");
            Console.WriteLine($"Log Directory: {logPath}");
            Console.WriteLine($"Log Directory Exists: {Directory.Exists(logPath)}");

            var configDrive = new DriveInfo(new DirectoryInfo(AppPaths.LocalConfig).Root.Name);
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
            CommandHelp.ShowGeneralHelp();
            return 1;
        }

        #endregion
    }
}

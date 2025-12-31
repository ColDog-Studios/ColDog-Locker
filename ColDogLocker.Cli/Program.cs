using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Cli.Commands;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;

namespace ColDogStudios.ColDogLocker.Cli;

class Program
{
    static int Main(string[] args)
    {
        System.Console.WriteLine();

        try
        {
            // Initialize application for CLI commands (except for UI launchers)
            if (args.Length > 0 && args[0].ToLowerInvariant() is not "gui" and not "terminal" and not "tui")
            {
                InitializeForCli();
            }

            // No arguments - show help
            if (args.Length == 0)
            {
                return HandleHelpCommand(args);
            }

            // Parse the first argument as the command/subcommand
            var command = args[0].ToLowerInvariant();

            return command switch
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
        catch (Exception ex)
        {
            System.Console.ForegroundColor = ConsoleColor.Red;
            System.Console.Error.WriteLine($"Error: {ex.Message}");
            System.Console.ResetColor();
            return 1;
        }
    }

    static void InitializeForCli()
    {
        // Create directories if needed
        if (!Directory.Exists(Variables.localConfig))
        {
            Directory.CreateDirectory(Variables.localConfig);
        }

        // Initialize database and migrate from JSON if needed
        ColDogStudios.ColDogLocker.Infrastructure.Data.LockerRepository.InitializeDatabase();
        ColDogStudios.ColDogLocker.Infrastructure.Data.LockerRepository.MigrateFromJson();

        // Load settings and lockers (minimal initialization for CLI)
        SettingsManager.LoadSettings();
        LockerService.LoadLockers();
    }

    #region UI Launchers

    static int LaunchGui()
    {
        return ColDogStudios.ColDogLocker.Gui.GuiLauncher.Launch();
    }

    static int LaunchTui()
    {
        return ColDogStudios.ColDogLocker.Tui.TuiLauncher.Launch();
    }

    #endregion

    #region Simple Command Handlers

    static int HandleHelpCommand(string[] args)
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

    static int HandleVersionCommand()
    {
        var version = typeof(Program).Assembly.GetName().Version;
        System.Console.WriteLine($"ColDog Locker v{version}");
        return 0;
    }

    static int HandleUnknownCommand(string command)
    {
        System.Console.Error.WriteLine($"Error: Unknown command '{command}'");
        System.Console.WriteLine();
        HelpSystem.ShowGeneralHelp();
        return 1;
    }

    #endregion
}

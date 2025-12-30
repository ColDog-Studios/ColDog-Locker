namespace ColDogLocker.Cli;

class Program
{
    static int Main(string[] args)
    {
        try
        {
            // No arguments - launch GUI (default behavior)
            if (args.Length == 0)
            {
                //return LaunchGui(); // This is what I want eventually, but use TUI until the GUI is built.
                return LaunchTui();
            }

            // Parse the first argument as the command/subcommand
            var command = args[0].ToLowerInvariant();

            return command switch
            {
                "gui" => LaunchGui(),
                "terminal" or "tui" => LaunchTui(),
                "new" => HandleNewCommand(args),
                "remove" => HandleRemoveCommand(args),
                "lock" => HandleLockCommand(args),
                "unlock" => HandleUnlockCommand(args),
                "list" => HandleListCommand(args),
                "status" => HandleStatusCommand(args),
                "help" => HandleHelpCommand(args),
                "--version" or "-v" => HandleVersionCommand(),
                _ => HandleUnknownCommand(command)
            };
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine($"Error: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    #region UI Launchers

    static int LaunchGui()
    {
        return ColDogLocker.Gui.GuiLauncher.Launch();
    }

    static int LaunchTui()
    {
        return ColDogLocker.Tui.TuiLauncher.Launch();
    }

    #endregion

    #region Command Handlers

    static int HandleNewCommand(string[] args)
    {
        // TODO: Create new locker
        // Usage: ColDogLocker.exe new <Locker Name> [--path "D:\Lockers"]
        Console.WriteLine("[NEW] Creating new locker...");
        
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker new <Locker Name> [--path <path>]");
            return 1;
        }

        var lockerName = args[1];
        string? customPath = null;

        // Parse optional --path parameter
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i] == "--path" && i + 1 < args.Length)
            {
                customPath = args[i + 1];
                break;
            }
        }

        Console.WriteLine($"Locker Name: {lockerName}");
        if (customPath != null)
            Console.WriteLine($"Custom Path: {customPath}");

        Console.WriteLine("(Implementation pending)");
        return 0;
    }

    static int HandleRemoveCommand(string[] args)
    {
        // TODO: Remove locker
        // Usage: ColDogLocker.exe remove <Locker Name> [--force]
        Console.WriteLine("[REMOVE] Removing locker...");

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker remove <Locker Name> [--force]");
            return 1;
        }

        var lockerName = args[1];
        var force = args.Contains("--force");

        Console.WriteLine($"Locker Name: {lockerName}");
        Console.WriteLine($"Force: {force}");
        
        if (!force)
        {
            Console.WriteLine("(Would prompt for confirmation)");
        }

        Console.WriteLine("(Implementation pending)");
        return 0;
    }

    static int HandleLockCommand(string[] args)
    {
        // TODO: Lock a locker
        // Usage: ColDogLocker.exe lock <Locker Name> [--password <pass>]
        Console.WriteLine("[LOCK] Locking locker...");

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker lock <Locker Name> [--password <password>]");
            return 1;
        }

        var lockerName = args[1];
        string? password = null;

        // Parse optional --password parameter
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i] == "--password" && i + 1 < args.Length)
            {
                password = args[i + 1];
                break;
            }
        }

        Console.WriteLine($"Locker Name: {lockerName}");
        if (password != null)
        {
            Console.WriteLine("Password: (provided via --password flag)");
        }
        else
        {
            Console.WriteLine("(Would prompt for password securely)");
        }

        Console.WriteLine("(Implementation pending)");
        return 0;
    }

    static int HandleUnlockCommand(string[] args)
    {
        // TODO: Unlock a locker
        // Usage: ColDogLocker.exe unlock <Locker Name> [--password <pass>]
        Console.WriteLine("[UNLOCK] Unlocking locker...");

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker unlock <Locker Name> [--password <password>]");
            return 1;
        }

        var lockerName = args[1];
        string? password = null;

        // Parse optional --password parameter
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i] == "--password" && i + 1 < args.Length)
            {
                password = args[i + 1];
                break;
            }
        }

        Console.WriteLine($"Locker Name: {lockerName}");
        if (password != null)
        {
            Console.WriteLine("Password: (provided via --password flag)");
        }
        else
        {
            Console.WriteLine("(Would prompt for password securely)");
        }

        Console.WriteLine("(Implementation pending)");
        return 0;
    }

    static int HandleListCommand(string[] args)
    {
        // TODO: List all lockers and their status
        // Usage: ColDogLocker.exe list
        Console.WriteLine("[LIST] Listing all lockers...");
        Console.WriteLine("(Implementation pending)");
        return 0;
    }

    static int HandleStatusCommand(string[] args)
    {
        // TODO: Show detailed status of a locker
        // Usage: ColDogLocker.exe status <Locker Name>
        Console.WriteLine("[STATUS] Showing locker status...");

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Error: Locker name is required.");
            Console.WriteLine("Usage: ColDogLocker status <Locker Name>");
            return 1;
        }

        var lockerName = args[1];
        Console.WriteLine($"Locker Name: {lockerName}");
        Console.WriteLine("(Implementation pending)");
        return 0;
    }

    static int HandleHelpCommand(string[] args)
    {
        // TODO: Show help for specific command or general help
        // Usage: ColDogLocker.exe help [command]
        
        if (args.Length > 1)
        {
            var helpCommand = args[1].ToLowerInvariant();
            ShowCommandHelp(helpCommand);
        }
        else
        {
            ShowGeneralHelp();
        }

        return 0;
    }

    static int HandleVersionCommand()
    {
        Console.WriteLine($"ColDog Locker v{BuildInfo.Version}");
        Console.WriteLine("A secure file locker application");
        Console.WriteLine("Copyright © 2025 ColDog Studios");
        Console.WriteLine($"Build: {BuildInfo.BuildVersion}");
        Console.WriteLine($"Built: {BuildInfo.BuildDate} at {BuildInfo.BuildTime}");
        return 0;
    }

    static int HandleUnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        Console.WriteLine("Type 'ColDogLocker help' for usage information.");
        return 1;
    }

    #endregion

    #region Help System

    static void ShowGeneralHelp()
    {
        Console.WriteLine("ColDogLocker - Secure File Locker");
        Console.WriteLine();
        Console.WriteLine("USAGE:");
        Console.WriteLine("  ColDogLocker                           Launch GUI (default)");
        Console.WriteLine("  ColDogLocker gui                       Launch GUI explicitly");
        Console.WriteLine("  ColDogLocker terminal                  Launch Terminal UI");
        Console.WriteLine();
        Console.WriteLine("COMMANDS:");
        Console.WriteLine("  new <name> [--path <path>]             Create a new locker");
        Console.WriteLine("  remove <name> [--force]                Remove a locker");
        Console.WriteLine("  lock <name> [--password <pass>]        Lock a locker");
        Console.WriteLine("  unlock <name> [--password <pass>]      Unlock a locker");
        Console.WriteLine("  list                                   List all lockers");
        Console.WriteLine("  status <name>                          Show locker status");
        Console.WriteLine("  help [command]                         Show help information");
        Console.WriteLine("  --version, -v                          Show version information");
        Console.WriteLine();
        Console.WriteLine("For more information on a specific command, use:");
        Console.WriteLine("  ColDogLocker help <command>");
    }

    static void ShowCommandHelp(string command)
    {
        Console.WriteLine($"Help for command: {command}");
        Console.WriteLine();

        switch (command)
        {
            case "new":
                Console.WriteLine("CREATE NEW LOCKER:");
                Console.WriteLine("  ColDogLocker new <Locker Name> [--path <path>]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Creates a new locker with the specified name.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --path <path>    Specify a custom path for the locker");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker new MyLocker");
                Console.WriteLine("  ColDogLocker new MyLocker --path \"D:\\Lockers\"");
                break;

            case "remove":
                Console.WriteLine("REMOVE LOCKER:");
                Console.WriteLine("  ColDogLocker remove <Locker Name> [--force]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Removes the specified locker. Prompts for confirmation unless --force is used.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --force    Skip confirmation prompt");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker remove MyLocker");
                Console.WriteLine("  ColDogLocker remove MyLocker --force");
                break;

            case "lock":
                Console.WriteLine("LOCK LOCKER:");
                Console.WriteLine("  ColDogLocker lock <Locker Name> [--password <password>]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Locks the specified locker. Prompts for password unless provided.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --password <password>    Provide password (for automation, use cautiously)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker lock MyLocker");
                Console.WriteLine("  ColDogLocker lock MyLocker --password MySecurePass123");
                break;

            case "unlock":
                Console.WriteLine("UNLOCK LOCKER:");
                Console.WriteLine("  ColDogLocker unlock <Locker Name> [--password <password>]");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Unlocks the specified locker. Prompts for password unless provided.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  --password <password>    Provide password (for automation, use cautiously)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker unlock MyLocker");
                Console.WriteLine("  ColDogLocker unlock MyLocker --password MySecurePass123");
                break;

            case "list":
                Console.WriteLine("LIST LOCKERS:");
                Console.WriteLine("  ColDogLocker list");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Lists all lockers and their current status.");
                break;

            case "status":
                Console.WriteLine("SHOW LOCKER STATUS:");
                Console.WriteLine("  ColDogLocker status <Locker Name>");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Shows detailed status information for the specified locker.");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  ColDogLocker status MyLocker");
                break;

            case "gui":
                Console.WriteLine("LAUNCH GUI:");
                Console.WriteLine("  ColDogLocker gui");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Launches the graphical user interface.");
                break;

            case "terminal":
            case "tui":
                Console.WriteLine("LAUNCH TERMINAL UI:");
                Console.WriteLine("  ColDogLocker terminal");
                Console.WriteLine();
                Console.WriteLine("DESCRIPTION:");
                Console.WriteLine("  Launches the terminal-based user interface.");
                break;

            default:
                Console.WriteLine($"No help available for command: {command}");
                Console.WriteLine();
                Console.WriteLine("Available commands: new, remove, lock, unlock, list, status, gui, terminal");
                break;
        }
    }

    #endregion
}

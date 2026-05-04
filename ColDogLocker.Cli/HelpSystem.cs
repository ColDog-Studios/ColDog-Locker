namespace ColDogStudios.ColDogLocker.Cli
{
    /// <summary>
    /// Provides help information for CLI commands.
    /// </summary>
    public static class HelpSystem
    {
        public static void ShowGeneralHelp()
        {
            Console.WriteLine("USAGE:");
            Console.WriteLine("  cdlocker                           Launch GUI (default)");
            Console.WriteLine("  cdlocker gui                       Launch GUI explicitly");
            Console.WriteLine("  cdlocker terminal                  Launch Terminal UI");
            Console.WriteLine();

            Console.WriteLine("LOCKER COMMANDS:");
            Console.WriteLine("  new <name> [options]                   Create a new locker");
            Console.WriteLine("    --path <path>                        Custom directory path");
            Console.WriteLine("    --password <pass>                    Password (insecure, for automation)");
            Console.WriteLine("  remove <name> [options]                Remove a locker");
            Console.WriteLine("    --force                              Skip confirmation prompt");
            Console.WriteLine("    --delete                             Also delete directory and contents");
            Console.WriteLine("  lock <name> [--password <pass>]        Lock a locker");
            Console.WriteLine("  unlock <name> [--password <pass>]      Unlock a locker");
            Console.WriteLine("  list [--locked|--unlocked]             List all lockers");
            Console.WriteLine("  status <name>                          Show locker status");
            Console.WriteLine();

            Console.WriteLine("LOCKER MANAGEMENT:");
            Console.WriteLine("  change-password <name>                 Change locker password");
            Console.WriteLine("  verify <name>                          Verify locker integrity");
            Console.WriteLine();

            Console.WriteLine("SETTINGS & DATABASE:");
            Console.WriteLine("  settings [set <key> <value>]           View or modify settings");
            Console.WriteLine("  db-vacuum                              Optimize database");
            Console.WriteLine("  db-info                                Show database information");
            Console.WriteLine();

            Console.WriteLine("OTHER:");
            Console.WriteLine("  help [command]                         Show help information");
            Console.WriteLine("  --version, -v                          Show version information");
            Console.WriteLine();
            Console.WriteLine("For more information on a specific command, use:");
            Console.WriteLine("  cdlocker help <command>");
        }

        public static void ShowCommandHelp(string command)
        {
            Console.WriteLine($"Help for command: {command}");
            Console.WriteLine();

            switch (command)
            {
                case "new":
                    Console.WriteLine("CREATE NEW LOCKER:");
                    Console.WriteLine("  cdlocker new <Locker Name> [--path <path>]");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Creates a new locker with the specified name.");
                    Console.WriteLine();
                    Console.WriteLine("OPTIONS:");
                    Console.WriteLine("  --path <path>    Specify a custom path for the locker");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker new MyLocker");
                    Console.WriteLine("  cdlocker new MyLocker --path \"D:\\Lockers\"");
                    break;

                case "remove":
                    Console.WriteLine("REMOVE LOCKER:");
                    Console.WriteLine("  cdlocker remove <Locker Name> [--force]");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Removes the specified locker. Prompts for confirmation unless --force is used.");
                    Console.WriteLine();
                    Console.WriteLine("OPTIONS:");
                    Console.WriteLine("  --force    Skip confirmation prompt");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker remove MyLocker");
                    Console.WriteLine("  cdlocker remove MyLocker --force");
                    break;

                case "lock":
                    Console.WriteLine("LOCK LOCKER:");
                    Console.WriteLine("  cdlocker lock <Locker Name> [--password <password>]");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Locks the specified locker. Prompts for password unless provided.");
                    Console.WriteLine();
                    Console.WriteLine("OPTIONS:");
                    Console.WriteLine("  --password <password>    Provide password (for automation, use cautiously)");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker lock MyLocker");
                    Console.WriteLine("  cdlocker lock MyLocker --password MySecurePass123");
                    break;

                case "unlock":
                    Console.WriteLine("UNLOCK LOCKER:");
                    Console.WriteLine("  cdlocker unlock <Locker Name> [--password <password>]");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Unlocks the specified locker. Prompts for password unless provided.");
                    Console.WriteLine();
                    Console.WriteLine("OPTIONS:");
                    Console.WriteLine("  --password <password>    Provide password (for automation, use cautiously)");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker unlock MyLocker");
                    Console.WriteLine("  cdlocker unlock MyLocker --password MySecurePass123");
                    break;

                case "list":
                    Console.WriteLine("LIST LOCKERS:");
                    Console.WriteLine("  cdlocker list [--locked | --unlocked]");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Lists all lockers and their current status.");
                    Console.WriteLine();
                    Console.WriteLine("OPTIONS:");
                    Console.WriteLine("  --locked      Show only locked lockers");
                    Console.WriteLine("  --unlocked    Show only unlocked lockers");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker list");
                    Console.WriteLine("  cdlocker list --locked");
                    Console.WriteLine("  cdlocker list --unlocked");
                    break;

                case "change-password":
                    Console.WriteLine("CHANGE LOCKER PASSWORD:");
                    Console.WriteLine("  cdlocker change-password <Locker Name>");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Changes the password for an existing locker. The locker must be unlocked");
                    Console.WriteLine("  to change its password. You will be prompted to enter the current password");
                    Console.WriteLine("  for verification, then provide a new password that meets security requirements.");
                    Console.WriteLine();
                    Console.WriteLine("REQUIREMENTS:");
                    Console.WriteLine("  - Locker must be unlocked");
                    Console.WriteLine("  - Must provide correct current password");
                    Console.WriteLine("  - New password must meet requirements (8+ characters, uppercase, lowercase, digit, special char)");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker change-password MyLocker");
                    break;

                case "verify":
                    Console.WriteLine("VERIFY LOCKER:");
                    Console.WriteLine("  cdlocker verify <Locker Name>");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Verifies the integrity and consistency of a locker by performing");
                    Console.WriteLine("  multiple checks on the directory structure and attributes.");
                    Console.WriteLine();
                    Console.WriteLine("CHECKS PERFORMED:");
                    Console.WriteLine("  - Directory existence");
                    Console.WriteLine("  - Directory access permissions");
                    Console.WriteLine("  - Hidden/System attributes match lock state");
                    Console.WriteLine("  - File and folder counts");
                    Console.WriteLine();
                    Console.WriteLine("OUTPUT:");
                    Console.WriteLine("  [OK]   - Check passed");
                    Console.WriteLine("  [FAIL] - Critical error found");
                    Console.WriteLine("  [!]    - Warning or inconsistency detected");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker verify MyLocker");
                    break;

                case "settings":
                    Console.WriteLine("MANAGE SETTINGS:");
                    Console.WriteLine("  cdlocker settings [<key> [<value>]]");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  View or modify application settings. Call without arguments to view all");
                    Console.WriteLine("  settings, with a key to view a specific setting, or with key and value");
                    Console.WriteLine("  to update a setting.");
                    Console.WriteLine();
                    Console.WriteLine("AVAILABLE SETTINGS:");
                    Console.WriteLine("  debug                 Enable/disable debug mode (true/false)");
                    Console.WriteLine("  log-retention         Days to keep log files (1-3650)");
                    Console.WriteLine("  auto-update           Enable/disable auto-updates (true/false)");
                    Console.WriteLine("  update-channel        Update channel (stable/prerelease)");
                    Console.WriteLine("  db-vacuum-interval    Days between database optimizations (0=disabled, 1-365)");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker settings");
                    Console.WriteLine("  cdlocker settings debug true");
                    Console.WriteLine("  cdlocker settings log-retention 60");
                    Console.WriteLine("  cdlocker settings auto-update true");
                    Console.WriteLine("  cdlocker settings update-channel stable");
                    Console.WriteLine("  cdlocker settings db-vacuum-interval 30");
                    break;

                case "db-vacuum":
                    Console.WriteLine("VACUUM DATABASE:");
                    Console.WriteLine("  cdlocker db-vacuum");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Optimizes the database by reclaiming unused space and rebuilding");
                    Console.WriteLine("  internal structures. This is useful after deleting many lockers or");
                    Console.WriteLine("  when the database file seems larger than expected.");
                    Console.WriteLine();
                    Console.WriteLine("NOTES:");
                    Console.WriteLine("  - Briefly locks the database during optimization");
                    Console.WriteLine("  - Updates LastDatabaseVacuum timestamp in settings");
                    Console.WriteLine("  - Reports bytes reclaimed after completion");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker db-vacuum");
                    break;

                case "db-info":
                    Console.WriteLine("DATABASE INFORMATION:");
                    Console.WriteLine("  cdlocker db-info");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Displays detailed information about the SQLite database including");
                    Console.WriteLine("  size, locker count, SQLite version, and integrity status.");
                    Console.WriteLine();
                    Console.WriteLine("INFORMATION DISPLAYED:");
                    Console.WriteLine("  - Database file path");
                    Console.WriteLine("  - Database file size");
                    Console.WriteLine("  - Total number of lockers");
                    Console.WriteLine("  - SQLite version");
                    Console.WriteLine("  - Database integrity check status");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker db-info");
                    break;

                case "status":
                    Console.WriteLine("SHOW LOCKER STATUS:");
                    Console.WriteLine("  cdlocker status <Locker Name>");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Shows detailed status information for the specified locker.");
                    Console.WriteLine();
                    Console.WriteLine("EXAMPLES:");
                    Console.WriteLine("  cdlocker status MyLocker");
                    break;

                case "gui":
                    Console.WriteLine("LAUNCH GUI:");
                    Console.WriteLine("  cdlocker gui");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Launches the graphical user interface.");
                    break;

                case "terminal":
                case "tui":
                    Console.WriteLine("LAUNCH TERMINAL UI:");
                    Console.WriteLine("  cdlocker terminal");
                    Console.WriteLine();
                    Console.WriteLine("DESCRIPTION:");
                    Console.WriteLine("  Launches the terminal-based user interface.");
                    break;

                default:
                    Console.WriteLine($"No help available for command: {command}");
                    Console.WriteLine();
                    Console.WriteLine("Available commands: new, remove, lock, unlock, list, status, change-password, verify, settings, db-vacuum, db-info, gui, terminal");
                    break;
            }
        }
    }
}

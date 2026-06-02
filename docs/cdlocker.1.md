# cdlocker(1)

## NAME

`cdlocker` - manage encrypted ColDog Locker directories

## SYNOPSIS

```text
cdlocker
cdlocker gui
cdlocker tui
cdlocker terminal
cdlocker new <name> [--path <parent>] [--password <password>]
cdlocker lock <name> [--password <password>]
cdlocker unlock <name> [--password <password>]
cdlocker list [--locked | --unlocked]
cdlocker status <name>
cdlocker verify <name>
cdlocker change-password <name>
cdlocker remove <name> [--force] [--delete]
cdlocker settings [<key> [<value>]]
cdlocker db-info
cdlocker db-vacuum
cdlocker update [--download] [--notes]
cdlocker help [command]
cdlocker --version
```

## DESCRIPTION

`cdlocker` creates and manages password-protected locker directories. A locker is stored as a normal directory when unlocked. Locking verifies the locker password, encrypts all files recursively, renames the directory with a leading dot, marks it hidden/system where supported, and updates the local locker database. Unlocking reverses that operation.

Locker metadata is stored in a per-user SQLite database. Settings and logs are stored under the per-user local app data directory.

## COMMANDS

`gui`
: Launch the graphical interface.

`tui`, `terminal`
: Launch the terminal user interface.

`new <name>`
: Create a locker. Use `--path <parent>` to choose the parent directory. Use `--password <password>` for automation.

`lock <name>`
: Encrypt and hide a locker. Prompts for a password unless `--password` is supplied.

`unlock <name>`
: Decrypt and unhide a locker. Prompts for a password unless `--password` is supplied.

`list`
: Print all lockers. Use `--locked` or `--unlocked` to filter.

`status <name>`
: Print state, path, GUID, timestamps, and content counts.

`verify <name>`
: Check that the locker directory and metadata are consistent.

`change-password <name>`
: Change a locker password. The locker must be unlocked.

`remove <name>`
: Remove a locker from metadata. Use `--force` to skip confirmation. Use `--delete` to delete the directory contents too.

`settings [<key> [<value>]]`
: Show all settings, show one setting, or update one setting.

`db-info`
: Print SQLite database information.

`db-vacuum`
: Optimize the SQLite database.

`update`
: Check for releases. Use `--notes` to print release notes and `--download` to download a matching installer.

`help [command]`
: Show help.

`--version`, `-v`
: Show version and build information.

## OPTIONS

`--path <parent>`
: Parent directory for a new locker. The locker directory is created as `<parent>/<name>`.

`--password <password>`
: Supply a password on the command line. This is useful for automation but can expose secrets through shell history, scripts, logs, or process listings.

`--locked`
: Show only locked lockers in `list`.

`--unlocked`
: Show only unlocked lockers in `list`.

`--force`
: Skip removal confirmation.

`--delete`
: Delete the locker directory when removing the locker.

`--notes`
: Print update release notes when available.

`--download`
: Download and verify a matching update installer when available.

## FILES

`%LOCALAPPDATA%\ColDog Studios\ColDog Locker\settings.json`
: Application settings.

`%LOCALAPPDATA%\ColDog Studios\ColDog Locker\lockers.db`
: Locker metadata database.

`%LOCALAPPDATA%\ColDog Studios\ColDog Locker\logs\`
: Application logs.

`%USERPROFILE%\Documents\ColDog Locker\`
: Default parent location for new lockers on Windows.

## EXIT STATUS

`0`
: Success.

`1`
: Error.

`2`
: Update available but no downloadable installer is available for the current platform.

## EXAMPLES

```bash
cdlocker new MyLocker
cdlocker new Taxes --path "D:\Private"
cdlocker lock MyLocker
cdlocker unlock MyLocker
cdlocker list --locked
cdlocker verify MyLocker
cdlocker settings update-channel stable
cdlocker update --notes
```

## SECURITY NOTES

Use strong, unique passwords and keep backups. ColDog Locker cannot recover forgotten passwords. Avoid `--password` for interactive use. System paths, drive roots, profile roots, and top-level user folders are blocked from becoming lockers.

## SEE ALSO

[How to Use ColDog Locker](how-to-use.md), [CLI Reference](cli-reference.md), [Security Features](security-features.md)

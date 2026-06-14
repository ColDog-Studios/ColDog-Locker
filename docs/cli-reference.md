# CLI Reference

The CLI executable is `cdlocker.exe` on Windows and `cdlocker` on Linux/macOS. When running from source, use:

```bash
dotnet run --project ColDogLocker.Cli -- <command>
```

## Exit Codes

- `0`: command completed successfully, or there was no work to do.
- `1`: command failed.
- `2`: `update` found an update but no downloadable installer was available for the current platform.

## Interfaces

### `cdlocker`

Shows general help.

### `cdlocker gui`

Launches the graphical interface.

Current behavior:

- Windows launches the Avalonia GUI executable, `ColDogLocker.exe`.
- Linux attempts to launch the Avalonia GUI executable, `ColDogLocker`.
- macOS reports that GUI launching is not available yet and suggests the TUI.

### `cdlocker tui`

Launches the terminal user interface.

Alias:

```bash
cdlocker terminal
```

## Locker Commands

### `cdlocker new <name> [--path <parent>] [--password <password>]`

Creates a new locker.

Options:

- `--path <parent>`: create the locker under this parent directory.
- `--password <password>`: provide the password non-interactively.

Notes:

- `<name>` must be a relative locker name, not an absolute path.
- With `--path "D:\Private"` and name `Taxes`, the created locker path is `D:\Private\Taxes`.
- If `--path` is omitted, the locker is created under the default ColDog Locker documents directory.
- Passwords must meet the active password rules.

Examples:

```bash
cdlocker new MyLocker
cdlocker new Taxes --path "D:\Private"
cdlocker new BuildSecrets --password "Use-A-Strong-Password-123!"
```

### `cdlocker lock <name> [--password <password>]`

Locks a locker by verifying the password, renaming the directory with a leading dot, encrypting files recursively, setting hidden/system attributes, and updating locker metadata.

If the locker is already locked, the command exits successfully without changing it.

Example:

```bash
cdlocker lock MyLocker
```

### `cdlocker unlock <name> [--password <password>]`

Unlocks a locker by verifying the password, renaming the directory back to the locker name, decrypting files recursively, clearing hidden/system attributes, and updating locker metadata.

If the locker is already unlocked, the command exits successfully without changing it.

Example:

```bash
cdlocker unlock MyLocker
```

### `cdlocker list [--locked | --unlocked]`

Lists known lockers, their state, and their filesystem location.

Examples:

```bash
cdlocker list
cdlocker list --locked
cdlocker list --unlocked
```

### `cdlocker status <name>`

Shows the lock state, location, GUID, timestamps, and content counts for one locker.

Example:

```bash
cdlocker status MyLocker
```

### `cdlocker verify <name>`

Checks the locker directory and metadata for consistency.

Checks include:

- Directory exists.
- Directory can be accessed.
- Locked lockers are hidden/system and have a leading dot.
- Unlocked lockers are not hidden/system and do not have a leading dot.
- File and folder counts can be read.

Example:

```bash
cdlocker verify MyLocker
```

### `cdlocker change-password <name> [--old-password <password> --new-password <password>]`

Changes a locker's password.

Requirements:

- The locker must be unlocked.
- The current password must be provided correctly.
- The new password must meet the active password rules.

Options:

- `--old-password <password>`: provide the current password non-interactively.
- `--new-password <password>`: provide the replacement password non-interactively.

If either password option is supplied, both are required. Prefer the interactive prompt for normal use because command-line passwords can be exposed through shell history, scripts, logs, or process listings.

Example:

```bash
cdlocker change-password MyLocker
cdlocker change-password MyLocker --old-password "Old-Strong-Password-123!" --new-password "New-Strong-Password-123!"
```

### `cdlocker remove <name> [--force] [--delete]`

Removes a locker from ColDog Locker metadata.

Options:

- `--force`: skip the confirmation prompt.
- `--delete`: also delete the locker directory and its contents.

Notes:

- Locked lockers cannot be removed.
- Without `--delete`, the folder remains on disk.

Examples:

```bash
cdlocker remove MyLocker
cdlocker remove MyLocker --force
cdlocker remove MyLocker --force --delete
```

## Settings Commands

### `cdlocker settings`

Prints all current settings.

### `cdlocker settings <key>`

Prints one setting.

### `cdlocker settings <key> <value>`

Updates one setting.

Supported keys:

| Key | Values |
| --- | --- |
| `debug` | `true`, `false` |
| `log-level` | logger level name |
| `log-format` | logger format string/name |
| `max-file-size` | positive integer, MB |
| `file-logging` | `true`, `false` |
| `auto-update` | `true`, `false` |
| `update-channel` | `stable`, `s`, `unstable`, `u`, `prerelease`, `pre`, `p` |
| `db-vacuum-interval` | integer from `0` to `365`; `0` disables automatic interval tracking |

Examples:

```bash
cdlocker settings
cdlocker settings auto-update true
cdlocker settings update-channel unstable
cdlocker settings db-vacuum-interval 30
```

## Database Commands

### `cdlocker db-info`

Shows SQLite database path, existence, size, creation and modification timestamps, locker count, SQLite version, and integrity status.

### `cdlocker db-vacuum`

Runs SQLite `VACUUM`, updates the last-vacuum timestamp in settings, and reports reclaimed bytes.

## Update Commands

### `cdlocker update [--download]`

Checks GitHub Releases for an update matching the configured channel and current platform.

Options:

- `--download`: download and verify a matching installer package when available.

Release notes are printed automatically when available.

The command downloads the installer only. It does not install the update automatically.

## Other Commands

### `cdlocker help [command]`

Shows general help or command-specific help.

### `cdlocker --version`

Shows semantic version, build version, assembly version, build date, and build time.

Alias:

```bash
cdlocker -v
```

### `cdlocker dev`

Prints diagnostic environment information, including OS, architecture, runtime identifier, framework, local config location, current directory, log directory status, available disk space, and process memory.

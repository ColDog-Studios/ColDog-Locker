# How to Use ColDog Locker

ColDog Locker manages directories called lockers. A locker is an ordinary folder while it is unlocked. When you lock it, ColDog Locker creates an encrypted archive, removes the original plaintext folder, and publishes the archive in a folder with a leading dot. It marks that folder hidden/system where the platform supports those attributes.

> Important: There is no password recovery. If you forget a locker password, ColDog Locker cannot decrypt the files.

## Choose an Interface

ColDog Locker currently has three user-facing interfaces:

- **Avalonia GUI**: `cdlocker gui`
- **Terminal UI**: `cdlocker tui`
- **CLI commands**: `cdlocker <command> ...`

Running `cdlocker` with no arguments currently shows command help. Use `cdlocker gui` when you want the graphical interface.

## Build and Run from Source

Prerequisite:

```bash
dotnet --version
```

Install the exact .NET SDK version in the repository’s `global.json` (currently `10.0.112`); SDK roll-forward is disabled.

Build everything:

```bash
dotnet restore --locked-mode
dotnet build
```

Run the CLI:

```bash
dotnet run --project ColDogLocker.Cli -- help
```

Run the TUI:

```bash
dotnet run --project ColDogLocker.Cli -- tui
```

Run the GUI launcher:

```bash
dotnet run --project ColDogLocker.Cli -- gui
```

## Create a Locker

Create a locker in the default ColDog Locker documents directory:

```bash
cdlocker new MyLocker
```

By default, lockers are created under:

- Windows: `%USERPROFILE%\Documents\ColDog Locker`
- Linux/macOS: the platform's documents folder as reported by .NET, under `ColDog Locker`; if unavailable, the user profile is used

Create a locker under a specific parent directory:

```bash
cdlocker new Taxes --path "D:\Private"
```

This creates `D:\Private\Taxes`. The `--path` value is the parent directory, not the final locker directory.

You can pass a password for automation:

```bash
cdlocker new MyLocker --password "River!Cobalt8Fern"
```

Prefer the interactive prompt for normal use. Shell history, scripts, logs, or process monitors may expose command-line passwords.

## Lock and Unlock

Keep an independent backup first. Close editors and other programs writing to the locker, and pause synchronization for that folder. Locking compares the exact archived contents with an atomically claimed source tree and aborts when it detects a create, overwrite, truncate, rename or deletion. A program that keeps a native writable file handle open across that cutover cannot be stopped portably, so closing writers is still required.

Lock a locker:

```bash
cdlocker lock MyLocker
```

Unlock a locker:

```bash
cdlocker unlock MyLocker
```

Both commands prompt for the locker password unless `--password <password>` is supplied.

## List and Inspect Lockers

List all lockers:

```bash
cdlocker list
```

Filter by state:

```bash
cdlocker list --locked
cdlocker list --unlocked
```

Show details for one locker:

```bash
cdlocker status MyLocker
```

Check whether the locker directory and metadata are consistent:

```bash
cdlocker verify MyLocker
```

## Change a Password

The locker must be unlocked before changing its password:

```bash
cdlocker unlock MyLocker
cdlocker change-password MyLocker
```

For automation, provide both the current and new password:

```bash
cdlocker change-password MyLocker --old-password "River!Cobalt8Fern" --new-password "Meadow7!CopperBirch"
```

These passwords are examples; choose your own unique password.

Prefer the interactive prompt for normal use. Shell history, scripts, logs, or process monitors may expose command-line passwords.

Files are decrypted while the locker is unlocked. Changing the password updates the stored password hash. The new password is used the next time the locker is locked.

## Remove a Locker

Remove only the locker registration:

```bash
cdlocker remove MyLocker
```

Remove without confirmation:

```bash
cdlocker remove MyLocker --force
```

Remove the registration and delete the directory contents:

```bash
cdlocker remove MyLocker --delete
```

Locked lockers cannot be removed. Unlock the locker first.

## Settings

Show all settings:

```bash
cdlocker settings
```

Show one setting:

```bash
cdlocker settings update-channel
```

Update a setting:

```bash
cdlocker settings auto-update true
cdlocker settings update-channel stable
```

Settings are stored as JSON under the per-user local app data directory.

## Backup and Recovery

Use [Backup and Recovery](backup-and-recovery.md) before collecting backups or resolving an interrupted operation. `db-backup` saves registration and recovery records; locker files must be backed up separately. After a failure, preserve every reported path and inspect `cdlocker recovery-list` before retrying.

## Database Maintenance

Show database information:

```bash
cdlocker db-info
```

Vacuum the SQLite database:

```bash
cdlocker db-vacuum
```

## Updates

Check for updates:

```bash
cdlocker update
```

Release notes are shown automatically when available.

Download, verify, and start a matching installer when one is available:

```bash
cdlocker update --download
```

Windows starts the installer after verification. Linux installs the verified `.deb` or `.rpm` package through the local package manager and may prompt for administrator approval through `pkexec` or `sudo`. Linux package updates remove the installed `coldog-locker` package first, then install the verified package. macOS downloads and verifies the matching `.pkg`, then opens it with Installer.

Windows and macOS packages are unsigned, so Windows SmartScreen or macOS Gatekeeper may display a warning.

## Data Locations

ColDog Locker stores application data per user:

- `settings.json`
- `lockers.db`
- `logs/`

Typical base locations are `%LOCALAPPDATA%\ColDog Studios\ColDog Locker` on Windows, `${XDG_DATA_HOME:-$HOME/.local/share}/ColDog Studios/ColDog Locker` on Linux, and `$HOME/Library/Application Support/ColDog Studios/ColDog Locker` on macOS. Run `cdlocker dev` to see the authoritative local configuration location for the current account. See [Platform and Storage Support](platform-support.md) for runtime and filesystem limits.

## Safe Locker Locations

Use a dedicated subdirectory, such as:

```text
Documents\ColDog Locker\MyLocker
Documents\SecureFiles
D:\Private\Taxes
```

Do not try to lock system folders, drive roots, profile roots, or top-level user folders like Documents or Desktop. ColDog Locker blocks these paths to reduce accidental damage and malicious use.

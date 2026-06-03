# How to Use ColDog Locker

ColDog Locker manages directories called lockers. A locker is an ordinary folder while it is unlocked. When you lock it, ColDog Locker encrypts the files inside it, renames the folder with a leading dot, and marks it hidden/system where the platform supports those attributes.

> Important: There is no password recovery. If you forget a locker password, ColDog Locker cannot decrypt the files.

## Choose an Interface

ColDog Locker currently has three user-facing interfaces:

- **Windows GUI**: `cdlocker gui`
- **Terminal UI**: `cdlocker tui` or `cdlocker terminal`
- **CLI commands**: `cdlocker <command> ...`

Running `cdlocker` with no arguments currently shows command help. Use `cdlocker gui` when you want the graphical interface.

## Build and Run from Source

Prerequisite:

```bash
dotnet --version
```

The repo targets .NET 10.

Build everything:

```bash
dotnet restore
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
- Linux/macOS: the platform's documents folder as reported by .NET, under `ColDog Locker`

Create a locker under a specific parent directory:

```bash
cdlocker new Taxes --path "D:\Private"
```

This creates `D:\Private\Taxes`. The `--path` value is the parent directory, not the final locker directory.

You can pass a password for automation:

```bash
cdlocker new MyLocker --password "Use-A-Strong-Password-123!"
```

Prefer the interactive prompt for normal use. Shell history, scripts, logs, or process monitors may expose command-line passwords.

## Lock and Unlock

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
cdlocker change-password MyLocker --old-password "Old-Strong-Password-123!" --new-password "New-Strong-Password-123!"
```

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

Show release notes when an update is available:

```bash
cdlocker update --notes
```

Download and verify a matching installer when one is available:

```bash
cdlocker update --download
```

Downloaded installers still need to be run manually.

## Data Locations

ColDog Locker stores application data per user:

- `settings.json`
- `lockers.db`
- `logs/`

The base location is:

```text
%LOCALAPPDATA%\ColDog Studios\ColDog Locker
```

On non-Windows platforms, the exact local app data root comes from .NET's `LocalApplicationData` special folder.

## Safe Locker Locations

Use a dedicated subdirectory, such as:

```text
Documents\ColDog Locker\MyLocker
Documents\SecureFiles
D:\Private\Taxes
```

Do not try to lock system folders, drive roots, profile roots, or top-level user folders like Documents or Desktop. ColDog Locker blocks these paths to reduce accidental damage and malicious use.

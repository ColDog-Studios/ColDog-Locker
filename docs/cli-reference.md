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
- macOS launches `/Applications/ColDog Locker.app` when installed from the PKG.

### `cdlocker tui`

Launches the terminal user interface.

## Locker Commands

### `cdlocker new <name> [--path <parent>] [--password <password>]`

Creates a new locker.

> [!WARNING]
> Prefer interactive prompts. Password arguments can appear in shell history, process listings, scripts and CI logs.

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
```

### `cdlocker lock <name> [--password <password>]`

Locks a locker by verifying the password, creating an encrypted archive, removing the plaintext source, publishing the locked directory, and updating metadata. If a failure occurs after source removal begins, the complete archive is retained and its recovery path is reported.

If the locker is already locked, the command exits successfully without changing it.

> [!WARNING]
> Prefer interactive prompts. Password arguments can appear in shell history, process listings, scripts and CI logs.

Example:

```bash
cdlocker lock MyLocker
```

### `cdlocker unlock <name> [--password <password>]`

Unlocks a locker by verifying the password, authenticating and extracting the archive into private staging, publishing the restored directory, and updating metadata.

If the locker is already unlocked, the command exits successfully without changing it.

> [!WARNING]
> Prefer interactive prompts. Password arguments can appear in shell history, process listings, scripts and CI logs.

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

Shows the lock state, location, GUID, timestamps, and content counts for one locker. If content inspection cannot complete, counts are shown as unavailable and the command returns a failure status.

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
- For locked lockers: archive header/registration agreement, stored SHA-256 agreement, and absence of unexpected entries beside `locker.cdl`.
- For unlocked lockers: absence of a leftover locked archive sibling.

This command does not take a password or authenticate encrypted contents. Hidden/system attributes are warnings and depend on the operating system. A matching stored hash does not establish authenticity if the database was also tampered with.

Content counting stops on unsafe links or unsupported entries, inaccessible paths, more than 200,000 entries, depth beyond 256, or a five-second traversal budget. An incomplete scan reports unavailable counts and makes verification fail. The budget is checked between filesystem calls; it cannot interrupt a stalled OS call and does not limit archive hashing. Counts are not a snapshot of a tree being changed by other programs.

Example:

```bash
cdlocker verify MyLocker
```

### `cdlocker change-password <name> [--old-password <password> --new-password <password>]`

Changes a locker's password.

> [!WARNING]
> Prefer interactive prompts. Password arguments can appear in shell history, process listings, scripts and CI logs.

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
cdlocker change-password MyLocker --old-password "River!Cobalt8Fern" --new-password "Meadow7!CopperBirch"
```

These passwords are examples; choose your own unique password.

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

- `--download`: download, verify, and start a matching installer package when available.

Release notes are printed automatically when available.

On Windows, the installer is launched after verification. On Linux, the verified `.deb` or `.rpm` package is installed through the local package manager and may prompt for administrator approval through `pkexec` or `sudo`. Linux package updates remove the installed `coldog-locker` package first, then install the verified package.

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

### `cdlocker recover <archive.cdl> <new-destination>`

Authenticate and restore a locker archive without loading the locker database. Use this when a failed lock reports a retained recovery archive, or when the database is unavailable. The original archive is kept. The destination must not already exist; recovery never merges into or overwrites surviving source files.

```bash
cdlocker recover "/path/to/retained/locker.cdl" "$HOME/RecoveredLocker"
```

Enter the original archive password at the prompt. `--password <password>` is available for automation, but exposes the password in command-line arguments. Recovery accepts archive format version 2 only; version 1 prerelease archives are unsupported. It restores files only; it does not register a locker or repair existing database records. Inspect the recovered files and keep the archive until you have an independent backup.

### `cdlocker recovery-list`

List recorded lock/unlock operations and their source, target, and staging paths. This is read-only. Records may describe an operation still running in another app window or process. If that process stopped unexpectedly, preserve every listed directory and archive. Further changes to that locker are blocked while the record remains.

Use `cdlocker recover <archive.cdl> <new-destination>` to extract a complete retained archive. A partially written archive may not be recoverable; during archive preparation, the original source has not yet been removed. Standalone `recover` does not clear the journal or repair registration. Use the recovery commands below for supported reconciliation cases; see [Backup and Recovery](backup-and-recovery.md) for the workflow.

### `cdlocker recovery-cancel <operation-id>`

Cancel an interrupted preparation listed by `recovery-list`. This only succeeds for lock preparation before source removal, or unlock preparation before publication readiness. The source must still exist, the target must be absent, and stored locker metadata must match the original snapshot. An active operation owned by another process cannot be cancelled this way.

No files are removed or modified. The pending record moves atomically to recovery history, retaining its source, target, and staging paths. Reload the locker before retrying. Operations that might have removed source files or published output are refused and still require verified recovery.

### `cdlocker recovery-history`

Show resolved operation records, retained source/target/staging paths, and recovery attempts. Cancellation preserves staging files, which may include an incomplete encrypted archive or partially extracted plaintext. Keep them until you have checked your original files and backups. The command does not delete or alter artifacts.

### `cdlocker recovery-finish <operation-id>`

Resolve a pending operation whose metadata was already committed. For a lock, this verifies the recorded archive hash and identity. For an unlock, this compares restored directory names and contents with the digest recorded before publication; the original archive need not still exist.

The command moves the pending record into recovery history and leaves all files untouched. It refuses incomplete operations, changed metadata, and missing or changed output. Retained archives or staging files are not automatically deleted. If verification fails, preserve the listed recovery artifacts while investigating.

### `cdlocker recovery-restore <operation-id> <archive.cdl> <new-destination>`

Recover a journaled operation using a retained archive and repair its locker registration. Select the operation with `recovery-list` and an archive at its recorded source (unlock) or staging/target (lock) path. The new destination must be separate from all those paths and must end with the original locker name.

```bash
cdlocker recovery-restore <operation-id> "/recorded/staging/locker.cdl" "$HOME/Recovered/MyLocker"
```

The command prompts for the archive password; `--password <password>` is available for automation. It checks archive identity, authenticates all contents, records the recovery attempt before writing plaintext, then updates registration and history transactionally. It never overwrites a destination or deletes original artifacts. Wrong passwords leave the operation pending. `recovery-history` lists successful and superseded recovery attempts and their paths.

Keep the retained archive until you have checked the recovered files and made an independent backup. Surviving original/staging plaintext is also retained: locking the recovered folder does not protect those other copies. For an operation at `MetadataCommitted`, `recovery-finish` can verify the committed output even if an unlocked operation’s archive was already removed. If it refuses changed output and no usable archive remains, preserve the output and recovery records; no automatic resolution is available. Do not delete database rows to bypass that state.

### `cdlocker db-backup <new-directory>`

Create an integrity-checked SQLite snapshot at `<new-directory>/lockers.db`. The parent directory must already exist; the destination must be new. The snapshot includes locker registrations, password verifiers, operation journals and recovery history. It uses private permissions and never overwrites an existing destination.

```bash
mkdir -p "$HOME/ColDogLockerBackups"
cdlocker db-backup "$HOME/ColDogLockerBackups/registry-2026-09-20"
```

This is a metadata backup, **not a backup of your files**. Save the locked `locker.cdl` archives separately, along with any recovery artifacts listed by `recovery-list` or `recovery-history`. Keep their original passwords. The database snapshot is internally consistent, but it does not freeze locker directories: avoid changing lockers while collecting the complete backup set. Database writes may pause briefly while the snapshot is copied.

The database backup contains names, paths and password verifiers; it is not encrypted. Store the backup set in a protected location. Do not replace a live database with an old snapshot: its recorded state may no longer match the folders. The database-independent `recover` command can restore an archive to a new directory without replacing current registration data.

### `cdlocker db-restore <backup-lockers.db>`

Restore a database snapshot when the current profile has **no registry and no SQLite sidecar files**. Close other ColDog Locker instances first. The command never replaces an existing database, including an empty one; do not delete a live database to bypass this check.

```bash
cdlocker db-restore "$HOME/ColDogLockerBackups/registry-2026-09-20/lockers.db"
cdlocker recovery-list
cdlocker list
```

The backup must use this application's current database schema. Restore checks database integrity, locker names and paths, and the recorded archive hashes for locked registrations. Ordinary registrations must still have their recorded folders. Pending operations retain their journals and continue to block ordinary mutations until recovery resolves them. The command changes no locker contents and preserves the input backup.

Restore uses the original paths; it does not relocate archives or prove that an unlocked folder still has its earlier contents. If paths have moved, an archive differs, or a current registry already exists, use `recover` to authenticate the archive into a new directory instead. Keep your original passwords: database restoration does not reset them.

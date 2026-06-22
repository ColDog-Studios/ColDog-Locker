# Architecture

ColDog Locker is a .NET 10 solution split into core domain code, shared services, and multiple user interfaces.

## Projects

| Project | Purpose |
| --- | --- |
| `ColDogLocker.Core` | Domain models, validation, path constants, and version helpers. |
| `ColDogLocker.Services` | Locker operations, SQLite persistence, encryption, settings, logging, file watching, updates, and startup initialization. |
| `ColDogLocker.Cli` | Main command-line entry point, command routing, TUI launcher, and Avalonia GUI launcher. |
| `ColDogLocker.Tui` | Terminal menu interface. |
| `ColDogLocker.Avalonia` | Active graphical interface and cross-platform GUI direction. |
| `ColDogLocker.Core.Tests` | Unit tests for core models, validators, and versioning. |
| `ColDogLocker.Services.Tests` | Unit tests for services, logging, locker filtering, updates, and encryption. |

## Dependency Flow

```text
Core
  ^
  |
Services
  ^
  |
+-----------+-----------+-----------+
|           |           |           |
Cli         Tui         Avalonia
```

The CLI references `Core`, `Services`, and `Tui`, and owns the GUI launcher used by `cdlocker gui`. The GUI implementations use `Core` and `Services` directly.

## Startup Flow

All CLI entry points run shared initialization before handling commands:

1. Load or create `settings.json`.
2. Configure logging from settings.
3. Ensure the per-user local config and `logs` directories exist.
4. Initialize the SQLite locker database.
5. Load lockers into memory.
6. Initialize file watchers for settings and locker data.
7. Check for updates if auto-update is enabled.

## Data Locations

Application data is stored per user under `AppPaths.LocalConfig`:

```text
%LOCALAPPDATA%\ColDog Studios\ColDog Locker
```

Contents include:

- `settings.json`
- `lockers.db`
- `logs/`

The default locker parent directory is `AppPaths.CdlDir`:

```text
%USERPROFILE%\Documents\ColDog Locker
```

## Locker Lifecycle

Creating a locker:

1. Validate the locker name and target path.
2. Reject protected paths.
3. Validate the password.
4. Hash the password with BCrypt.
5. Create the locker directory if needed.
6. Insert metadata into SQLite.

Locking a locker:

1. Revalidate the locker path.
2. Verify the supplied password against the stored BCrypt hash.
3. Stream the locker contents into an authenticated encrypted archive at `.<name>/locker.cdl`.
4. Store the archive SHA-256, storage format version, and locked timestamp in SQLite.
5. Remove the plaintext locker directory after the archive is created.
6. Mark the locked directory hidden/system where supported.
7. Update `IsLocked` and `LockerLocation` in SQLite.

Unlocking reverses the lock operation:

1. Verify the password.
2. Verify `locker.cdl` exists and its SHA-256 matches SQLite metadata.
3. Decrypt and authenticate the archive into a staging directory.
4. Replace `.<name>` with the restored `<name>` directory.
5. Clear locked archive metadata.
6. Update metadata.

Archive hardening rules:

- Do not use legacy ZIP encryption.
- Do not write a plaintext archive temp file.
- Reject source links/reparse points when locking.
- Reject archive entries with absolute paths, traversal segments, backslashes, drive/ADS colons, links, device entries, or other non-file/non-directory types.
- Enforce archive entry count, path length, and extracted byte limits during unlock.
- Treat mismatches between archive metadata, SQLite metadata, and the archive SHA-256 as corruption.

## Persistence

Locker metadata is stored in SQLite via `LockerRepository`.
In-memory locker state is owned by `LockerService`; UI and CLI callers should use service methods such as `GetLockersSnapshot`, `FindLockerByName`, `FindLockerByGuid`, `AddLocker`, `RemoveLocker`, `Lock`, and `Unlock` instead of mutating locker collections or calling repository write methods directly.
SQLite schema migrations are tracked with `PRAGMA user_version`; update `LockerRepository.CurrentSchemaVersion` whenever a migration changes persisted schema.

The `Lockers` table contains:

- `Guid`
- `LockerName`
- `Password`
- `LockerLocation`
- `IsLocked`
- `StorageFormatVersion`
- `LockedArchiveSha256`
- `LockedAtUtc`
- `CreatedAt`
- `UpdatedAt`

Settings are stored separately as JSON through `SettingsManager`.

## Settings

Settings include:

- Developer mode.
- Logging format, level, maximum file size, and file logging enablement.
- Fixed logging defaults for retention, UTC ISO-8601 timestamps, asynchronous writes, and developer-mode thread IDs.
- Auto-update and update channel.
- Database vacuum interval and last-vacuum timestamp.

Settings writes use a temporary file and replacement flow so a failed write is less likely to leave a corrupt settings file. Malformed settings files are backed up before defaults are reinitialized.

## Updates

Update checks use `UpdateService` and GitHub Releases. The active update channel controls whether stable or unstable releases are considered. The CLI can check, show release notes, download a matching installer package, and hand it to the platform installer after digest verification. Windows launches the installer elevated. Linux installs `.deb`/`.rpm` packages through the available system package manager using root, `pkexec`, or `sudo`. macOS opens the verified `.pkg` with Installer.

## Versioning

Shared version metadata is defined in `Directory.Build.props`.

Current version source:

```xml
<Version>...</Version>
```

The literal version changes in `Directory.Build.props`; do not duplicate it as another source of truth. Build metadata is generated through MSBuild properties such as `FileVersion`, `InformationalVersion`, and `AssemblyVersion`.

## Notes for Maintainers

- SQLite is already the active locker metadata store.
- The CLI is the most complete command surface and should be treated as the reference behavior for docs.
- Avalonia is the active GUI implementation.

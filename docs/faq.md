# FAQ

## Is ColDog Locker ready for production use?

ColDog Locker is still pre-release software.
Locking now aborts when its exact archive manifest does not match the atomically claimed source tree. Data-loss risks from writers retaining native handles across that cutover and from interrupted operations remain. Use independent, tested backups; do not entrust the only copy of important files to this prerelease. Platform validation is also incomplete.
Windows and macOS packages are unsigned, so Windows SmartScreen or macOS Gatekeeper may display a warning.

## What is a locker?

A locker is a managed directory. While unlocked, it behaves like a normal folder. Locking creates an encrypted archive and removes the plaintext source folder. The archive is published in a folder with a leading dot, marked hidden/system where supported.

## Where are lockers created by default?

By default, `cdlocker new <name>` creates lockers under the user's Documents folder in a `ColDog Locker` directory.

On Windows, that is usually:

```text
%USERPROFILE%\Documents\ColDog Locker
```

## What does `--path` mean when creating a locker?

`--path` is the parent directory. For example:

```bash
cdlocker new Taxes --path "D:\Private"
```

creates:

```text
D:\Private\Taxes
```

## Can I recover a forgotten password?

No. Password recovery is not available. If the files are locked and the password is lost, ColDog Locker cannot decrypt the files.

## Why are some folders blocked?

ColDog Locker blocks drive roots, system directories, app data folders, temp folders, profile roots, and top-level user folders to reduce accidental damage and malicious use. Create lockers in dedicated subdirectories instead.

## Does ColDog Locker store my password?

It stores a salted, versioned password verifier, not the plaintext password. The password itself is not saved.

## Where is the locker database?

Locker metadata is stored in `lockers.db` under the per-user configuration directory. Typical roots are `%LOCALAPPDATA%\ColDog Studios\ColDog Locker` on Windows, `${XDG_DATA_HOME:-$HOME/.local/share}/ColDog Studios/ColDog Locker` on Linux, and `$HOME/Library/Application Support/ColDog Studios/ColDog Locker` on macOS.

The database stores locker names, paths, password verifiers, GUIDs, and lock state.

## Where are settings and logs?

Settings are stored in `settings.json`; logs are stored in `logs/` under the same per-user directory. Run `cdlocker dev` for the authoritative path. See [Platform and Storage Support](platform-support.md) for the complete location table.

## Does locking delete my files?

Yes: locking replaces the ordinary files with an encrypted `locker.cdl` archive, then removes the plaintext directory. Keep a tested backup before locking important data. Unlocking authenticates and decrypts that archive back into the normal locker folder.

## Should I keep backups?

Yes. Keep independent, tested backups for interrupted writes, hardware failure, accidental deletion, and software bugs. A copy of an encrypted archive still requires its original password; it cannot recover a forgotten password. A database backup contains registration data, not your files. See [Backup and Recovery](backup-and-recovery.md).

## Are command-line password options safe?

Options such as `--password`, `--old-password`, and `--new-password` are intended for automation, not normal interactive use. Command-line passwords may be visible in shell history, scripts, logs, or process lists. Prefer the prompt when using ColDog Locker manually.

## Why does `cdlocker` show help instead of opening the GUI?

That is the current CLI behavior. Use `cdlocker gui` to launch the graphical interface or execute `ColDogLocker.exe`.

## What GUI should I use?

Use the Avalonia GUI through `cdlocker gui` on Windows, Linux, or macOS. The macOS package installs `/Applications/ColDog Locker.app`, and the CLI launcher opens that app bundle.

## What packages are available?

Each package contains the CLI, TUI, and Avalonia GUI:

- Windows: x64 and arm64 `.msi` and setup `.exe` installers.
- Debian/Ubuntu-family Linux: x64 and arm64 `.deb` packages.
- Fedora/RHEL/openSUSE-family Linux: x64 and arm64 `.rpm` packages.
- macOS: x64 and arm64 `.pkg` installers.

## What does `verify` prove?

`verify` checks directory access, naming/attributes and content counts. For a locked locker it also checks the archive header against registration data, compares the archive SHA-256 with the stored hash, and reports unexpected neighboring files. It does not ask for a password or authenticate the encrypted contents with AES-GCM. Use `recover` into a new directory to test password-based recovery while retaining the original archive. A successful `verify` is not a substitute for a tested backup.

## Why did my locked folder get renamed?

Locked folders are renamed with a leading dot, such as `MyLocker` to `.MyLocker`, and the metadata path is updated. Unlocking restores files to a new ordinary folder at the unlocked path.

## Why was a file rejected because of filesystem metadata?

The archive preserves ordinary Unix modes and modification times, plus supported Windows attributes and creation/modification times. It refuses metadata that it cannot restore safely, including Unix extended attributes, macOS extended ACLs, Windows explicit/protected ACLs and alternate data streams. Linux SELinux labels and inherited Windows ACLs remain managed by the operating system. Remove or independently back up unsupported metadata before retrying; the failed lock leaves the source in place.

## Can I remove a locked locker?

No. Unlock it first, then run `cdlocker remove <name>`. Use `--delete` only if you also want to delete the directory and its contents.

## Why is my password verifier reported as unsupported?

This prerelease accepts only the current PBKDF2 password-verifier format. Older BCrypt verifiers are not migrated, and password changes cannot authenticate them. Export and independently back up files using the version that created older lockers before upgrading. If you already have an archive in the supported format version 2, standalone `recover` can extract it with the original archive password without reading its database verifier. Version 1 archives remain unsupported.

## Why does the window stay open when I try to close it?

The app keeps its main window open while locker work or a refresh is running. It also asks the desktop session to postpone shutdown while tracked work is active. Wait for the operation and any result or error dialog to finish, then close the window again. Closing the window is not a cancellation command. An operating system can still force termination; after that, check `cdlocker recovery-list` before retrying an interrupted locker operation.

## Why is a locker size shown as “Unknown”?

The app could not finish a size scan, for example because a folder is missing, cannot be read, contains a link, or exceeds the scan limits. “Unknown” does not mean empty. Size display is informational and does not verify archive integrity. The properties dialog calculates metadata in the background; closing it cancels that scan.

## Can I cancel a refresh?

Yes. Use **Cancel refresh** in the status bar. The app keeps the previously displayed list until a complete refresh succeeds. Cancellation takes effect between filesystem calls, so an unresponsive drive may delay it. Locker transformations have a separate **Cancel operation** button.

## Can I cancel locking or unlocking?

Yes, while **Cancel operation** is enabled. Cancellation takes effect between filesystem reads and leaves the source state in place. The button becomes disabled when publication starts: locking may then claim and remove the verified source, while unlocking may publish authenticated plaintext. A cancellation request at or after that boundary does not interrupt the journaled transition. Wait for it to finish; if the process or machine stops, run `cdlocker recovery-list` before retrying.

Before locking, the app scans the logical payload and checks a conservative archive-space estimate against known free space at the encrypted destination. Unlocking reports available destination space, but it cannot know the exact restored size until it authenticates and reads the archive. Keep extra capacity available for restore.

## Why did a displayed size not change immediately?

Automatic list updates may reuse a size estimate for up to 30 seconds. Use **Refresh** or reopen **Properties** to request a fresh measurement. A changed locker registration triggers a fresh size scan automatically. Size estimates are never used to decide which files to encrypt or delete.

## What should I do after an interrupted lock or unlock?

Stop changing the affected folders and run `cdlocker recovery-list`. Preserve the listed source, target and staging paths. Follow [Backup and Recovery](backup-and-recovery.md) to choose between preparation cancellation, committed-state verification and restoration to a new destination. Do not delete journal rows or retry by removing recovery artifacts.

## Can uninstalling delete my lockers?

The Windows installer preserves user data by default. Explicit command-line uninstall with `REMOVE_USER_DATA_ON_UNINSTALL=1` enables cleanup that recursively deletes the app's local data directory and `%USERPROFILE%\Documents\ColDog Locker`. That includes the database, logs and any locked or unlocked files under that default locker directory. The normal installer UI has no cleanup checkbox. Do not pass this property unless you intend to delete those files and have checked an independent backup; never pass it during an upgrade. See [Backup and Recovery](backup-and-recovery.md) before uninstalling or changing installations.

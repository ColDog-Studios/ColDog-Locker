# FAQ

## Is ColDog Locker ready for production use?

ColDog Locker is still pre-release software.
The packages still need release-candidate validation on clean systems before the project is declared stable.
Windows and macOS packages are unsigned, so Windows SmartScreen or macOS Gatekeeper may display a warning.

## What is a locker?

A locker is a managed directory. While unlocked, it behaves like a normal folder. When locked, the files inside it are encrypted, the directory is renamed with a leading dot, and the directory is marked hidden/system where supported.

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

It stores a BCrypt password hash, not the plaintext password. The password itself is not saved.

## Where is the locker database?

Locker metadata is stored in SQLite at:

```text
%LOCALAPPDATA%\ColDog Studios\ColDog Locker\lockers.db
```

The database stores locker names, paths, password hashes, GUIDs, and lock state.

## Where are settings and logs?

Settings and logs are stored under:

```text
%LOCALAPPDATA%\ColDog Studios\ColDog Locker
```

Settings are stored in `settings.json`; logs are stored in `logs/`.

## Does locking delete my files?

No. Locking writes the locker contents into an encrypted `locker.cdl` archive and removes the plaintext directory only after the archive succeeds. Unlocking authenticates and decrypts that archive back into the normal locker folder.

## Should I keep backups?

Yes. Always keep backups of important data. Backups protect you from forgotten passwords, interrupted writes, hardware failure, accidental deletion, and software bugs.

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

`verify` checks filesystem and metadata consistency. It does not cryptographically authenticate every file. It reports whether the directory exists, is accessible, has the expected hidden/name state, and can be counted.

## Why did my locked folder get renamed?

Locked folders are renamed with a leading dot, such as `MyLocker` to `.MyLocker`, and the metadata path is updated. Unlocking renames it back.

## Can I remove a locked locker?

No. Unlock it first, then run `cdlocker remove <name>`. Use `--delete` only if you also want to delete the directory and its contents.

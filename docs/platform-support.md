# Platform and Storage Support

ColDog Locker is prerelease software. Package targets describe what the build produces; they do not imply that every target has passed native installation and recovery testing.

## Current validation status

| Platform | Package targets | Current evidence |
| --- | --- | --- |
| Windows | x64 and ARM64 MSI/setup EXE | Builds and platform-specific automated tests are defined. Native install, update, GUI, filesystem-policy and recovery runs are still required before public launch. Packages are unsigned. |
| Linux | x64 and ARM64 DEB/RPM | Clean x64 installation, CLI round trips, GUI startup, reinstall and removal passed on Ubuntu 24.04 and Fedora 43. ARM64 installed validation is still required. |
| macOS | x64 and ARM64 PKG | Builds and platform-specific automated tests are defined. Native install, update, GUI, filesystem-policy and recovery runs are still required before public launch. Packages are unsigned and unnotarized. |

Linux and macOS packages are self-contained. The Windows MSI requires the matching .NET 10 runtime; the setup EXE can download the pinned runtime when it is absent. Offline and no-runtime Windows installation still needs native validation.

Headless GUI tests cover application bindings and workflows. Icon-only commands, custom menus and core form fields provide explicit accessibility names or label relationships, and dynamic status/error text is exposed as live output. A Linux Wayland/AT-SPI run verified the visible main-window accessibility tree and focusable New Locker fields. These checks do not certify sequential keyboard navigation, actual screen-reader speech, scaling, high contrast, password-manager interaction, or Windows/macOS accessibility. Those checks remain launch requirements.

## Filesystem requirements

Use a local filesystem that supports atomic same-volume rename, durable file flushes, stable file identity and normal file locking. ColDog Locker's crash-recovery guarantees depend on those operating-system primitives.

Network shares, userspace mounts, cloud-synchronized folders and removable drives are outside the power-loss guarantee. Do not use them for the only copy of important data. Disconnecting storage, another program changing files during locking, or a process keeping a writable native handle open can leave a recovery operation that requires manual review.

Lockers support ordinary files and directories. The app refuses symbolic links/reparse points, hard-linked source files, FIFOs, sockets, devices, sparse files and filesystem metadata it cannot reproduce. Read-only or permission-denied storage fails the operation. Lock checks a conservative encrypted-output space estimate; unlock reports destination capacity, but exact restored size is known only while the authenticated archive is read.

Keep an independent tested backup and follow [Backup and Recovery](backup-and-recovery.md) after any interruption. The detailed metadata policy is in [Security Features](security-features.md).

## Application data locations

The per-user configuration directory contains `lockers.db`, `settings.json`, logs and update staging. A `db-backup` snapshot is written to the new directory selected by the user. Typical configuration locations are:

| Platform | Typical directory |
| --- | --- |
| Windows | `%LOCALAPPDATA%\ColDog Studios\ColDog Locker` |
| Linux | `${XDG_DATA_HOME:-$HOME/.local/share}/ColDog Studios/ColDog Locker` |
| macOS | `$HOME/Library/Application Support/ColDog Studios/ColDog Locker` |

.NET special-folder configuration and the environment can change these paths. Run `cdlocker dev` and use **Local Config Location** as the authoritative path for the current account.

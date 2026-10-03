# Security Features

ColDog Locker is designed to protect files at rest inside managed locker directories. It combines file encryption, password hashing, password strength checks, and path validation that blocks risky locker locations.

This document describes the current implementation, not an aspirational design.

## Summary

| Area | Current Implementation |
| --- | --- |
| File encryption | Versioned encrypted locker archive (`locker.cdl`) with AES-GCM per-chunk authentication tags |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations; only archive format version 2 is accepted |
| Archive salt | 16 random bytes stored in the archive's readable header |
| Password storage | Versioned PBKDF2-HMAC-SHA256 verifier, 600,000 iterations, independent random salt; unsupported formats refused |
| Locker metadata | Per-user SQLite database |
| Settings | Per-user JSON file |
| Path protection | Blocks drive roots, system paths, app data paths, and top-level user folders |
| Operation safety | Staged archive creation/extraction, exact source-manifest cutover checks, persistent operation records and explicit recovery commands; interruption and retained-write-handle risks remain |

## Prerelease Compatibility

This build reads and writes archive format version 2 only. Version 1 archives from earlier prereleases are unsupported, including by `recover`; there is no in-app conversion. Before upgrading an older prerelease, restore/export your files using the version that created its archives and keep an independent backup in a protected location. A password change does not convert an archive format. Older BCrypt password verifiers are also unsupported; this build does not migrate them.

## File Encryption

When a locker is locked, ColDog Locker creates a compressed `tar+gzip` stream of the validated locker contents and encrypts that stream into a versioned `locker.cdl` archive inside the locked locker directory.

For each archive:

1. Generate a random 16-byte salt.
2. Generate a random nonce prefix.
3. Use PBKDF2-HMAC-SHA256 with 600,000 iterations to derive a 256-bit AES key from the locker password and salt.
4. Write a header containing the archive format marker, salt, nonce prefix, locker metadata, and key derivation settings.
5. Encrypt archive content in chunks with AES-GCM.
6. Store an authentication tag for each encrypted chunk and an authenticated end marker committing the final chunk count.
7. Write encrypted output to a temporary locked directory.
8. Move the staged locked directory into place only after archive creation succeeds.

Archive creation limits the total inspected file contents to 1 TiB and caps each file read at its inspected length. Observed length changes or early end-of-file stop creation. It hashes the exact entry metadata and bytes passed to the archive, atomically claims the source tree and refuses deletion unless the claimed tree matches. Close writers and keep independent backups because native handles retained across cutover cannot be revoked portably.

When unlocking, ColDog Locker reads the encrypted archive header, derives the same key, verifies each AES-GCM authentication tag, decrypts to a staging directory, validates archive entries, and moves the restored locker directory into place only after extraction succeeds.

## Important Crypto Caveats

The current archive format provides authenticated encryption for locked locker contents.

The version 2 protocol has maintainer adversarial tests and an independent interoperability fixture, but it has not received third-party cryptanalysis. Treat it as a prerelease format until that review occurs.

Practical effects:

- A wrong password fails during authenticated decryption.
- Modified encrypted chunks fail authentication. Extraction uses a temporary directory and only succeeds after checking the complete archive, including the version 2 end marker. Missing end markers and appended bytes are rejected. Version 1 archives are refused. Every accepted archive must have authenticated termination.
- Locked archive tampering is detected before the restored locker is moved into place.
- Backups matter. Keep copies of important data outside the locker workflow.

ColDog Locker also stores archive metadata and a SHA-256 hash in SQLite so filesystem state, metadata, and encrypted archive content can be checked together.

The archive header is readable without a password. It exposes the locker name and GUID, lock time, app/format information, and recorded root mode/modification time. Salt and key-derivation settings are also public. File contents and the internal file/directory listing are encrypted; the locker name itself is not confidential. Header metadata participates in authenticated decryption, but reading the header alone does not authenticate it.

## Operation Safety

Lock and unlock operations are designed to avoid updating locker metadata until the filesystem operation completes.

During lock:

1. The existing locker path and locker name are validated.
2. Symlinks, reparse points, and unsafe paths are rejected.
3. A compressed encrypted archive is written to a temporary locked directory.
4. The original plaintext directory is removed only after archive creation succeeds.
5. The temporary locked directory is moved to the locked path.
6. Hidden/system attributes are applied where supported.
7. SQLite metadata is updated last.

During unlock:

1. The existing locker path and locker name are validated.
2. The encrypted archive is authenticated and decrypted to a staging directory.
3. Archive entries are validated before files are written.
4. Hidden/system attributes are removed where supported.
5. The staging directory is moved to the unlocked path.
6. SQLite metadata is updated last.
7. The locked archive directory is deleted best effort.

If locking fails after source deletion begins, the completed archive is retained and its path is reported. The source may be incomplete. Do not delete the archive or relock the surviving source. A persistent SQLite journal records lock/unlock phases and blocks retries after an unfinished operation. Per-locker process ownership serializes application operations, and revision checks reject stale metadata updates. Published unlock output and locked-archive cleanup use stable filesystem identity; if another object replaces an owned directory at the same path, cleanup preserves the replacement. `recovery-cancel`, `recovery-finish` and `recovery-restore` resolve supported states; standalone `recover` extracts files without changing registration. Follow [Backup and Recovery](backup-and-recovery.md) to select the appropriate action.

The GUI reports lock/unlock phases and exposes cancellation only while it is safe to stop before publication. Once lock is ready to claim the source, or unlock is ready to publish plaintext, cancellation is disabled and the durable journal controls recovery. Lock preflight rejects known-insufficient destination space before archive output starts. Unlock reports destination capacity, but the exact authenticated plaintext size is learned while extracting.

Archive and extracted-file data is flushed before publication. On Linux and macOS the app also flushes affected directories; on Windows it uses write-through same-volume moves. Power-loss recovery requires a local filesystem that honors those operating-system durability and atomic-rename operations. Network shares, userspace mounts, removable media and cloud-synchronized folders are outside that guarantee. A failed directory flush stops the operation and keeps its recovery record and artifacts.

These measures do not provide a filesystem snapshot, prevent every path-replacement race, or guarantee power-loss recovery. Detected changes before the source cutover abort and restore the changed tree. Stop writers and synchronization before locking because an already-open native writable handle may outlive the atomic path claim. Keep independent backups.

## Password Storage

Locker passwords are not stored in plaintext.

New passwords use a versioned PBKDF2-HMAC-SHA256 verifier with 600,000 iterations and a separate random salt. The complete UTF-8 password is checked with a constant-time comparison before locking. Older BCrypt verifiers are unsupported and are refused before password-authorized operations. There is no automatic verifier conversion; use a current-version locker registration for new operations.

Changing a password requires:

- The locker must be unlocked.
- The current password must be entered correctly.
- The new password must pass the password filter.

The CLI can accept `--old-password` and `--new-password` for automation, but interactive prompts are preferred for normal use because command-line arguments may expose secrets.

Because files are already plaintext while a locker is unlocked, changing the password updates only the stored password hash. Files are encrypted with the new password the next time the locker is locked.

## Password Requirements

Passwords must satisfy all of these rules:

- At least 12 characters.
- At least one uppercase letter.
- At least one lowercase letter.
- At least one digit.
- At least one special character.
- Must not contain blocked common words such as `password`, `admin`, `locker`, `secret`, `123456`, `qwerty`, or similar entries.

## Path and Metadata Protection

ColDog Locker validates locker paths when lockers are created, updated, locked, unlocked, and deleted. This prevents many accidental or malicious attempts to encrypt or delete important system locations.

Locker names are also validated centrally by the service layer. A locker name must be a valid file name, not an absolute path, relative path, `.` entry, or `..` entry.

Blocked exact roots include:

- Drive roots, such as `C:\` or `/`.
- The user profile root.
- Top-level user folders such as Documents, Desktop, Downloads, Pictures, Videos, and Music.
- The top-level AppData folder.

Blocked paths and their subdirectories include:

- Windows system directories.
- Program Files and common program files directories.
- ProgramData.
- AppData Roaming and Local.
- Temp directories.
- Startup folders.
- Additional Windows critical directories such as Recovery, Boot, EFI, `$Recycle.Bin`, and System Volume Information.

Use dedicated subdirectories for lockers:

```text
Documents\ColDog Locker\MyLocker
Documents\SecureFiles
D:\Private\Taxes
```

Recursive directory deletion is guarded by the same service-layer validation. ColDog Locker refuses to delete locked locker directories and checks that the target directory name matches the locker metadata before recursive deletion.

## Metadata and Settings Security

Locker metadata is stored in `lockers.db` under the per-user configuration directory. Typical roots are `%LOCALAPPDATA%\ColDog Studios\ColDog Locker` on Windows, `${XDG_DATA_HOME:-$HOME/.local/share}/ColDog Studios/ColDog Locker` on Linux, and `$HOME/Library/Application Support/ColDog Studios/ColDog Locker` on macOS. Run `cdlocker dev` to find the authoritative path for the current account.

The database stores:

- Locker GUID.
- Locker name.
- Versioned password verifier. Imported older databases may contain unsupported verifier formats.
- Locker directory path.
- Lock state.
- Created and updated timestamps.
- Archive format, recorded archive hash and revision data.
- Pending operations, recovery history and artifact paths.

The database is not itself encrypted. It does not store plaintext passwords or encryption keys.

Settings are stored as `settings.json` in the same directory. See [Platform and Storage Support](platform-support.md) for filesystem and native-validation limits.

Settings writes use a temporary-file replacement flow. If a malformed settings file is detected, ColDog Locker backs it up and reinitializes defaults.

Logger writes run asynchronously and are flushed during normal process shutdown so recent security-relevant events are not silently dropped. Log entries always include UTC ISO-8601 timestamps; thread IDs are included when developer mode is enabled.

Downloaded updates are stored in an owner-only directory under the app's local data folder. ColDog Locker rejects linked staging paths and verifies the release SHA-256 digest before elevation. The privileged launcher copies the package into a new private system staging directory, verifies that copy and only then starts the platform installer. Signing is not configured, so checksums protect byte integrity but do not provide an operating-system publisher signature for ColDog Studios.

## What ColDog Locker Protects Against

ColDog Locker is intended to help with:

- Casual or unauthorized access to files at rest.
- Exposure from someone browsing the filesystem while lockers are locked.
- Immediate disclosure of plaintext passwords from the registry: it stores salted verifiers. An attacker who obtains a verifier or archive can still attempt offline password guessing.
- Accidental locking of high-risk system or profile locations.
- Tampering with encrypted archive contents while lockers are locked.
- Some interrupted lock/unlock failure modes through retained archives, operation records and verified recovery commands.

## What ColDog Locker Does Not Protect Against

ColDog Locker does not protect against:

- Forgotten passwords.
- Malware or keyloggers capturing passwords.
- A compromised operating system.
- Physical access while a locker is unlocked.
- Memory inspection while passwords or derived keys are in use.
- Complete locker-level state tampering when the database, filesystem, and archive metadata are all manipulated consistently.
- Data loss from interrupted operations, hardware failure, or missing backups.
- Recoverable plaintext in deleted disk blocks, filesystem snapshots, cloud sync history, or external backups. Locking removes ordinary files; it does not securely erase every historical copy.

## Recommended User Practices

- Use strong, unique passwords for each locker.
- Prefer interactive password prompts over command-line password options.
- Keep tested backups of important files.
- Do not run ColDog Locker with elevated privileges unless absolutely required.
- Avoid editing locked locker contents outside ColDog Locker.
- Do not manually move or rename locked locker folders. Registration still points to the original path; standalone archive recovery can retrieve files at a new location if needed.

## Reporting Security Issues

Do not open a public issue for a vulnerability.

Use GitHub's private security advisory flow for the repository and include:

- A short description.
- Reproduction steps.
- Expected impact.
- A suggested fix, if you have one.

## Filesystem Metadata

New archives preserve Unix permission modes and file/directory modification times, including the locker root. Unix extraction staging starts with directory mode `0700` and file mode `0600`; original modes are applied after the entire archive authenticates. Special Unix permission bits (set-user-ID, set-group-ID, sticky) are rejected before archiving. Older archives cannot recover metadata that was never recorded.

Windows staging is created with an owner-only inheritable access rule. Ordinary inherited ACLs come from the destination parent; explicit or protected ACLs and alternate data streams are rejected before source deletion. Unix ownership must match the current user and group, and unsupported extended attributes are rejected. Hard-linked source files are rejected instead of being restored as independent files. These native policies have automated platform tests, but Windows/macOS hosted results are still required before public launch.

### Unsupported file types

Lockers support ordinary files and directories. Symbolic links, reparse points, FIFOs, Unix sockets and device files are rejected during source inspection. On Unix, failure to obtain the native entry type also stops archiving. Remove unsupported entries from the folder before retrying; an interrupted operation may first need `recovery-cancel` if `recovery-list` reports preparation. File reads compare the opened handle with the object inspected during enumeration. The source root, its ancestors and every entry carry stable filesystem identity through archive creation and the atomic source claim; a parent or regular-file replacement aborts before deletion. Publication and directory cleanup also verify the moved object's identity so a same-path replacement is preserved.

Filesystem metadata has a fail-closed policy. Unix files must use the current user's ownership; ordinary permission modes, executable bits and modification times are restored, while special permission bits and extended attributes are refused before source deletion. Linux SELinux labels remain managed by the operating system. macOS extended ACLs are refused. On Windows, ordinary attributes and creation/modification times are authenticated and restored. The app refuses non-current ownership, explicit or protected ACLs, alternate data streams, compression, EFS encryption, sparse files and other attributes it cannot reproduce. A normal Windows round trip inherits ACLs again from the same parent; standalone recovery inherits from the selected destination parent. Windows-metadata archives must be restored on Windows.

### Hard-linked files

A hard link is another name for the same underlying file, possibly outside the locker. Archiving that file as an ordinary copy would lose its shared-file relationship, and locking could leave an external plaintext link behind. The app therefore refuses source files whose inspected link count is not exactly one. Move such files out of the locker or deliberately replace them with independent copies before retrying; keep a backup and check any outside copies. Archive backups with hard links remain readable for standalone recovery. This check does not prevent another program from creating links or changing files later during the operation.

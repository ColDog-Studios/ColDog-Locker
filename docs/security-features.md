# Security Features

ColDog Locker is designed to protect files at rest inside managed locker directories. It combines file encryption, password hashing, password strength checks, and path validation that blocks risky locker locations.

This document describes the current implementation, not an aspirational design.

## Summary

| Area | Current Implementation |
| --- | --- |
| File encryption | Versioned encrypted locker archive (`locker.cdl`) with AES-GCM per-chunk authentication tags |
| Key derivation | PBKDF2-HMAC-SHA256, 210,000 iterations |
| Archive salt | 16 random bytes stored in the encrypted archive header |
| Password storage | BCrypt hash, cost factor 14 |
| Locker metadata | Per-user SQLite database |
| Settings | Per-user JSON file |
| Path protection | Blocks drive roots, system paths, app data paths, and top-level user folders |
| Operation safety | Staged archive creation/extraction and best-effort rollback for interrupted lock/unlock operations |

## File Encryption

When a locker is locked, ColDog Locker creates a compressed `tar+gzip` stream of the validated locker contents and encrypts that stream into a versioned `locker.cdl` archive inside the locked locker directory.

For each archive:

1. Generate a random 16-byte salt.
2. Generate a random nonce prefix.
3. Use PBKDF2-HMAC-SHA256 with 210,000 iterations to derive a 256-bit AES key from the locker password and salt.
4. Write a header containing the archive format marker, salt, nonce prefix, original archive length, and key derivation settings.
5. Encrypt archive content in chunks with AES-GCM.
6. Store an authentication tag for each encrypted chunk.
7. Write encrypted output to a temporary locked directory.
8. Move the staged locked directory into place only after archive creation succeeds.

When unlocking, ColDog Locker reads the encrypted archive header, derives the same key, verifies each AES-GCM authentication tag, decrypts to a staging directory, validates archive entries, and moves the restored locker directory into place only after extraction succeeds.

## Important Crypto Caveats

The current archive format provides authenticated encryption for locked locker contents.

Practical effects:

- A wrong password fails during authenticated decryption.
- Modified encrypted chunks fail authentication before plaintext restoration.
- Locked archive tampering is detected before the restored locker is moved into place.
- Backups matter. Keep copies of important data outside the locker workflow.

ColDog Locker also stores archive metadata and a SHA-256 hash in SQLite so filesystem state, metadata, and encrypted archive content can be checked together.

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

If a lock or unlock operation fails partway through, ColDog Locker attempts a best-effort rollback and logs rollback failures. This reduces inconsistent states but does not replace the need for backups.

## Password Storage

Locker passwords are not stored in plaintext.

The locker database stores BCrypt hashes generated with cost factor 14. Password verification compares the supplied password against that hash before lock, unlock, or password-change operations proceed.

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

Locker metadata is stored in SQLite at:

```text
%LOCALAPPDATA%\ColDog Studios\ColDog Locker\lockers.db
```

The database stores:

- Locker GUID.
- Locker name.
- BCrypt password hash.
- Locker directory path.
- Lock state.
- Created and updated timestamps.

The database is not itself encrypted. It does not store plaintext passwords or encryption keys.

Settings are stored as JSON at:

```text
%LOCALAPPDATA%\ColDog Studios\ColDog Locker\settings.json
```

Settings writes use a temporary-file replacement flow. If a malformed settings file is detected, ColDog Locker backs it up and reinitializes defaults.

Logger writes run asynchronously and are flushed during normal process shutdown so recent security-relevant events are not silently dropped. Log entries always include UTC ISO-8601 timestamps; thread IDs are included when developer mode is enabled.

## What ColDog Locker Protects Against

ColDog Locker is intended to help with:

- Casual or unauthorized access to files at rest.
- Exposure from someone browsing the filesystem while lockers are locked.
- Password hash disclosure, because plaintext passwords are not stored.
- Accidental locking of high-risk system or profile locations.
- Tampering with encrypted archive contents while lockers are locked.
- Some interrupted lock/unlock failure modes through temporary files and best-effort rollback.

## What ColDog Locker Does Not Protect Against

ColDog Locker does not protect against:

- Forgotten passwords.
- Malware or keyloggers capturing passwords.
- A compromised operating system.
- Physical access while a locker is unlocked.
- Memory inspection while passwords or derived keys are in use.
- Complete locker-level state tampering when the database, filesystem, and archive metadata are all manipulated consistently.
- Data loss from interrupted operations, hardware failure, or missing backups.

## Recommended User Practices

- Use strong, unique passwords for each locker.
- Prefer interactive password prompts over command-line password options.
- Keep tested backups of important files.
- Do not run ColDog Locker with elevated privileges unless absolutely required.
- Avoid editing locked locker contents outside ColDog Locker.
- Do not manually rename locked locker folders unless you also know how to repair the metadata.

## Reporting Security Issues

Do not open a public issue for a vulnerability.

Use GitHub's private security advisory flow for the repository and include:

- A short description.
- Reproduction steps.
- Expected impact.
- A suggested fix, if you have one.

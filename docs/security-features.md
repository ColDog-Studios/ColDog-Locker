# Security Features

ColDog Locker is designed to protect files at rest inside managed locker directories. It combines file encryption, password hashing, password strength checks, and path validation that blocks risky locker locations.

This document describes the current implementation, not an aspirational design.

## Summary

| Area | Current Implementation |
| --- | --- |
| File encryption | Versioned AES-GCM file format with per-chunk authentication tags |
| Key derivation | PBKDF2-HMAC-SHA256, 210,000 iterations |
| Per-file salt | 16 random bytes stored in the encrypted file header |
| Password storage | BCrypt hash, cost factor 14 |
| Locker metadata | Per-user SQLite database |
| Settings | Per-user JSON file |
| Path protection | Blocks drive roots, system paths, app data paths, and top-level user folders |
| Operation safety | Temporary-file replacement and best-effort rollback for interrupted lock/unlock operations |

## File Encryption

When a locker is locked, ColDog Locker recursively encrypts each file in the locker directory using a versioned `CDLENC` file format.

For each file:

1. Generate a random 16-byte salt.
2. Generate a random nonce prefix.
3. Use PBKDF2-HMAC-SHA256 with 210,000 iterations to derive a 256-bit AES key from the locker password and salt.
4. Write a header containing the format marker, salt, nonce prefix, original file length, and key derivation settings.
5. Encrypt file content in chunks with AES-GCM.
6. Store an authentication tag for each encrypted chunk.
7. Write encrypted output to a temporary file.
8. Replace the original file only after encryption completes.

When unlocking, ColDog Locker reads the encrypted file header, derives the same key, verifies each AES-GCM authentication tag, decrypts to a temporary file, and replaces the encrypted file only after the full file has been authenticated and decrypted.

## Important Crypto Caveats

The current file format provides authenticated encryption for file contents.

Practical effects:

- A wrong password fails during authenticated decryption.
- Modified encrypted chunks fail authentication before plaintext replacement.
- Tamper detection is per encrypted file, not a complete locker-level manifest.
- Backups matter. Keep copies of important data outside the locker workflow.

Future improvements should consider a locker-level state marker or manifest that cross-checks the database, directory state, and expected encrypted files.

## Operation Safety

Lock and unlock operations are designed to avoid updating locker metadata until the filesystem operation completes.

During lock:

1. The existing locker path and locker name are validated.
2. Files are encrypted in place using temporary-file replacement.
3. The locker directory is renamed to its locked form.
4. Hidden/system attributes are applied where supported.
5. SQLite metadata is updated last.

During unlock:

1. The existing locker path and locker name are validated.
2. Files are authenticated and decrypted in place using temporary-file replacement.
3. Hidden/system attributes are removed where supported.
4. The locker directory is renamed to its unlocked form.
5. SQLite metadata is updated last.

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

Logger writes can run asynchronously. When asynchronous logging is disabled or the process exits, ColDog Locker attempts to flush queued log entries so recent security-relevant events are not silently dropped.

## What ColDog Locker Protects Against

ColDog Locker is intended to help with:

- Casual or unauthorized access to files at rest.
- Exposure from someone browsing the filesystem while lockers are locked.
- Password hash disclosure, because plaintext passwords are not stored.
- Accidental locking of high-risk system or profile locations.
- Tampering with encrypted file contents while lockers are locked.
- Some interrupted lock/unlock failure modes through temporary files and best-effort rollback.

## What ColDog Locker Does Not Protect Against

ColDog Locker does not protect against:

- Forgotten passwords.
- Malware or keyloggers capturing passwords.
- A compromised operating system.
- Physical access while a locker is unlocked.
- Memory inspection while passwords or derived keys are in use.
- Complete locker-level state tampering when the database and filesystem are both manipulated.
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

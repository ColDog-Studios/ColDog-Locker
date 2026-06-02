# Security Features

ColDog Locker is designed to protect files at rest inside managed locker directories. It combines file encryption, password hashing, password strength checks, and path validation that blocks risky locker locations.

This document describes the current implementation, not an aspirational design.

## Summary

| Area | Current Implementation |
| --- | --- |
| File encryption | .NET AES with key and IV derived per file |
| Key derivation | PBKDF2-HMAC-SHA256, 10,000 iterations |
| Per-file salt | 16 random bytes stored at the start of each encrypted file |
| Password storage | BCrypt hash, cost factor 14 |
| Locker metadata | Per-user SQLite database |
| Settings | Per-user JSON file |
| Path protection | Blocks drive roots, system paths, app data paths, and top-level user folders |

## File Encryption

When a locker is locked, ColDog Locker recursively encrypts each file in the locker directory.

For each file:

1. Generate a random 16-byte salt.
2. Use PBKDF2-HMAC-SHA256 with 10,000 iterations to derive 48 bytes from the locker password and salt.
3. Use the first 32 derived bytes as the AES key.
4. Use the remaining 16 derived bytes as the AES IV.
5. Write the salt at the beginning of the encrypted file.
6. Write encrypted content to a temporary `.enc` file.
7. Delete the plaintext file and move the encrypted file into its place.

When unlocking, ColDog Locker reads the first 16 bytes as the salt, derives the same key and IV, decrypts to a temporary `.dec` file, deletes the encrypted file, and moves the decrypted file into place.

## Important Crypto Caveats

The current implementation does not store a separate authentication tag or MAC for each encrypted file. That means the encrypted file format is focused on confidentiality, not strong tamper detection.

Practical effects:

- A wrong password will usually fail during decryption, but the file format does not provide explicit authenticated integrity.
- A modified encrypted file may not always be detected as a deliberate tamper event before decryption is attempted.
- Backups matter. Keep copies of important data outside the locker workflow.

Future improvements should consider authenticated encryption, such as AES-GCM, or an encrypt-then-MAC format.

## Password Storage

Locker passwords are not stored in plaintext.

The locker database stores BCrypt hashes generated with cost factor 14. Password verification compares the supplied password against that hash before lock, unlock, or password-change operations proceed.

Changing a password requires:

- The locker must be unlocked.
- The current password must be entered correctly.
- The new password must pass the password filter.

Because files are already plaintext while a locker is unlocked, changing the password updates only the stored password hash. Files are encrypted with the new password the next time the locker is locked.

## Password Requirements

Passwords must satisfy all of these rules:

- At least 12 characters.
- At least one uppercase letter.
- At least one lowercase letter.
- At least one digit.
- At least one special character.
- Must not contain blocked common words such as `password`, `admin`, `locker`, `secret`, `123456`, `qwerty`, or similar entries.

## Path Protection

ColDog Locker validates locker paths when lockers are created and again before locking. This prevents many accidental or malicious attempts to encrypt important system locations.

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

## What ColDog Locker Protects Against

ColDog Locker is intended to help with:

- Casual or unauthorized access to files at rest.
- Exposure from someone browsing the filesystem while lockers are locked.
- Password hash disclosure, because plaintext passwords are not stored.
- Accidental locking of high-risk system or profile locations.

## What ColDog Locker Does Not Protect Against

ColDog Locker does not protect against:

- Forgotten passwords.
- Malware or keyloggers capturing passwords.
- A compromised operating system.
- Physical access while a locker is unlocked.
- Memory inspection while passwords or derived keys are in use.
- File tampering with authenticated integrity guarantees.
- Data loss from interrupted operations, hardware failure, or missing backups.

## Recommended User Practices

- Use strong, unique passwords for each locker.
- Prefer interactive password prompts over `--password`.
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

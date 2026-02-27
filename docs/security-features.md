# Security Features

ColDog Locker is built with security as a core principle. This document outlines the cryptographic protections, password security measures, and anti-ransomware safeguards that make ColDog Locker a trustworthy file security solution.

## Overview

- **Encryption**: AES-256-CBC with PBKDF2 key derivation
- **Password Hashing**: BCrypt with configurable work factor
- **Anti-Ransomware**: Path validation prevents locking critical system directories
- **Defense in Depth**: Multiple validation layers and security checkpoints

---

## Encryption

### AES-256-CBC Encryption

ColDog Locker uses **AES-256 in CBC (Cipher Block Chaining) mode** for file encryption:

- **Algorithm**: Advanced Encryption Standard with 256-bit keys
- **Mode**: CBC provides semantic security - identical plaintext blocks produce different ciphertext
- **IV (Initialization Vector)**: Cryptographically random 16-byte IV generated per file
- **Padding**: PKCS7 padding ensures proper block alignment

**Why AES-256-CBC?**
- Industry-standard symmetric encryption algorithm
- 256-bit keys provide strong protection against brute-force attacks
- CBC mode prevents pattern analysis attacks
- Widely audited and NIST-approved

### Key Derivation (PBKDF2)

User passwords are transformed into encryption keys using **PBKDF2-HMAC-SHA256**:

- **Algorithm**: Password-Based Key Derivation Function 2
- **Hash Function**: HMAC-SHA256
- **Iterations**: 100,000 rounds (configurable, increases computation time for attackers)
- **Salt**: Cryptographically random 32-byte salt per locker (prevents rainbow table attacks)
- **Output**: 256-bit encryption key

**Security Benefits**:
- **Slow by design**: Makes brute-force attacks computationally expensive
- **Unique salts**: Same password produces different keys for different lockers
- **Memory-hard**: Resists GPU and ASIC-based cracking attempts

### File Encryption Process

1. Generate random 16-byte IV
2. Derive 256-bit key from password using PBKDF2
3. Encrypt file with AES-256-CBC
4. Prepend IV to encrypted file (IV is not secret, just must be unique)
5. Securely overwrite original file with encrypted data

### File Decryption Process

1. Extract IV from first 16 bytes of encrypted file
2. Derive key from user password using stored salt
3. Decrypt remaining bytes using AES-256-CBC with extracted IV
4. Verify decryption success (invalid password produces garbage data)
5. Restore original file

---

## Password Security

### BCrypt Hashing

Locker passwords are hashed using **BCrypt** before storage:

- **Algorithm**: Blowfish-based adaptive hash function
- **Work Factor**: Configurable cost parameter (default: 12)
- **Salt**: Automatically generated per password
- **Output**: 60-character hash string

**Why BCrypt?**
- **Adaptive**: Cost factor can be increased as hardware improves
- **Salted**: Each password gets a unique salt (prevents rainbow tables)
- **Slow**: Intentionally computationally expensive to slow brute-force attacks
- **Proven**: Battle-tested algorithm used by major platforms

**Database Storage**: Only BCrypt hashes are stored, never plaintext passwords. Even with database access, an attacker cannot recover the original passwords without brute-forcing the hash.

### Password Requirements

Enforced password complexity requirements protect against weak passwords:

- **Minimum Length**: 12 characters (resists brute-force)
- **Uppercase**: At least one uppercase letter (A-Z)
- **Lowercase**: At least one lowercase letter (a-z)
- **Digit**: At least one number (0-9)
- **Special Character**: At least one symbol (!@#$%^&*, etc.)
- **Common Words**: Blocks passwords containing common words (password, admin, locker, etc.)

These requirements ensure passwords have sufficient entropy to resist dictionary and brute-force attacks.

---

## Anti-Ransomware Protection

ColDog Locker prevents malicious use by blocking critical system and user directory roots from being locked.

### Two-Tier Protection

**System Paths** (blocks path + all subdirectories):
- Drive roots (`C:\`, `D:\`), Windows, Program Files, ProgramData
- AppData\Roaming, AppData\Local, Temp, Startup folders

**User Folders** (blocks exact path only, allows subdirectories):
- User profile root, AppData root, Documents, Desktop, Downloads, Pictures, Videos, Music
- Example: ❌ `C:\Users\[Username]\Documents` ✅ `C:\Users\[Username]\Documents\MyLocker`

### Validation Points

Path validation occurs at:
1. **Creation time** (GUI/CLI/TUI) - User-friendly error messages
2. **Lock operation** - Final safety check, logs violations at Fatal level

This defense-in-depth approach catches attempts to bypass protection by tampering with the database.

**Best Practice**: Create dedicated subdirectories for lockers (e.g., `Documents\SecureFiles`, `AppData\MyHiddenLocker`) rather than locking top-level folders.

---

## Database Security

### SQLite Encryption

Locker metadata is stored in an **SQLite database** with the following protections:

- **Password Hashes Only**: Only BCrypt hashes stored, never plaintext passwords
- **Salts**: PBKDF2 salts stored per locker for key derivation
- **No Key Storage**: Encryption keys are never stored - derived from user password at runtime
- **Metadata**: Stores locker names, paths, creation dates, and lock status

**Security Model**: Even with full database access, an attacker cannot:
- Recover original passwords (BCrypt is one-way)
- Decrypt files without the user's password
- Derive encryption keys without brute-forcing the password

### File Integrity

The database tracks:
- **File Count**: Number of files in each locker
- **Lock Status**: Whether locker is currently locked/unlocked
- **Timestamps**: Creation and last modified dates

This metadata helps detect tampering attempts and ensures consistency between database state and filesystem state.

---

## Security Best Practices

### For Users

✅ **DO**:
- Use strong, unique passwords for each locker (minimum 12 characters)
- Store lockers in subdirectories (e.g., `Documents\SecureFiles`)
- Keep multiple backups of critical encrypted data
- Run ColDog Locker with normal user privileges (not as Administrator)

❌ **DON'T**:
- Reuse passwords across lockers
- Lock system directories or drive roots
- Forget your password (it cannot be recovered)
- Share your locker password insecurely

### For Developers

The codebase includes:
- **Unit Tests**: 71 tests covering validation, encryption, and security logic
- **Static Analysis**: Enforces code quality and security patterns
- **Input Validation**: All user inputs sanitized and validated
- **Error Handling**: Security violations logged at Fatal level

---

## Threat Model

### What ColDog Locker Protects Against

✅ **Protected**:
- Unauthorized file access (files encrypted at rest)
- Password guessing (BCrypt + strong requirements)
- Rainbow table attacks (unique salts per locker/password)
- Brute-force attacks (PBKDF2 with 100k iterations, BCrypt work factor)
- Ransomware abuse (path validation prevents locking critical directories)
- Database tampering (re-validation at lock time)

### What ColDog Locker Does NOT Protect Against

❌ **Not Protected**:
- Keyloggers or malware capturing passwords during entry
- Physical access to unlocked files
- Attacks on the operating system or hardware
- Social engineering (user reveals password)
- Memory dumps while locker is unlocked (keys in memory)
- Backdoors or compromised system components

**Security Principle**: ColDog Locker provides strong file encryption and password protection, but cannot protect against compromised systems or user errors. Always use trusted, malware-free systems.

---

## Cryptographic Specifications

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| **File Encryption** | AES-256-CBC | 256-bit key, 16-byte IV per file |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | 100,000 iterations, 32-byte salt |
| **Password Hashing** | BCrypt | Work factor 12 (configurable) |
| **Random Generation** | System CSPRNG | .NET `RandomNumberGenerator` |
| **Padding** | PKCS7 | Standard block cipher padding |

### Algorithm Justifications

- **AES-256**: NIST-approved, quantum-resistant for foreseeable future
- **PBKDF2**: NIST SP 800-132 recommended, widely supported
- **BCrypt**: Adaptive hashing, resists GPU attacks
- **CBC Mode**: Simple, secure when properly implemented with random IVs

---

## Reporting Security Issues

If you discover a security vulnerability in ColDog Locker, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Open a [private security advisory](https://github.com/yourusername/ColDog-Locker/security/advisories/new) on GitHub
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if applicable)

We take security seriously and will respond to verified reports promptly.

# Archive protocol review

This is the focused maintainer review of current prerelease archive format version 2. It records the security invariants that the implementation and adversarial tests must preserve. It is not an external cryptographic audit.

## Current format

The container has a readable header followed by AES-256-GCM chunks:

1. `CDLARC1` magic.
2. Little-endian signed 32-bit metadata length, limited to 1 MiB.
3. A random 16-byte PBKDF2 salt.
4. A random 8-byte nonce prefix.
5. An exact PBKDF2 iteration value.
6. UTF-8 JSON metadata containing the exact supported format version.
7. Repeated chunks containing a signed 32-bit plaintext length, a 16-byte GCM tag and ciphertext of the recorded length.
8. An authenticated zero-length chunk at the next chunk index.

The AES key is PBKDF2-HMAC-SHA256 output using the complete UTF-8 password, the archive salt, exactly 600,000 iterations and a 32-byte output. The reader accepts only format version 2 with that exact work factor, so a hostile header cannot select an excessive KDF cost. Other prerelease formats are intentionally unsupported.

Each 12-byte nonce is the archive's random 8-byte prefix followed by the little-endian 32-bit chunk index. Associated data is the magic, exact metadata bytes, chunk index and plaintext length. This binds ordering, lengths and readable metadata to every tag. Salt or nonce-prefix changes cause authentication failure because they change the derived key or nonce. Chunk indexes advance with checked arithmetic.

The 1 TiB logical content limit and 200,000-entry limit keep valid writer output far below the signed 32-bit chunk-index limit. One TiB alone occupies about 13.4 million 81,920-byte chunks; TAR headers, bounded names and gzip overhead do not approach 2.1 billion chunks. Readers also reject negative or over-buffer chunk lengths before allocation.

The terminal chunk authenticates the final chunk count. Missing, partial, changed or duplicated terminal data fails. Any byte after the terminal chunk fails. Extraction drains TAR/gzip padding and then requires encrypted-stream EOF, so TAR end markers cannot hide unauthenticated encrypted data.

The header remains intentionally readable for identification and recovery routing. `ReadMetadata` does not claim authenticity. Operations that trust contents authenticate the encrypted stream; registered locked archives also have a database SHA-256 identity. Callers must not use readable metadata alone as proof of archive ownership.

Derived keys and plaintext chunk buffers are cleared during disposal and authentication failure. Managed password strings and unavoidable runtime/OS copies cannot be reliably erased. Ciphertext, authentication tags and readable metadata are not secret buffers.

## Work-factor evidence

On September 24, 2026, .NET 10.0.12 on Fedora Linux 44 x64 measured 15 warmed-up PBKDF2-HMAC-SHA256 derivations at 600,000 iterations. Median time was 61.165 ms, with 58.870 ms minimum and 68.360 ms maximum. A normal lock/unlock also performs password-verifier work, archive I/O, compression, authenticated encryption, hashing, durable filesystem writes and SQLite work, so this microbenchmark is only the KDF component.

The selected value matches the current OWASP PBKDF2-HMAC-SHA256 recommendation and remains below its general one-second per-hash guidance on this development host. PBKDF2 is CPU-hard rather than memory-hard. Archive passwords therefore need high entropy, and the work factor must be reviewed again when the format changes or supported hardware baselines materially change.

## Verification matrix

The automated protocol tests cover:

- Successful extraction of a fixed version-2 fixture produced independently with Python `tarfile`, `gzip` and `hashlib`, plus OpenSSL EVP AES-256-GCM.
- Rejection and byte preservation of an independently generated version-1 fixture.
- Strict rejection of format versions 0, 1 and 3 even when they advertise the current KDF.
- Rejection of lower and higher PBKDF2 values before decryption.
- Removed, reordered and duplicated encrypted chunks.
- Missing, partial, changed and followed-by-data authenticated terminals.
- Negative and over-buffer chunk lengths before ciphertext allocation.
- Wrong passwords, changed archive bytes, metadata identity mismatch and incomplete encrypted-stream consumption.
- Successful nested, empty-directory and zero-length-file round trips.

External cryptanalysis and third-party design review remain recommended before declaring a stable archive format. Any later format must use a new authenticated version and fixed, bounded KDF policy rather than silently changing version 2.

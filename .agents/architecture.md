# Architecture

ColDog Locker is a .NET 10 solution split into core domain code, shared services, and multiple user interfaces.

## Prerelease compatibility policy

The user explicitly permits breaking changes and requires no backward compatibility (2026-09-21). There is no stable release to preserve. Archive, password-verifier and database formats may change to simplify correctness and security; mark deliberate version/schema changes clearly. Historical compatibility sections below describe existing code, not a requirement to retain it. Current-version round-trip integrity and failure-safe recovery remain required.

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

CLI help and version commands run without application initialization. Operational commands run shared initialization inside the CLI error boundary:

1. Load or create `settings.json`.
2. Configure logging from settings.
3. Ensure the per-user local config and `logs` directories exist.
4. Initialize the SQLite locker database.
5. Load lockers into memory.
6. Initialize file watchers for settings and locker data.
7. GUI/TUI initialization checks for updates if auto-update is enabled. CLI operations skip the startup network check; `cdlocker update` explicitly checks for updates.

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
4. Create a versioned full-password PBKDF2-HMAC-SHA256 verifier.
5. Create the locker directory if needed.
6. Insert metadata into SQLite.

Locking a locker:

1. Revalidate the locker path.
2. Verify the complete password against the current PBKDF2 verifier; unsupported formats, including BCrypt, are refused before encryption.
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
Schema version 2 adds a unique name index using the `CDL_NAME` collation, registered on every application connection with .NET ordinal case-insensitive comparison. Databases with pre-existing case-duplicate names stop migration without deleting rows. External SQLite maintenance tools must register the same collation before writing or checking indexed data.
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

Update checks use `UpdateService` and GitHub Releases. The active update channel controls whether stable or unstable releases are considered. The CLI can check, show release notes, download a matching installer package, and hand it to the platform installer after digest verification. Downloads use an owner-only app-data staging directory; linked ancestors are refused, Unix mode is enforced as `0700`, and Windows uses a protected owner-only DACL. The installer rehashes a no-follow regular-file handle before elevation. The privileged launcher then copies that source into a new root/administrator-owned private staging directory, rehashes the copied package and invokes the platform consumer only after the copied bytes match. Windows uses `msiexec` or the staged executable, Linux uses the available package manager through root, `pkexec` or `sudo`, and macOS uses Installer.

The installation entrypoint requires the downloader's SHA-256 digest. Invalid or missing digests, changed bytes, unsafe reads and cancellation prevent launch. Reverification of the privileged copy binds the bytes supplied to the package consumer even if the original user-owned pathname changes during an elevation prompt. Signing/notarization remains deferred by the user.

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

### Directory ownership during registration

Repository inserts and updates use an immediate SQLite write transaction to check all other lockers before committing metadata. Each locker reserves its current directory plus the name-based locked and unlocked sibling paths. Equal or ancestor/descendant paths are rejected after lexical normalization, with case-insensitive comparisons on Windows and conservatively on macOS. Existing paths must also have a link-free ancestor chain. Their stable leaf and ancestor identities are compared, so different path strings that resolve to the same directory or nested tree still conflict. Common string prefixes without a directory boundary and genuinely distinct Linux case-variant directories do not conflict. The check and write use the same transaction so simultaneous registrations cannot both claim one tree.

This registration guard does not replace filesystem operation ownership. Per-locker leases, revision checks, path-chain snapshots and identity-checked publication/cleanup protect later operations. Do not claim that a registry check alone prevents paths changing on disk after validation.

### Archive protocol version 2

New archives retain the `CDLARC1` container magic and header layout, with authenticated metadata `formatVersion: 2` and PBKDF2-SHA256 at 600,000 iterations. Readers accept only version 2 with 600,000 iterations; the former version 1/210,000 path was removed under the prerelease breaking-change policy. Version 2 ends with a zero-length AES-GCM chunk whose nonce and associated data use the next chunk index. This authenticates the final count; EOF without the marker and any bytes after it are rejected. Version 1 is refused; there is no EOF-without-terminator acceptance path.

Extraction drains bounded tar padding through gzip and checks encrypted-stream EOF before reporting success, rather than treating tar EOF as authentication completion. Stream disposal clears derived key/plaintext buffers, including failed authentication and failed writes. A fixed version 1 archive generated independently tests rejection and input preservation. A fixed version 2 archive generated with Python tarfile/gzip/hashlib and OpenSSL EVP AES-256-GCM proves current-format interoperability. Version 0/1/3 headers with the current KDF are refused before decryption, and negative/over-buffer chunk lengths fail before allocation. The focused invariant and threat review, KDF measurement and complete adversarial matrix are recorded in [archive-protocol-review.md](archive-protocol-review.md). External cryptanalysis remains recommended before a stable format declaration.

### Archive filesystem metadata

PAX entries carry ordinary Unix modes and modification times. Optional authenticated header fields `rootUnixMode` and `rootLastWriteTimeUtc` cover the root, which is absent from tar entries. On Windows, authenticated PAX fields carry each entry's supported file attributes and creation time; authenticated root fields carry the same values for the locker directory. These Windows fields participate in the source-cutover manifest so a metadata change before deletion aborts the lock. An archive containing Windows metadata is refused on another platform instead of silently dropping it.

Extraction writes into owner-only staging, authenticates the complete encrypted stream, then applies metadata in descending path-length order and root metadata last. Unix sources must be owned by the current effective user and group; ordinary modes and modification times are preserved, while special permission bits and extended attributes are rejected. Linux `security.selinux` labels are treated as operating-system policy and recreated by the destination filesystem. macOS extended ACLs are rejected. Windows sources must be owned by the current user with inherited, unprotected ACLs; explicit/protected ACLs, alternate data streams and attributes that `File.SetAttributes` cannot reproduce are rejected. Supported Windows read-only, hidden, system, archive, temporary and content-indexing flags plus creation/modification times are restored. Inherited Windows ACLs are reapplied by the same parent on a normal round trip; standalone recovery uses the chosen destination parent's inherited ACL. Version 1 archives are unsupported in this build.

### Failure retention and standalone recovery

Once `Lock` attempts source deletion, any subsequent exception preserves the completed archive and throws `LockerRecoveryRequiredException` with its path. It never assumes an existing source root means the tree is intact. A publication flag chooses the owned temporary/published archive path, so a destination collision does not cause cleanup of another operation's directory. Fault tests cover partial deletion, failure after root deletion, persistence failure and destination collision, then decrypt the retained archive and compare both originals.

`cdlocker recover` dispatches before application/database initialization. `LockerRecoveryService` reads header identity, authenticates the entire archive with the supplied password, extracts into a unique private staging directory and durably moves it to a new destination without overwriting existing data. It retains the input archive and does not register or repair database rows.

Unlock rollback also records whether its staging directory was successfully moved to the plaintext destination. If that move fails because a competing destination appeared, rollback cleans only staging and retains the archive and locked metadata; it does not delete or adopt the competing destination. A test injects the collision at the move boundary. This publication flag is not a replacement for cross-process ownership or protection against replacement after a successful move.

### Operation leases

Every locker service mutation acquires a named mutex keyed by user profile and locker GUID before changing state, and holds it through filesystem work, persistence and cleanup. Ownership is thread-affine and reentrant, allowing synchronous calls into `UpdateLocker`; do not carry it across an `await` or release it on another thread. A contender fails promptly with a busy/reload message instead of waiting while holding UI state. Waiting on an abandoned mutex grants the new caller ownership; persisted-state and durable-journal checks then decide whether recovery is required. This permits a safe retry when the former owner died before creating a journal and blocks mutation when an unfinished journal exists.

Windows uses the global kernel-object namespace to cover multiple sessions for the same profile ([Microsoft namespace documentation](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces)). Linux process exclusion is tested by `.github/scripts/check_operation_lease.py`; hosted Windows/macOS validation remains outstanding. The probe builds only the production lease source in a temporary executable without package references; its temporary project disables locked restore because it has no checked-in lockfile.

Unlock captures stable identity for the locked archive directory and extracted staging directory. After publication it verifies that the target has the staging identity. Any rollback or archive cleanup first moves the pathname to a unique same-parent quarantine, compares the moved object's identity, and only then deletes it. A replacement is restored to its original pathname and preserved. Linux uses device/inode identity, macOS uses device/file ID and Windows uses volume/file ID. Archive enumeration binds the source root, every entry and the full ancestor chain to those stable identities through source claim. Linux replacement regressions pass; native Windows/macOS execution remains grouped under F16.

### Optimistic persistence and preflight

Schema version 3 adds `Revision INTEGER NOT NULL DEFAULT 0`. Reads and copied models carry the revision; updates match the expected revision and increment it in the same SQL write, publishing the new revision to memory after commit. Service removal uses a revision-qualified delete. A stale snapshot cannot overwrite or delete a newer row.

Production lock/unlock/password-change paths check the persisted revision and all identity/state fields while holding the operation lease, before filesystem mutation. Preflight also checks other registered paths, rejecting overlapping records inherited from older databases. Test seams inject a persistence/preflight callback for isolated fault scenarios; production supplies `LockerRepository.EnsureCurrent`.

CLI removal with directory deletion is a single leased service call: validate current metadata, quarantine the identity-checked directory, delete it, then conditionally delete its row. This retains the record when directory deletion fails and preserves a same-path replacement. Leases plus revisions do not prevent an unrelated program from changing an already-open file handle during unsupported concurrent writes.

### Operation journal (schema version 4)

`LockerOperations` stores operation ID, locker GUID, kind, phase, source/target/staging paths and a JSON snapshot of the original metadata (never the plaintext password). Production lock/unlock create the record before filesystem changes. Lock advances through Preparing, ArchiveReady, SourceRemovalStarted, Published and MetadataCommitted; unlock uses ExtractionReady before Published. At the destructive lock boundary, the source root is atomically moved into private staging and an exclusive sentinel occupies the original pathname. The claimed tree must match the manifest of bytes actually supplied to the archive before deletion can run. SQLite connections explicitly use `synchronous=FULL`. Locker metadata/revision and MetadataCommitted are written in one transaction, with a required Published row. New mutations reject retained journals.

Completed archive files and extracted files are flushed to disk. Before a journal phase advances, Linux/macOS flush the affected directory tree and both parents of a cross-directory rename; a directory-flush failure aborts while recovery artifacts remain. Windows publication uses `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` after the individual file flushes. These guarantees require a local filesystem that honors the operating system's flush and atomic same-volume rename contracts. Network, userspace, cloud-synchronized and removable filesystems are not claimed to survive power loss. Successful lock clears the journal after metadata commit; unlock clears it after archive cleanup. Failures after destructive work retain the journal and recovery artifacts. Production unlock conservatively retains artifacts on failure instead of performing speculative cleanup; isolated legacy rollback tests can still inject a non-journal persistence delegate.

Startup logs retained records; `cdlocker recovery-list` exposes their paths without acting on them. A record can belong to a still-running operation, so listing alone is not proof of interruption. Reconciliation must acquire ownership and verify the recorded state. The GUI cancels ordinary window close and desktop-lifetime shutdown requests while tracked work is active. A forced process or machine termination relies on the durable journal rather than an exit callback. The deterministic crash harness kills real subprocesses at 23 named filesystem/database boundaries across lock, unlock and recovery, then proves cancellation, committed-state verification or authenticated restoration without overwriting existing output. It runs in the Windows/Linux/macOS test matrix; Linux execution is verified locally, while hosted native execution remains tracked under F16.

### Preparation reconciliation (schema version 5)

`LockerOperationHistory` retains the full prior journal record plus resolution/time. `recovery-cancel` obtains the locker lease, starts an immediate database transaction, rechecks the pending phase and exact metadata snapshot, requires an existing source and absent target, then moves the record into history in that transaction. Allowed phases are Lock/Preparing, Lock/ArchiveReady and Unlock/Preparing. These precede this application's destructive filesystem steps. Files are never changed or removed by this operation; staged artifacts remain identified by history.

The process-kill E2E drill cancels interrupted preparation, verifies history contains the operation and staging path, successfully retries lock/unlock, and compares the original content hash. Unit tests reject active ownership, changed metadata, a missing source, an existing target and later phases. Destructive phases use verified restoration instead of broadening cancellation based only on directory existence.

Lock/unlock progress is reported by the service rather than inferred by the GUI. Cancellation is checked while inspecting, archiving, extracting and applying authenticated metadata. It is disabled before lock claims the source and before unlock publishes plaintext; a token requested after either boundary is deliberately ignored so the durable journaled transition can finish. Lock preflight uses scanned logical bytes, per-entry overhead and a safety margin to reject a known-insufficient destination before archive output begins. Unlock reports destination capacity but cannot reliably preflight the final plaintext size because the readable header does not contain a trusted uncompressed length.

### Verified operation restoration (schema version 6)

`LockerRecoveryAttempts` records archive path/hash, destination, staging and state before recovery creates plaintext. `recovery-restore` acquires the locker lease, requires matching archive GUID/name and a recorded archive location, rejects destination overlap with original artifact paths, and authenticates extraction into a new directory. Archive identity is checked again by hash after extraction. The metadata row/revision, resolved journal history and committed recovery-attempt state update in one SQLite transaction; failed/superseded attempt paths are retained.

Pending operation staging and active recovery destination/staging paths participate in repository path-ownership checks, preventing registration from claiming those directories while recovery runs. Original directories/archives are never deleted by restoration. Recovery publication verifies staging identity, and the process-kill matrix covers every restoration filesystem/database boundary. Missing or changed committed artifacts are preserved and refused when their expected identity cannot be proved. Native Windows/macOS execution remains grouped under F16.

The published-CLI test suite now terminates a real process at SourceRemovalStarted/Published while holding a SQLite read transaction to prevent a later journal commit from racing ahead. It restores 3,000 original files, compares their contents, checks the retained archive hash and surviving source bytes, and confirms the pending journal is resolved. This Linux evidence does not replace hosted Windows/macOS execution.

### Committed-state reconciliation (schema version 7)

`OutputTreeSha256` is retained in pending/history rows. Production unlock hashes directory names, entry types and file contents after authenticated extraction and before publication. `recovery-finish` acquires the locker lease, requires MetadataCommitted, validates the expected revision and before/after metadata, then verifies either the registered archive identity/hash or the restored tree digest. It atomically moves the record into history without changing files or locker metadata. Unlock reconciliation therefore works even if archive cleanup already completed.

The digest certifies names, entry types, lengths, supported modes/timestamps/attributes, stable filesystem identity and exact file bytes. It incurs an additional full read of restored files. ACLs, extended attributes and unsupported metadata are governed by the separate fail-closed metadata policy. Changed output, older journals without a digest, or ambiguous metadata are refused with all artifacts retained. This is the recovery policy for legitimately edited output with no retained archive: the application will not adopt or overwrite unverifiable content, and the user must preserve the output and journal while restoring from an independent backup or seeking assistance.

### Verified database backup

`db-backup` bypasses normal initialization and opens the existing registry read-only without pooling; missing/corrupt sources cannot silently become empty databases. It requires the current schema, uses [Microsoft.Data.Sqlite online backup](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/backup) into a private staging directory, runs `integrity_check` with the application collation, closes SQLite, flushes the database file and staging directory, and publishes with a durable no-overwrite move. The snapshot includes journal/history/attempt tables. Microsoft.Data.Sqlite may block other database writes during copying; it is not an atomic backup of database plus filesystem artifacts.

Tests include committed WAL pages while a connection remains open, pending-record retention and source/backup independence, private Unix modes, non-overwrite, and absent/corrupt source refusal. `db-restore` supplies the supported absent-registry workflow; existing-registry merge, relocation and password reset are explicitly outside its scope. Windows ACL execution remains grouped under F16.

### Restore into an absent registry

`db-restore` bypasses initialization so it cannot create an empty registry before restore. It refuses an existing database or SQLite WAL/SHM/rollback journal, clones a compatible input through the verified backup path, validates names/locations and ordinary registered filesystem state, then publishes with a no-overwrite file move. Locked registrations require matching hash/header metadata and a non-link archive. Pending operation journals are preserved rather than requiring their interrupted folders to look complete. Input backup and locker files are untouched.

This supports loss of the registry with retained original locations. It is not a merge/import into an existing registry, relocation, password reset, cryptographic authentication of a user-supplied database, or a guarantee that unlocked contents have not changed. Close other app instances before restoring. Existing-registry import and hostile filesystem replacement races remain outside this workflow. The unused prerelease `CDLENC` per-file encryption API has been removed; there is no legacy per-file recovery path.

### Filesystem entry type preflight

Archive enumeration and the pre-open file check now reject non-regular entries using native type inspection. Recovery tree digests and archive input metadata/extraction/hash reads use the same check before reading data. Linux uses `statx` with `AT_SYMLINK_NOFOLLOW` and requires the returned `STATX_TYPE` bit; the fixed layout follows the [Linux UAPI stat header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/stat.h). macOS uses `getattrlist` with `ATTR_CMN_OBJTYPE` and `FSOPT_NOFOLLOW`, based on Apple's [attribute definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/attr.h) and [vnode types](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/vnode.h). Native lookup failure or an unavailable entry point fails closed. Windows retains managed link/reparse/device rejection.

Linux tests cover regular files/directories, missing entries, `/dev/null`, FIFOs and Unix sockets. FIFO/socket archive and digest attempts have timeout-bounded assertions and preserve source files. The macOS branch is compiled but has not run on a macOS host; Linux ARM/musl and Windows execution remain platform gates. Filesystem identity uses Linux device/inode, macOS device/file ID and Windows volume/file ID. Archive enumeration records identity for the root and every entry; `OpenRead` compares the opened handle with the enumerated identity before returning data. The exact source manifest also includes these identities, so the post-claim tree must contain the same filesystem objects as the archived tree. The complete ancestor chain is snapshotted before archive creation and checked again before source claim. Unlock and recovery similarly compare extracted staging identity after publication. Removal and cleanup first move the target to a unique same-parent quarantine and compare the moved object before recursive deletion. Linux replacement regressions execute locally; macOS and Windows native branches remain platform gates under F16.

### Unix reads validate the opened handle

Archive source/input reads and recovery hashing now share an `OpenRead` helper. After ordinary type preflight, Unix opens use `O_NOFOLLOW`, `O_NONBLOCK`, `O_CLOEXEC` and `O_NOCTTY`; type is then checked on that same descriptor using Linux `statx(AT_EMPTY_PATH)` or macOS `fgetattrlist`. A non-regular descriptor is closed before reading. The reader acquires a nonblocking shared advisory flock, preserving managed exclusive-lock interoperability, and passes ownership to a synchronous FileStream. Paths are normalized before inspection/opening. Platform flag values follow [Linux fcntl definitions](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/fcntl.h) and [Apple fcntl definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h).

Linux fault injection replaces a regular file with a FIFO, final-component symlink or different regular file between preflight and open. Each is rejected without reading or modifying original/unrelated contents. Additional tests cover reading the original descriptor after a later rename, refusing an existing managed exclusive lock and replacing the source parent immediately before claim. Atomic source claiming and the identity-bearing archive manifest reject ordinary concurrent tree changes before deletion. macOS and Windows native identity execution remains under F16.

### Hard-link source policy

Archives do not encode hard-link relationships, so source preflight and the opened source descriptor require exactly one link. Directory link counts are not restricted. Recovery tree hashing applies the same file policy; read-only archive metadata/hash/extraction inputs and installer verification do not require single-link ownership. Inspection failures refuse the operation. Linux uses `statx(AT_EMPTY_PATH, STATX_NLINK)` with the returned mask checked; macOS requests only `ATTR_FILE_LINKCOUNT` through `fgetattrlist`; Windows uses `GetFileInformationByHandleEx(FileStandardInfo)` on the open stream. Native layouts follow [Linux statx](https://man7.org/linux/man-pages/man2/statx.2.html), [Apple attribute constants](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/attr.h), and [Windows FILE_STANDARD_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info).

Checks cover pre-existing aliases inside/outside the source and a link added between preflight and open. This does not freeze link count after inspection; the later identity-bearing source claim and exact manifest comparison protect deletion against ordinary path replacements. Windows and macOS implementations require native execution in their platform jobs; Linux evidence alone is insufficient.

### Bounded status and verification counts

`DirectoryContentScanner` streams entries iteratively, keeping only pending directories. Its default limits are 200,000 entries, depth 256 and five seconds measured between OS calls. Linked ancestors/root/children and native unsupported entry types are refused. Exceptions return no partial counts. `LockerService.Verify` runs this scan before archive inspection; `CountsComplete` is required for a valid result. CLI status/verify report unavailable counts and failure when scanning is incomplete. Locked-directory extra-entry inspection uses `Any` instead of allocating a list. This is not a snapshot, does not close parent-replacement races, cannot abort blocked OS calls and does not bound archive hashing.

### Archive source byte bounds

Creation sums source sizes against the 1 TiB logical extraction cap, then wraps every file in `ExactLengthReadStream` before handing it to the TAR writer. The wrapper exposes a fixed inspected length, caps reads to the remaining bytes, checks observed underlying length before/after reads, rejects early EOF, requires complete consumption and feeds the exact consumed bytes into the source manifest. This matters because [the .NET TAR writer copies its input stream to EOF](https://github.com/dotnet/runtime/blob/v10.0.9/src/libraries/System.Formats.Tar/src/System/Formats/Tar/TarHeader.Write.cs); its header length alone is not an input cap. Test-only source-reader injection exercises growth and truncation through the full archive creation/cleanup path.

An existing archive destination is retained if exclusive creation fails: cleanup is attempted only after this invocation successfully created its output. Source stability is established separately by comparing the exact archive-input manifest with the atomically claimed tree. A process retaining a native writable handle across that cutover is unsupported. Published and cleanup paths use stable identity and quarantine checks so a same-path replacement is preserved.

### Bounded source enumeration and empty archives

Source enumeration applies the 200,000-entry cap as entries arrive, before inspecting another entry. It no longer sorts/materializes each entire directory before checking the cap. The bounded source list is sorted in place once by ordinal relative name, preserving archive ordering without a second result list. An internal reduced cap supports boundary tests without creating hundreds of thousands of fixture files.

Empty lockers explicitly write the two zero TAR end blocks because `TarWriter` emits no final records when no entries were written. Extraction accepts a null TAR data stream only when the regular-file length is zero, creates that empty file and still authenticates the complete encrypted envelope before publication. This repairs new empty-locker creation and valid zero-length-file extraction; it does not introduce a compatibility reader for malformed historical empty archives.

### Current password verifier only

Under the prerelease breaking-change policy, the BCrypt verifier fallback and BCrypt.Net-Next dependency have been removed. Only the versioned PBKDF2-SHA256 verifier with the exact current work factor/salt/key sizes is accepted. Unsupported nonempty verifier strings fail explicitly; null/empty credentials still fail authentication. There is no legacy-verifier upgrade path. Standalone recovery of a current-format archive derives its key from the supplied archive password independently of database verifiers. A fixed BCrypt test vector checks rejection; service regression checks source preservation on unsupported-verifier lock refusal. NuGet locks must be regenerated and locked restore verified after dependency removal.

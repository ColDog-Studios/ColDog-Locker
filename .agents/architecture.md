# Architecture

ColDog Locker targets .NET 10. `Directory.Build.props` owns the application version and build settings; `Directory.Packages.props` owns NuGet versions. There is no exact SDK pin or NuGet lock-file policy; local builds use the installed SDK and CI requests the current `10.0.x` SDK. NuGet versions are centrally managed, while npm release tooling retains its lock file.

## Projects and ownership

| Project | Responsibility |
| --- | --- |
| Core | Locker models/copies, path/password validation, paths, semantic versions, generated AppInfo, embedded third-party credits |
| Services | SQLite, locker transformations/recovery, archive protocol, filesystem policy, settings, logging, watchers, initialization and updates |
| Cli | Command routing, automation, GUI launcher; references Core, Services and Tui |
| Avalonia | Desktop GUI; calls Core/Services directly, never shells out to CLI for recovery |
| Tui | Essential interactive terminal locker workflows |
| *.Tests | Core, Services, CLI and Avalonia regression suites |

Use `LockerService` for ordinary locker mutations. It owns copied snapshots and revision publication; never modify `Lockers` directly or bypass service validation with UI repository writes. Recovery and database maintenance use their dedicated service/repository methods.

## Startup and data

Help, version, About, GUI launch, standalone archive recovery, database backup and missing-registry restore bypass ordinary CLI initialization. `cdlocker gui` must work even when database initialization fails: GUI startup shows errors but leaves Tools > Backup and Recovery available.

Ordinary initialization creates private per-user data/log directories, loads settings and logging, initializes SQLite, loads registrations/pending journals and starts watchers. CLI commands disable automatic startup update checks; `update` performs an explicit check. GUI startup supports automatic checks according to settings.

CLI stdout/stderr use UTF-8 without a BOM. Python CLI test readers decode UTF-8 explicitly and the E2E runner emits UTF-8 logs; Windows ANSI defaults otherwise corrupt punctuation and Unicode paths between processes. Regression tests simulate a CP1252 parent locale, and parity E2E exercises accented, Greek and CJK locker names.

`AppPaths.LocalConfig` contains `settings.json`, `lockers.db`, logs and update staging. See [public data locations](../docs/platform-support.md#application-data-locations). `COLDOG_LOCKER_DATA_HOME` is an absolute base-directory override used by isolated validation; relative values fail. Both GUI and CLI new-locker creation honor `SettingsManager.Settings.DefaultLockerLocation`, initially `AppPaths.CdlDir`.

The database vacuum interval is a stored preference only; no automatic scheduler consumes it. Database optimization is currently explicit through CLI db-vacuum, GUI Settings or Backup and Recovery.

Settings writes use a temporary file/replacement. Malformed settings are backed up before defaults are recreated. Keep all setting keys/validation synchronized between CLI and SettingsDialog.

## Persistence and operation ownership

The current schema is defined by `LockerRepository.CurrentSchemaVersion` (7). `PRAGMA user_version` gates compatibility. SQLite names use the application-defined `CDL_NAME` ordinal-ignore-case collation; external maintenance tools must register it before indexed writes/integrity work. Each registration carries `Revision`; updates/deletes compare expected revision and stale snapshots fail without overwriting newer state.

Immediate transactions reject equal/nested locker paths, reserved locked/unlocked sibling paths and existing filesystem aliases. Each mutation also takes a per-user/per-locker lease shared across processes. Abandoned ownership transfers; the durable journal determines safe recovery. Lease serialization alone does not freeze external writers.

Pending journals record intent and filesystem phases before destructive transitions. Metadata and `MetadataCommitted` are written atomically under FULL-synchronous SQLite. Journal history and recovery attempts retain artifact paths; do not delete them to force a retry.

## Transformation invariants

1. Lock validates metadata, password, paths, filesystem identities and supported entry types. TAR reads are length-bounded; a manifest records exact names, types, metadata and bytes archived.
2. A complete authenticated archive is created in private staging and flushed. Capacity preflight fails before writing when available space is clearly insufficient.
3. Lock atomically claims the source tree beneath private staging, installs a sentinel at the old path and checks the exact manifest again before deletion. Concurrent ordinary create/overwrite/truncate/rename/delete changes abort and restore the changed source.
4. Once deletion starts, failures retain the complete archive and journal. A surviving partial directory must never count as complete rollback.
5. Unlock authenticates the entire stream into private staging, restores reproducible metadata, verifies output identity/digest, publishes without replacing another destination and commits metadata before cleanup.
6. Namespace transitions flush POSIX directory entries; Windows moves use write-through semantics. Cancellation is accepted only before source claim/plaintext publication. A late request completes the durable transition.
7. Cleanup quarantines and verifies stable volume/object identity before deletion. Same-path replacements and ambiguous retained output are preserved/refused.

Windows: ordinary ownership accepts the token's default owner as well as account SID. Private root ACL snapshots must remain exact; descendants inherit that private ACL. Restored publication becomes ordinary inheritance. A source moved under private staging may change inherited-rule representation; validate the private parent, identities, bytes and strict descendants rather than mistaking that representation change for corruption.

Unix: owner-only plaintext staging exists from first write; ordinary modes and modification times are authenticated/restored. Unsupported ownership, ACLs/xattrs or special permission bits fail before source deletion. Symlinks/reparse points, hard links, sparse/non-regular entries, unsafe roots and linked ancestors are refused on every supported platform.

Native writable handles surviving cutover and unsupported network/cloud/removable storage are outside the portable guarantee. See [platform limits](../docs/platform-support.md) and [security policy](../docs/security-features.md).

Native interop in `DurableFileSystem` and `FileSystemEntryPolicy` is intentional: managed moves do not expose directory fsync/Windows write-through flags, and pathname checks cannot replace no-follow/nonblocking opens plus handle-based type and link-count validation. Generic unmanaged-code advisories do not justify removing those safeguards. Broad exception handling is appropriate at the maintenance dialog's final UI boundary, where errors are displayed and busy/password state is restored; filesystem rollback catches remain limited to expected failures. `CheckBox.IsChecked` is nullable, so `== true` deliberately treats indeterminate as unchecked.

## Archive and recovery

Only archive version 2 and the current full-UTF-8 PBKDF2-SHA256 password verifier are accepted. No stable release exists; breaking changes are authorized, and legacy archive/BCrypt compatibility is not required. Current round-trip and failure-preservation guarantees remain required. See [protocol invariants and adversarial evidence](archive-protocol-review.md).

Standalone `RecoverArchive` requires no database, never overwrites output and preserves input. `RecoverOperation` authenticates a retained archive into a new destination and transactionally repairs registration/history. Preparation cancellation and committed finishing are phase-limited, verify prerequisites and change no files. Unknown/changed committed state is refused and preserved. Database snapshots contain metadata only; restore accepts an absent compatible registry and original locations, not merges/relocation.

## Updates and version identity

Downloads use private no-follow staging and verified SHA-256 digests. Before elevated installation, a root/administrator-owned private copy is rehashed and passed to the package consumer. Timeout covers streamed bodies separately. Stable-channel discovery rejects all prereleases, including RCs mislabeled latest. Signing/notarization is deferred.

Semantic release versions, prerelease sequences, commit-SHA build identity and publication rules are documented once in [release automation](release-automation.md). Build date/time are deliberately omitted. Package layout and tools belong in [packaging](packaging.md); UI behavior and parity belong in [GUI guidance](gui-plans.md).

# Public launch review — 2026-09-16

**Verdict: do not ship this as a stable application for irreplaceable files.** The application passes its existing tests, but a normal filesystem permission failure can make its rollback delete the only surviving archive after some original files have already been deleted. That alone blocks launch. Formatting is the easy part; the filesystem transaction model needs work.

Reviewed commit: `9d1a618f21d75e46b330ea94e232b740bc5a11ce` (`0.11.1-beta`). Review date is America/Detroit; execution logs cross into September 17 UTC. This is a maintainer review, not public security documentation. No application fixes are included.

## Scope and evidence

Source references use repository paths where qualified; otherwise filenames refer to the matching Services file. `Core/`, `Cli/`, and `Avalonia/` abbreviate the corresponding `ColDogLocker.*` project directories. Line numbers refer to the reviewed commit.

Reviewed the core validators, encryption/archive implementation, locker lifecycle and SQLite persistence, CLI/TUI/GUI entry points, updater, settings/logging/watchers, packaging definitions, CI/release workflows, tests, and user documentation. Findings marked **reproduced** were exercised against the current code in isolated disposable directories. **Source-confirmed** means the relevant control flow is visible in code, but the full user scenario was not executed. **Validation gap** means evidence is still required, not that failure has been demonstrated.

Local environment: Fedora 44 x64, .NET SDK 10.0.111, runtime 10.0.11, unprivileged UID 1000. The starting tracked worktree was clean.

| Check | Result |
| --- | --- |
| `dotnet test ColDogLocker.slnx -c Release --nologo` | 414 passed, 5 skipped, 0 failed: Core 159/5, Services 199, CLI 29, Avalonia 27. |
| `dotnet list ColDogLocker.slnx package --vulnerable --include-transitive --format json` | No known vulnerable packages reported for the nine solution projects through the configured NuGet feed. This does not audit the bundled runtime, WiX SDK, npm release tooling, or every native binary. |
| `dotnet format ColDogLocker.slnx --verify-no-changes --no-restore --verbosity minimal` | Failed: 15 whitespace errors, 2 encoding errors, 40 IDE1006 naming warnings, 2 IDE0060 unused-parameter warnings, 1 IDE2000 blank-line warning, across 17 C# files. |
| `dotnet publish ColDogLocker.Cli/ColDogLocker.Cli.csproj -c Release -r linux-x64 -o /tmp/cdl-launch-publish` | Succeeded; exercised the actual self-contained single-file configuration. |
| Repository CLI E2E script against that publish | Initially 1 passed / 32 failed because the script's isolated home directory did not exist. After creating that directory, 33 passed / 0 failed. See F16. |
| Targeted lifecycle/security probes | Reproduced partial-delete data loss, permission/metadata loss, archive omission of a newly added file, long-password aliasing, locked-name metadata mismatch, Unix root acceptance, and an ancestor-symlink path bypass. |

Not executed: Windows/macOS installers, clean Linux distro installs, ARM binaries, destructive power-loss tests, full GUI interaction on a real desktop, screen-reader testing, or a hosted CodeQL run. Repository branch protections and private vulnerability-reporting settings were not inspected. Do not describe these as passed.

## Findings requiring correction before stable launch

### F01 — Critical: rollback discards the only complete copy after partial deletion

**Reproduced.** `ColDogLocker.Services/Lockers/LockerService.cs:265`, `:650–680`.

Lock creates the archive and recursively deletes the source. Recursive deletion can remove some files and then fail. Rollback restores from the archive only if the entire original directory no longer exists. If a partially deleted directory still exists, rollback skips restoration and deletes the staged archive anyway.

A disposable locker containing a normal file and a non-writable child directory produced `UnauthorizedAccessException`; the normal file was gone, the child survived, and no locker archive remained. No crash, malicious input, or database corruption was necessary.

**Required fix:** never treat directory existence as proof of complete original contents. Retain the verified archive until restoration or completion is durably confirmed. Implement explicit transaction phases and a recovery record; do not delete recoverable data in generic cleanup.

**Acceptance:** fail deletion after the first successful unlink on each supported platform. All original bytes must remain recoverable, and the application must identify the recovery artifact. Include failed restoration and insufficient disk space.

### F02 — High: files written during locking can be silently omitted and then deleted

**Reproduced omission; subsequent deletion is source-confirmed.** `LockerArchiveService.cs:60`, `:209–275`; `LockerService.cs:265`.

The source tree is enumerated once. Per-file checks cover only listed files, only around each individual read. They do not detect a new file added after enumeration or a file modified after its own final check. The service subsequently deletes the entire live directory, including unarchived additions.

The probe started archiving an 8 MiB random file, waited for the archive to appear (after enumeration), then added `late.txt`. Archive creation succeeded; extracting it did not restore `late.txt`.

**Required fix:** establish a stable source/snapshot and prevent unsupported concurrent writers. Revalidate the complete manifest and retain the source or recovery copy when consistency cannot be proved. A final enumeration alone still leaves a race before deletion.

**Acceptance:** concurrent create, overwrite, truncate, rename, and delete tests, including changes to files already archived. Either restore every accepted byte or abort without losing originals.

### F03 — High: no durable recovery protocol for interrupted operations

**Source-confirmed.** `LockerService.cs:258–279`, `:357–405`; `Startup/AppInitializer.cs:57–65`; `LockerArchiveService.cs:742–755`.

Filesystem changes and SQLite changes are separate operations. A process exit between deleting plaintext and saving metadata leaves the database pointing at a missing unlocked directory. Interrupted unlock can leave plaintext staging/output while SQLite still reports the locker locked. Exception rollback cannot run after process termination. Startup only initializes/loads the database; it does not reconcile `.locking` or `.unlocking` artifacts. Archive close/ordinary flush is also not an explicit durable storage commit before originals are removed.

**Required fix:** persist transaction intent and phases, preserve recoverable copies, use appropriate durable flush/rename ordering, and reconcile pending operations at startup. Specify crash behavior for supported filesystems. Add safe shutdown handling while a locker operation is active; GUI Exit currently just calls `Close()` (`Avalonia/Views/MainWindow.axaml.cs:52`).

**Acceptance:** terminate a subprocess at every filesystem/database boundary and restart. Recover without hand-editing SQLite, without claiming leftover plaintext is locked, and without overwriting the only complete copy.

### F04 — High: unlocking weakens file permissions and destroys filesystem metadata

**Reproduced on Linux.** `LockerArchiveService.cs:171`, `:252–275`, `:279–333`.

Archive entries copy names, data, and modification times, but extraction writes ordinary directories/files without restoring modes or timestamps. With umask 022, a private directory changed from `0700` to `0755`, a private file from `0600` to `0644`, and an executable from `0700` to `0644`. A 2001 modification timestamp became the extraction time. Plaintext staging has the same default-permission problem. Other users can read restored secrets wherever parent traversal permissions permit it.

There is also no implemented preservation policy for Windows ACLs, alternate data streams, extended attributes, or other platform metadata. Those cases were not executed; reject unsupported input before deleting it, or explicitly support and test it.

**Required fix:** create staging privately from its first instant, preserve supported metadata, and apply permissions safely before making restored content available. Do not broaden existing confidentiality restrictions. Define and document supported filesystem features.

**Acceptance:** private files/directories, executable scripts, timestamps, ACLs and platform-specific metadata survive a round trip, or unsupported cases are rejected before destructive work.

### F05 — High: BCrypt and encryption disagree about what the password is

**Reproduced.** `Security/EncryptionHelper.cs:254–274`; `Core/Validation/PasswordFilter.cs:65–73`; `LockerArchiveService.cs:711`, `:815`.

The password filter has no byte-length limit. BCrypt verification accepted two passwords with the same first 72 ASCII bytes and different suffixes. PBKDF2 uses the complete supplied password. Consequently, a suffix typo can pass the check during locking, encrypt using a different key, and leave the user's originally chosen password unable to decrypt the archive. This is a password-consistency/data-availability failure; it does not prove decryption can be bypassed.

**Required fix:** adopt one versioned, full-password interpretation across verification and derivation. If temporarily imposing a BCrypt limit, enforce UTF-8 byte length everywhere and provide a compatibility strategy for existing long passwords. Do not silently truncate encryption input. [OWASP documents BCrypt's 72-byte limit](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#input-limits-of-bcrypt).

**Acceptance:** ASCII and multibyte passwords around the boundary; altered suffixes must fail verification and must never select a different encryption key after successful authentication.

### F06 — High: the Properties dialog lets users make locked archives unopenable

**Source-confirmed UI path; reproduced archive rejection.** `Avalonia/Views/Dialogs/LockerPropertiesDialog.cs:59–67`, `:125–128`; `LockerService.cs:162–173`; `LockerArchiveService.cs:444–450`.

Locked lockers cannot browse to another location, but their names remain editable. Saving changes SQLite/model `LockerName` without changing the authenticated archive metadata. Both verification and extraction require exact name equality. Renaming `Original` to `Renamed` produced “Locked archive metadata does not match locker metadata.” The UI reports the save as successful.

**Required fix:** forbid changes to identity-bound fields while locked at the service layer, or implement an authenticated rename workflow. Prefer a stable immutable archive identity and a separate display name. Explain whether editing an unlocked location moves data or merely repoints metadata; the current operation only repoints it.

**Acceptance:** rename through the actual dialog, restart, verify, and unlock successfully—or reject the edit before saving. Include duplicate names and persistence errors.

### F07 — High: destructive operations have no shared ownership or concurrency control

**Source-confirmed; competing-process failure not executed.** `LockerService.cs:26–54`, `:193–211`, `:220–405`; `LockerRepository.cs:247–275`; `Avalonia/ViewModels/MainWindowViewModel.cs:66–68`, `:118–189`.

The list lock protects list access, not filesystem operations. Returned snapshots contain the same mutable model objects. There is no cross-process per-locker lock, expected-state database update, or ownership marker on staging/output directories. GUI commands separately guard their own execution, but lock/remove/properties/refresh can still overlap; `IsBusy` is set for refresh/initialization, not the full mutation. A second CLI or GUI process bypasses all UI guards.

Two unlocks can pass the destination-existence check. If one creates the destination and another fails its move, the second rollback can delete the first operation's output while the old archive still exists. Competing cleanup/commit steps can then make the outcome worse. Similarly, removal can use stale unlocked state during locking.

**Required fix:** serialize operations per canonical locker across processes, reload state under that lock, use conditional database writes, and only clean artifacts owned by the current transaction. Prevent GUI shutdown/conflicting actions during unsafe phases.

**Acceptance:** simultaneous lock/unlock/remove/rename from independent processes and conflicting GUI commands. No operation may delete another operation's output or overwrite newer metadata.

### F08 — High: path protection misses Unix roots and follows protected ancestors through aliases

**Reproduced.** `Core/Validation/LockerPathFilter.cs:229–232`, `:273–289`; `LockerArchiveService.cs:209–221`, `:423–431`.

`TrimEnd('/')` turns `/` into an empty string before the Unix root check compares it with `/`. `ValidatePath("/")` returned no error. `/etc` also returned no error because the protected-system list is largely Windows-oriented. Actual damage still depends on OS permissions and subsequent archive checks; this is not a privilege-escalation claim.

Validation is lexical, and archive checks reject links at the root/entry itself but not every ancestor. A symlink in an allowed review directory pointing into a disposable `/tmp` directory made `Alias/Leaf` pass validation and archive successfully, although the real `/tmp/.../Leaf` path was rejected. The service can act through that alias. Lowercasing every path also misclassifies distinct Unix paths.

**Required fix:** preserve root identity, define platform-specific protections and comparison rules, validate resolved ancestors, and address link substitution between validation and use. Apply the same policy to deletion and metadata updates.

**Acceptance:** `/`, Unix protected directories, drive/UNC roots, case-distinct Unix paths, ancestor symlinks/junctions, and link replacement races. Exercise unsafe locations only with non-destructive validation or disposable targets.

### F09 — High: two lockers can own the same directory or overlapping trees

**Source-confirmed.** `LockerService.cs:123–146`, `:162–173`; `LockerRepository.cs:48–60`; `Avalonia/Views/Dialogs/NewLockerDialog.cs:91–112`.

The schema enforces unique names, not unique locations. Add/update validation checks name/path safety without checking ownership or ancestor/descendant overlap. The GUI can register an existing directory under another name, or place one locker inside another. Locking/removing one then invalidates the other's location and can include or delete its data.

**Required fix:** enforce canonical directory ownership and reject aliases/overlap at the service boundary, including metadata edits, while holding the operation lock. Decide explicitly whether nested lockers are supported; they currently lack a coordinated lifecycle.

**Acceptance:** same directory under different names, case aliases, symlink aliases, and ancestor/descendant registrations must be rejected or handled consistently without orphaning another locker.

### F10 — High: creation can produce archives that exceed its own extraction limit

**Source-confirmed; no terabyte fixture was written.** `LockerArchiveService.cs:44`, `:209–249`, `:308–311`.

Extraction rejects more than 1 TiB of total file content. Creation caps entry count but never checks cumulative source length against that same size limit. A sufficiently large locker can archive successfully, lose its plaintext source, and then be refused by the normal unlock path. Sparse files make logical size particularly relevant.

**Required fix:** enforce symmetric format limits before deletion, using checked logical-size accounting, and provide actionable size/free-space diagnostics. Preserve compatibility with any archives already created beyond the limit.

**Acceptance:** small injected limits that prove boundary behavior without allocating terabytes; cover sparse files, arithmetic overflow, and source growth.

### F11 — High: normal recovery depends on a database users are not taught to back up

**Source-confirmed product gap.** `LockerService.cs:351–355`; `LockerArchiveService.cs:114–139`; `Cli/Program.cs:59–74`; `docs/faq.md:73–75`.

An intact `locker.cdl` and the correct password are insufficient for the supported UI/CLI workflow after `lockers.db` is lost. Unlock requires a registered locker, matching identity/name, and a stored archive hash. There is no supported archive import/recovery command or database backup/restore command. The archive contains enough metadata to support a deliberately designed recovery path, but users currently need developer assistance. Generic “keep backups” advice does not explain this dependency.

**Required fix:** ship a tested recovery/import workflow that authenticates the archive before trusting recovered metadata, plus explicit backup/restore instructions covering archives and database state. Clarify compatibility with earlier per-file encrypted formats; the legacy encryption helper remains, but the current locker unlock path expects `locker.cdl`.

**Acceptance:** restore on a fresh profile with the original database absent and correct password available; reject wrong passwords/corrupt archives without damaging the original. Define which prerelease versions are supported for upgrade.

## Security hardening and operational fixes

### F12 — Medium: archive KDF policy needs review before freezing format version 1

**Source-confirmed.** `LockerArchiveService.cs:40`, `:491`, `:711`.

The archive uses PBKDF2-HMAC-SHA256 at 210,000 iterations. An offline attacker can test the archive directly; the separate BCrypt cost does not increase that attack cost. OWASP's current password-storage guidance lists 600,000 iterations for PBKDF2-HMAC-SHA256. This is a useful work-factor benchmark, not evidence that AES-GCM is broken or a universal encryption-format requirement. [OWASP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).

Benchmark supported hardware and select/document a defensible KDF policy. Keep readers compatible with old parameters while limiting attacker-controlled work factors; the current reader only accepts exactly 210,000. Obtain focused review of the custom chunk protocol, including authenticated termination, truncation/trailing data, chunk counter limits, and complete stream consumption. No independent full-protocol cryptanalysis was performed here. Clear derived keys/plaintext buffers on disposal and failure where feasible; the current archive streams retain managed key arrays.

### F13 — Medium: updater verification does not bind the bytes eventually installed

**Source-confirmed; replacement attack not executed.** `Updates/UpdateService.cs:514–525`, `:883–908`; `Updates/UpdateInstaller.cs:65–88`.

The downloader verifies the hash, closes the file, and saves it in Downloads. The installer subsequently accepts a path and checks existence; it ignores `UpdateDownloadResult.Sha256`. A file replaced between verification and installer use is executed/installed without revalidation, potentially after an elevation prompt. Exploitation requires write access to that file/directory or equivalent local influence; this is not an unauthenticated remote exploit.

Use private transaction-specific staging, reverify immediately before handoff, verify publisher/package signatures where supported, and design the privileged consumer boundary so a pathname replacement does not invalidate verification. A second hash alone does not eliminate the last race. Add a replacement test that proves the installer refuses changed bytes.

### F14 — Medium: update downloads can hang after response headers

**Source-confirmed.** `Updates/UpdateService.cs:213`, `:529`, `:843–878`.

`HttpClient.Timeout` is 30 seconds, but downloads use `ResponseHeadersRead` and then read the body with only the caller's token. Callers using the default token have no body deadline. A server or stalled connection can return headers and stop indefinitely. [Microsoft explicitly documents this timeout boundary](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpcompletionoption?view=net-10.0).

Add a linked total/idle timeout for the streaming body, distinguish cancellation from timeout, and clean up temporary downloads. Test a server that sends headers immediately and never completes its body.

### F15 — Medium: basic CLI commands depend on writable state and network initialization

**Source-confirmed.** `Cli/Program.cs:35–41`; `Startup/AppInitializer.cs:34–71`; `Configuration/SettingsManager.cs:158`; `Updates/UpdateService.cs:213`.

Even `--version` and help initialize settings, database, watchers, and an enabled-by-default update check before dispatch. They can wait on the network and fail when local state is broken. Initialization also runs outside the CLI's top-level `try`, so startup errors escape its normal error/exit handling. The update-check result is discarded during initialization.

Route stateless help/version first, handle initialization exceptions consistently, and move automatic update checks out of command startup or cache/background them. Acceptance: help/version work promptly offline and with unwritable/corrupt application state; operational commands report actionable initialization errors.

### F16 — Medium: published-artifact tests do not currently exercise the shipped configuration reliably

**Reproduced test-harness failure; source-confirmed pipeline gap.** `.github/scripts/cli_e2e.py:106–117`; `.github/workflows/test.yml`; `.github/workflows/release.yml`.

The script sets an isolated home path without creating it. The self-contained single-file Linux binary failed with exit 159 before managed startup because native-library extraction could not find a writable home. Creating the test home made all 33 checks pass. CI's CLI publish command omits a RID, so it does not exercise the packaging configuration that exposed this problem.

Create every isolated directory needed by the harness and run E2E on actual package payloads for each target. Release's own test job runs on Linux; packaging jobs build other targets but do not install and exercise them. PR checks help, but manual dispatch/direct pushes must not silently bypass release validation. Verify branch protections in GitHub rather than assuming `.agents/release-automation.md` enforces them.

### F17 — Medium: Linux packages omit native dependency declarations

**Source-confirmed packaging gap; clean-machine failure not tested.** `ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj:100–111`, `:157–158`.

DEB control data has no `Depends`. RPM sets `AutoReqProv: no` and provides no explicit `Requires`. Bundling .NET does not establish that desktop/native runtime dependencies exist on a target system. The distribution notes themselves leave dependency identification open.

Determine minimum supported distros/native libraries using clean installations, declare dependencies, then install/upgrade/remove both architectures and exercise CLI, TUI, GUI launch, desktop entries, and updater handoff. Do not claim cross-distro support from successful compilation alone.

### F18 — Medium: release-candidate builds are delivered through the stable channel

**Source-confirmed intentional policy requiring correction or an explicit product decision.** `.github/workflows/release.yml:60–72`; `Updates/UpdateService.cs:538–542`; `.agents/release-automation.md`.

The workflow marks `rc` versions as full releases/latest. The stable updater trusts `releases/latest` without independently excluding semantic prerelease versions. A stable user can therefore receive a release candidate. The maintainer documentation agrees with the workflow, so this is a policy problem rather than an undocumented implementation accident.

Keep RCs on an opt-in prerelease channel unless the public channel contract deliberately promises otherwise. Test actual GitHub release flags plus client selection, including stable-to-RC and RC-to-stable upgrades.

### F19 — Medium: package provenance and release reproducibility are incomplete

**Source-confirmed / validation gap.** `.github/workflows/release.yml:7–8`, `:315–327`; `Directory.Build.props:5–7`; `README.md:76–78`; `.agents/distribution-plan.md`.

Windows/macOS packages are explicitly unsigned; macOS is unnotarized. Workflows reference mutable action tags and grant release-wide `contents: write`; npm transitive dependencies for changelog generation are not locked. No checked-in SDK pin or NuGet lock files establish a fully repeatable dependency/toolchain baseline, and wall-clock version fields change build output. These are supply-chain and support gaps, not evidence of compromise.

Before broad stable distribution, establish signing/notarization or a documented, consciously accepted distribution limitation; narrow write permissions to publishing; pin action revisions and release-tool dependencies; produce a dependency/native-runtime inventory and provenance/checksum artifacts. Validate bundled runtime servicing separately from the NuGet audit. Establish a signing-key/release credential recovery procedure. Inventory bundled third-party notices/licenses; this review did not perform a legal compliance determination.

## Code quality, performance, and user experience

### F20 — Medium: expensive work is repeatedly performed on the GUI thread or across whole trees

**Source-confirmed; no performance benchmark collected.** `Avalonia/ViewModels/MainWindowViewModel.cs:104–110`, `:361–369`, `:421–445`; `Avalonia/Views/Dialogs/LockerPropertiesDialog.cs:65`, `:243–269`; `LockerService.cs:553–555`; `LockerArchiveService.cs:82`, `:249`, `:778–790`.

BCrypt cost-14 hashing runs on the UI thread when creating a locker. Opening Properties synchronously calculates recursive directory size, with no reparse-point/cycle policy. Refresh recalculates every locker's size; verification materializes complete file/directory arrays. Archive creation sorts entries twice, uses maximum gzip compression unconditionally, rereads the archive for hashing, and constructs AES/nonce/AAD/ciphertext buffers per chunk.

Move hashing and property scans off the UI thread; add cancellation, bounded traversal, and a policy for links. Cache or lazily calculate sizes and distinguish “unknown” from zero. Profile many-small-file and large/incompressible workloads before changing compression, streaming hash, buffer pooling, or AES lifetime. Those latter changes are optimization candidates, not demonstrated bottlenecks. Add operation progress, safe cancellation points, and free-space/error reporting; the existing demonstration progress dialog is not wired into locker transformations.

### F21 — Medium: service state can diverge after persistence failures

**Source-confirmed.** `LockerService.cs:79–95`, `:421–460`; `LockerRepository.cs:48–60`, `:168`, `:340`.

`ChangePassword` mutates the in-memory hash before persisting and does not restore it on failure. Unlike CLI validation, the service itself only checks that the new password is nonempty. `LoadLockers` swallows read failures and leaves stale state available; consumers can present a successful refresh or empty list instead of an operational failure. SQLite's case-sensitive unique-name constraint also disagrees with case-insensitive lookup, so alternate registration paths can introduce ambiguous names.

Persist validated proposed state before publishing it to shared models, return reload failures to callers, and make uniqueness consistent with name lookup. Add failed-write/reload and case-variant registration tests. Replace snapshots of shared mutable objects with immutable values or explicitly synchronized state.

### F22 — Low: formatting and exception handling create unnecessary review noise

**Reproduced formatting failure / source-confirmed cleanup.** `.editorconfig`; `LockerService.cs:175–185`, `:281–289`; `LockerArchiveService.cs:91–100`; `Core/Environment/AppPaths.cs:26–30`.

The configured formatter does not pass. Examples include `LockerArchiveService.cs:272`, dialog object initializers, and encoding in `Avalonia/Program.cs` and `ViewModels/ViewModelBase.cs`. Many filtered catches are followed by a general catch performing the same rollback/log/rethrow, doubling code without changing behavior. Broad silent cleanup catches also hide whether sensitive plaintext was actually removed.

Run formatting intentionally, align naming rules with intended constants/fields, and enforce verification in CI. Consolidate identical catches; preserve contextual errors and surface failed sensitive cleanup. Remove or clearly isolate unused legacy encryption paths after confirming compatibility needs. This work should follow the data-loss fixes, not substitute for them.

### F23 — Medium: public security documentation overstates several guarantees

**Source-confirmed.** `docs/security-features.md:14–18`, `:28–35`, `:105–123`; `docs/faq.md:69–75`; `.agents/architecture.md`; `.agents/distribution-plan.md`.

The security document says the archive header contains an original archive length; the current header does not. It says Unix `/` is blocked; the reproduced validator accepts it. “Does locking delete my files? No” is a poor answer when locking deliberately deletes plaintext and can currently lose data. The documentation does not explain database-dependent recovery, metadata loss, unsupported filesystem features, or plaintext remnants in snapshots/backups/deleted blocks. Ordinary deletion is not secure erasure.

Correct guarantees to match tested behavior, explain recoverability and at-rest threat boundaries, document actual Linux/macOS data locations and supported OS/filesystem limits, and provide a backup/restore drill. Keep maintenance detail in `.agents/`: its distribution/architecture notes also contain stale claims about trimmed CLI publication and single-file Windows packaging, contrary to the current project definitions.

## Remaining launch validation

These are required evidence, not additional demonstrated vulnerabilities:

- Record install, upgrade, downgrade, uninstall, and reinstall results on supported Windows/macOS/Linux versions and x64/ARM64. Include unsigned-package prompts and no-runtime machines. Check Windows cleanup explicitly: `Product.wxs:87–95` recursively removes metadata and the default locker directory when opted in; users need a clear data-loss warning and upgrade-safe conditions.
- Exercise realistic storage: USB removal, network shares if supported, full disks, read-only media, long/Unicode names, locked files, sparse files, huge entry counts, and denied permissions. State unsupported cases before users put data there.
- Test real GUI keyboard navigation, focus, screen-reader names for icon buttons, scaling/high contrast, long localized text, error dialogs, and copy/paste/password-manager use. Headless tests do not prove accessibility or desktop usability.
- Document the supported-version/security-fix policy and confirm that GitHub private vulnerability reporting is enabled. Maintain an incident response and release rollback procedure that does not downgrade users into an incompatible archive/database format.
- Audit release artifacts, not only source dependencies: native libraries, bundled runtimes, license notices, signing/provenance, release asset digests, and package metadata. No known NuGet advisory is a narrow result, not a clean bill of health.

## Reproduction notes

Probes used a temporary external .NET console project referencing `ColDogLocker.Services.csproj`, existing public service/archive APIs, a fresh GUID-named directory under the review user's profile, and disposable content. They did not alter existing lockers. Test content was removed afterwards. Permission tests require an unprivileged Unix user and umask 022.

Observed output:

```text
PATH / = ALLOWED
PATH /etc = ALLOWED
ROUNDTRIP root:700->755 file:600->644 executable:700->644
RENAMED extraction: Locked archive metadata does not match locker metadata.
PARTIAL lock: UnauthorizedAccessException
PARTIAL deleted-original=True remaining=True archive-count=0
LIVE WRITER source-late=True archived-late=False
ANCESTOR LINK real-path=Cannot lock directories under: /tmp alias-path=ALLOWED archive-created=True
LONG PASSWORD different-suffix-verifies=True filter=ACCEPTED
```

Minimal recipes for future regression tests:

1. **F01:** create a writable locker root with `a-deletable.txt` and `z-readonly/remaining.txt`; chmod the child directory to 0500. Construct a `LockerModel` with a valid password hash and call `LockerService.Lock`. The failure occurs before database persistence. Verify the first file's bytes are recoverable after the exception, not merely that the root exists. Restore child permissions for cleanup.
2. **F02:** create an 8 MiB incompressible source file. Start `CreateFromDirectory` on a worker, wait for the archive file to appear, then add `late.txt`. Await completion and extract to a fresh directory. Confirm the omitted file, then test the corrected service's handling without sacrificing originals.
3. **F04:** create a 0700 source directory, a 0600 file dated 2001-01-01 UTC, and a 0700 executable. Call `CreateFromDirectory` and `ExtractToDirectory`. Compare content, modes, and timestamps independently. Current output is 0755/0644/0644 and a new timestamp.
4. **F05:** use `"Kestrel!8" + new string('x', 72) + "A"` and the same expression ending in `"B"`. Hash the first with `EncryptionHelper.HashPassword`; the second currently verifies against that hash. Both pass the current strength filter. Add full lock/unlock tests after correcting password semantics.
5. **F06:** archive a model named `Original`, change only its name to `Renamed`, and extract with the same password. Current extraction rejects the mismatch. Add the GUI save/restart/unlock case, since the current dialog permits that exact metadata change.
6. **F08:** call `ValidatePath` on `/` and `/etc` without performing filesystem operations there. Separately create a disposable `/tmp/.../Leaf`, link an allowed parent `Alias` to its parent, and validate/archive `Alias/Leaf`. The real path is blocked while the alias succeeds. Remove the symlink itself before cleaning the disposable target.

## Release gate

Resolve F01–F11 with regression coverage before treating this as safe storage for public users. Close the medium findings or record explicit, justified scope decisions where applicable. Then run the failure/recovery matrix and installed-artifact tests on all supported platforms. Formatting and a green happy-path suite cannot compensate for deleting the only good copy of someone's files.

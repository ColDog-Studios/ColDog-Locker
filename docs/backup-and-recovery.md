# Backup and Recovery

ColDog Locker is prerelease software. Keep independent, tested copies of important files. Detected concurrent changes abort locking, but writers retaining native handles across the source cutover and interrupted operations can still cause data loss; a recovery journal does not guarantee recovery after power loss.

## Make a complete backup

A complete backup needs both your files and the information needed to find and decrypt them:

1. Stop locker operations and close other app windows. Close programs writing into unlocked lockers and pause folder synchronization while collecting the backup.
2. Copy each locked locker's `locker.cdl` archive to independent storage. Back up unlocked files separately. Include retained artifacts reported by `recovery-list` and `recovery-history` if any operations need recovery.
3. Run `cdlocker db-backup <new-directory>` to save registration, password verifiers and recovery records. The parent directory must already exist. This command does not copy your files or freeze their contents.
4. Keep the original archive passwords in your password manager. Changing a locker password later does not change the password of an older archive backup.
5. Test each archive backup by restoring it into a new directory and inspecting its files. Protect the restored plaintext and the backup storage appropriately.

For example, in a Unix shell:

```bash
mkdir -p "$HOME/ColDogLockerBackups"
cdlocker db-backup "$HOME/ColDogLockerBackups/registry-2026-09-21"
```

That example saves only database metadata. Copy your archives/files separately; a backup on the same disk does not protect against loss of that disk. The database backup is not encrypted and contains names, paths and password verifiers.

An encrypted backup still needs its original password. Neither `db-restore` nor any recovery command resets an archive password.

## Test or extract an archive without the database

`recover` accepts archive format version 2 only; older version 1 archives are unsupported in this prerelease. It authenticates an accepted archive and extracts files into a new destination. It works without loading the locker database, preserves the input archive and refuses an existing destination. It does not register the restored folder or resolve pending operations.

```bash
cdlocker recover "/path/to/backup/locker.cdl" "$HOME/RecoveredLocker"
```

The destination's parent must exist. Enter the original archive password at the prompt. Inspect the recovered files and keep the archive until you have a separate verified backup. `verify` checks an existing registration and archive hash without a password; it does not replace this recovery test.

## After an interrupted lock or unlock

Stop changing the affected folders. Do not relock a surviving partial source, delete staging folders, edit database rows, or replace the database to force a retry. Preserve every source, target and staging path reported by the application.

```bash
cdlocker recovery-list
```

Use the operation ID, kind and phase in that output to choose a supported action:

| Recorded state | Action |
| --- | --- |
| Lock at `Preparing` or `ArchiveReady`; unlock at `Preparing` | `recovery-cancel <operation-id>` can resolve preparation if the source still exists, the target is absent and registration still matches. It preserves all files. Check the originals before retrying. |
| Lock or unlock at `MetadataCommitted` | `recovery-finish <operation-id>` verifies the recorded committed output and resolves the journal without changing files. Unlock verification can work after the old archive was removed. |
| Any other unfinished state with a complete retained archive | `recovery-restore <operation-id> <archive.cdl> <new-destination>` can authenticate the archive, restore to a separate new folder and repair registration. |
| Database unavailable, or an archive that is not associated with a usable pending record | Use standalone `recover` for file extraction. Registration and journal repair remain separate. |
| No usable archive, or `recovery-finish` refuses changed output | Preserve the surviving files and records. The app has no automatic resolution for every such state; use an independent backup and seek assistance before cleanup. |

Commands refuse unsupported or ambiguous states. A refusal is not permission to remove the journal or recovery files. Partially written archives may be unusable; during preparation the original source has not yet been removed by that operation.

For `recovery-restore`, choose an archive at the recorded source path for an unlock, or staging/target path for a lock. The destination must have the original locker name, be outside the recorded paths, and have an existing parent. For example, after creating `$HOME/Recovered`, substitute the actual operation ID and recorded archive path:

```bash
cdlocker recovery-restore <operation-id> "/recorded/staging/locker.cdl" "$HOME/Recovered/MyLocker"
cdlocker recovery-history
```

Enter the archive password when prompted. After success, reload other app windows. Inspect the restored files and retain an independent backup before considering cleanup of old artifacts. Recovery preserves original source and staging copies, which may contain plaintext; locking the recovered folder does not encrypt those other copies.

## Restore a missing registry

Close other app instances first. `db-restore` can restore a compatible database backup only when the current registry and SQLite sidecar files are absent. It refuses to replace an existing registry.

```bash
cdlocker db-restore "/path/to/registry-backup/lockers.db"
cdlocker recovery-list
cdlocker list
```

The backup must use the current database schema and retain the original file locations. Restore checks ordinary registrations against those locations and the recorded archive hashes, but does not authenticate archives with a password or prove that unlocked contents are unchanged. Pending recovery records are preserved.

If paths have moved, the registry already exists, or restore refuses an archive mismatch, use standalone `recover` into a new destination to retrieve files. Do not delete the current registry to make `db-restore` accept an older backup.

See the [CLI reference](cli-reference.md) for each command's arguments and restrictions.

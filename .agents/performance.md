# Performance baselines

These are measurements of a development worktree, not release guarantees or comparative optimization claims. The executable SHA-256 in each report identifies the measured binary; its displayed Git commit alone does not capture uncommitted remediation changes.

## Reproduce the CLI workloads

Publish the CLI for the test host, then run the opt-in harness from the repository root:

```bash
dotnet publish ColDogLocker.Cli/ColDogLocker.Cli.csproj -c Release -r linux-x64 -o /tmp/cdl-benchmark-publish
python3 .github/scripts/locker_benchmark.py \
  --cli /tmp/cdl-benchmark-publish/cdlocker \
  --output /tmp/cdl-performance-new.json
```

The output must not already exist. Defaults are 5,000 files of 4 KiB each and one 256 MiB file, with three lock/unlock cycles per workload. `--small-files`, `--large-mib` and `--repeats` adjust these sizes. Fixtures use seeded pseudorandom bytes and isolated app-data directories under an exclusively created directory in the user's home. Every cycle compares all restored file names and SHA-256 values, and requires no pending operation journals. Successful runs remove their generated fixtures; failed runs retain them for investigation. Each CLI subprocess has the E2E helper's 120-second timeout.

Timings include process startup, password verification/KDF, archive processing, durable file writes, operation journaling and cleanup. Fixture creation and subsequent verification are excluded. OS caches are uncontrolled; these are sequential local runs, not cold-cache measurements. RSS, CPU samples, GUI responsiveness, network filesystems, disk-full behavior and cross-platform results require separate measurement. No CI timing threshold is imposed because machine/storage variance would make one misleading.

## Linux x64 baseline, September 20, 2026 (America/Detroit)

Raw report: [2026-09-20-linux-x64.json](benchmarks/2026-09-20-linux-x64.json). Captured at September 21 UTC. Host: Linux x64, btrfs, 20 logical CPUs. All six cycles passed content verification and journal-cleanup checks.

| Workload | Input | Median lock | Median unlock |
| --- | --- | --- | --- |
| Many small files | 5,000 × 4 KiB, 19.53 MiB total | 1.971 s | 7.102 s |
| Large incompressible file | 256 MiB | 9.686 s | 1.936 s |

The large-file archive was approximately 256.14 MiB, so this fixture did not benefit from compression. These elapsed times do not attribute costs to compression, cryptography, SQLite, metadata restoration or file flushing. Profile those stages before changing compression policy, buffers, AES object lifetimes or durability behavior. In particular, do not remove flushes just to improve small-file timing.

The display-size cache has separate correctness tests for expiry, explicit refresh bypass, invalidation, bounded capacity and cancellation. GUI latency and cache performance with hundreds/thousands of registrations have not been benchmarked yet.

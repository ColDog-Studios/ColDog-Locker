#!/usr/bin/env python3
"""Reproducible, opt-in published-CLI workloads; verifies bytes after every cycle."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from cli_e2e import CliE2E


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run_workload(harness: CliE2E, name: str, files: int, bytes_per_file: int, repeats: int) -> dict:
    directory = harness.create_locker_with_name(name)
    expected = {}
    generator = random.Random(20260920)
    for index in range(files):
        path = directory / f"group-{index // 100:04d}" / f"file-{index:06d}.bin"
        path.parent.mkdir(exist_ok=True)
        with path.open("wb") as stream:
            remaining = bytes_per_file
            while remaining:
                chunk = generator.randbytes(min(1024 * 1024, remaining))
                stream.write(chunk)
                remaining -= len(chunk)
        expected[path.relative_to(directory).as_posix()] = digest(path)

    samples = []
    for cycle in range(repeats):
        started = time.perf_counter()
        harness.run_cli("lock", name, "--password", harness.password)
        lock_seconds = time.perf_counter() - started
        archive = directory.parent / f".{name}" / "locker.cdl"
        archive_bytes = archive.stat().st_size
        started = time.perf_counter()
        harness.run_cli("unlock", name, "--password", harness.password)
        unlock_seconds = time.perf_counter() - started
        started = time.perf_counter()
        actual = {path.relative_to(directory).as_posix(): digest(path)
                  for path in directory.rglob("*") if path.is_file()}
        if actual != expected:
            raise AssertionError(f"Restored names/content differ for {name}, cycle {cycle + 1}")
        harness.no_pending_operations()
        samples.append({"cycle": cycle + 1, "lock_seconds": lock_seconds,
                        "unlock_seconds": unlock_seconds, "archive_bytes": archive_bytes,
                        "verification_seconds": time.perf_counter() - started})
        print(f"{name} {cycle + 1}/{repeats}: lock={lock_seconds:.3f}s unlock={unlock_seconds:.3f}s; bytes verified", flush=True)

    return {"name": name, "files": files, "source_bytes": files * bytes_per_file,
            "median_lock_seconds": statistics.median(sample["lock_seconds"] for sample in samples),
            "median_unlock_seconds": statistics.median(sample["unlock_seconds"] for sample in samples),
            "samples": samples}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New JSON report path; never overwritten")
    parser.add_argument("--small-files", type=int, default=5000)
    parser.add_argument("--large-mib", type=int, default=256)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if min(args.small_files, args.large_mib, args.repeats) <= 0:
        parser.error("workload sizes and repeats must be positive")
    cli = args.cli.resolve(strict=True)
    if args.output.exists():
        parser.error("output already exists")
    root = Path(tempfile.mkdtemp(prefix="cdl-benchmark-", dir=Path.home()))
    print(f"Isolated fixtures: {root}", flush=True)
    harness = CliE2E(cli, root)
    try:
        report = {"captured_utc": datetime.now(timezone.utc).isoformat(),
                  "platform": platform.platform(), "architecture": platform.machine(),
                  "logical_cpus": os.cpu_count(), "cli_sha256": digest(cli),
                  "cli_version": harness.output(harness.run_cli("--version")),
                  "method": "Sequential local runs, seeded incompressible fixtures, uncontrolled OS caches. Timings include process startup, KDF, archive I/O, journaling and cleanup; fixture generation and post-unlock verification excluded. No RSS/CPU profiling or cold-cache claim.",
                  "workloads": []}
        if shutil.which("findmnt"):
            filesystem = subprocess.run(["findmnt", "-n", "-o", "FSTYPE", "-T", str(root)],
                                        capture_output=True, text=True, check=False, timeout=10)
            report["filesystem"] = filesystem.stdout.strip()
        for name, files, size in (("SmallFiles", args.small_files, 4096),
                                  ("LargeFile", 1, args.large_mib * 1024 * 1024)):
            report["workloads"].append(run_workload(harness, name, files, size, args.repeats))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    except BaseException:
        print(f"Benchmark failed; isolated fixtures and recovery evidence retained at {root}", flush=True)
        raise
    else:
        # All data below this exclusively created directory is generated test data.
        shutil.rmtree(root)
    print(f"Report: {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Kill real locker subprocesses at each durable transaction boundary and recover."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path


PASSWORD = "Crash-boundary@5821!"
PAYLOAD = b"durable crash-boundary payload\n" * 128
LOCK_BOUNDARIES = (
    "Lock.JournalPrepared",
    "Lock.ArchiveDurable",
    "Lock.ArchiveReady",
    "Lock.SourceRemovalStarted",
    "Lock.SourceClaimed",
    "Lock.SourceSentinelDurable",
    "Lock.SourceDeleted",
    "Lock.ArchivePublished",
    "Lock.Published",
    "Lock.MetadataCommitted",
    "Lock.JournalCleared",
)
UNLOCK_BOUNDARIES = (
    "Unlock.JournalPrepared",
    "Unlock.ExtractionDurable",
    "Unlock.ExtractionReady",
    "Unlock.PlaintextPublished",
    "Unlock.Published",
    "Unlock.MetadataCommitted",
    "Unlock.ArchiveDeleted",
    "Unlock.JournalCleared",
)
RECOVERY_BOUNDARIES = (
    "Recovery.AttemptPrepared",
    "Recovery.ExtractionDurable",
    "Recovery.PlaintextPublished",
    "Recovery.MetadataCommitted",
)


class CrashBoundaryCheck:
    def __init__(self, root: Path, cli: Path, probe: Path) -> None:
        self.root = root
        self.cli = cli
        self.probe = probe

    def environment(self, directory: Path) -> dict[str, str]:
        app = directory / "app"
        env = os.environ.copy()
        locations = {
            "LOCALAPPDATA": app / "local",
            "APPDATA": app / "roaming",
            "USERPROFILE": app / "profile",
            "HOME": app / "home",
            "XDG_DATA_HOME": app / "xdg-data",
            "XDG_CONFIG_HOME": app / "xdg-config",
        }
        for key, path in locations.items():
            path.mkdir(parents=True, exist_ok=True)
            env[key] = str(path)

        settings = {
            "DevMode": False,
            "AutoUpdate": False,
            "LogLevel": "Info",
            "EnableFileLogging": False,
            "DefaultLockerLocation": str(directory),
        }
        for data_root in (locations["LOCALAPPDATA"], locations["XDG_DATA_HOME"]):
            settings_dir = data_root / "ColDog Studios" / "ColDog Locker"
            settings_dir.mkdir(parents=True, exist_ok=True)
            (settings_dir / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
        return env

    def run_cli(self, env: dict[str, str], *args: str, retry_abandoned: bool = True) -> subprocess.CompletedProcess[str]:
        command = [str(self.cli), *args]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120, check=False)
        combined = result.stdout + result.stderr
        if retry_abandoned and result.returncode != 0 and "terminated unexpectedly" in combined:
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120, check=False)
            combined = result.stdout + result.stderr
        if result.returncode != 0:
            raise AssertionError(f"Command failed: {' '.join(command)}\n{combined}")
        return result

    def create_locker(self, directory: Path, env: dict[str, str], name: str) -> Path:
        self.run_cli(env, "new", name, "--path", str(directory), "--password", PASSWORD)
        source = directory / name
        (source / "payload.bin").write_bytes(PAYLOAD)
        return source

    @staticmethod
    def database(directory: Path) -> Path:
        matches = list((directory / "app").rglob("lockers.db"))
        if len(matches) != 1:
            raise AssertionError(f"Expected one database, found {matches}")
        return matches[0]

    def kill_at(self, env: dict[str, str], directory: Path, operation: str, identity: str,
                boundary: str, *extra: str) -> None:
        marker = directory / f"{boundary}.ready"
        command = ["dotnet", str(self.probe), operation, identity, boundary, str(marker), PASSWORD, *extra]
        process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and not marker.is_file():
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    raise AssertionError(
                        f"Probe exited before {boundary} (exit {process.returncode})\n{stdout}\n{stderr}"
                    )
                time.sleep(0.005)
            if not marker.is_file():
                raise AssertionError(f"Timed out waiting for {boundary}")
            if marker.read_text(encoding="utf-8") != boundary:
                raise AssertionError(f"Probe signaled the wrong boundary for {boundary}")
            process.kill()
            process.communicate(timeout=30)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=30)

    @staticmethod
    def pending(database: Path) -> tuple[str, str, Path, Path, Path] | None:
        with sqlite3.connect(database) as connection:
            row = connection.execute(
                "SELECT OperationId, Phase, SourcePath, TargetPath, StagingPath FROM LockerOperations"
            ).fetchone()
        if row is None:
            return None
        return row[0], row[1], Path(row[2]), Path(row[3]), Path(row[4])

    @staticmethod
    def assert_payload(path: Path) -> None:
        payload = path / "payload.bin"
        if not payload.is_file() or hashlib.sha256(payload.read_bytes()).digest() != hashlib.sha256(PAYLOAD).digest():
            raise AssertionError(f"Recovered payload differs at {path}")

    def resolve_lock(self, directory: Path, env: dict[str, str], name: str, database: Path) -> None:
        pending = self.pending(database)
        if pending is None:
            self.run_cli(env, "unlock", name, "--password", PASSWORD)
            self.assert_payload(directory / name)
            return

        operation_id, phase, source, target, staging = pending
        if phase in ("Preparing", "ArchiveReady") and source.is_dir():
            self.run_cli(env, "recovery-cancel", operation_id)
            self.assert_payload(source)
            return
        if phase == "MetadataCommitted":
            self.run_cli(env, "recovery-finish", operation_id)
            self.run_cli(env, "unlock", name, "--password", PASSWORD)
            self.assert_payload(directory / name)
            return

        archives = [path / "locker.cdl" for path in (staging, target) if (path / "locker.cdl").is_file()]
        if len(archives) != 1:
            raise AssertionError(f"Expected one complete retained archive, found {archives}")
        parent = directory / "recovered"
        parent.mkdir()
        destination = parent / name
        self.run_cli(env, "recovery-restore", operation_id, str(archives[0]), str(destination), "--password", PASSWORD)
        self.assert_payload(destination)

    def lock_boundary(self, boundary: str) -> None:
        with tempfile.TemporaryDirectory(prefix="cdl-lock-crash-", dir=self.root) as temporary:
            directory = Path(temporary)
            env = self.environment(directory)
            name = "LockBoundary"
            source = self.create_locker(directory, env, name)
            self.kill_at(env, directory, "lock", name, boundary)
            self.resolve_lock(directory, env, name, self.database(directory))
            if source.exists() and (source / "payload.bin").exists():
                self.assert_payload(source)

    def unlock_boundary(self, boundary: str) -> None:
        with tempfile.TemporaryDirectory(prefix="cdl-unlock-crash-", dir=self.root) as temporary:
            directory = Path(temporary)
            env = self.environment(directory)
            name = "UnlockBoundary"
            self.create_locker(directory, env, name)
            self.run_cli(env, "lock", name, "--password", PASSWORD)
            self.kill_at(env, directory, "unlock", name, boundary)
            database = self.database(directory)
            pending = self.pending(database)
            if pending is None:
                self.assert_payload(directory / name)
                return

            operation_id, phase, source, _, _ = pending
            if phase == "Preparing":
                self.run_cli(env, "recovery-cancel", operation_id)
                self.run_cli(env, "unlock", name, "--password", PASSWORD)
                self.assert_payload(directory / name)
            elif phase == "MetadataCommitted":
                self.run_cli(env, "recovery-finish", operation_id)
                self.assert_payload(directory / name)
            else:
                archive = source / "locker.cdl"
                parent = directory / "recovered"
                parent.mkdir()
                destination = parent / name
                self.run_cli(env, "recovery-restore", operation_id, str(archive), str(destination), "--password", PASSWORD)
                self.assert_payload(destination)

    def recovery_boundary(self, boundary: str) -> None:
        with tempfile.TemporaryDirectory(prefix="cdl-recovery-crash-", dir=self.root) as temporary:
            directory = Path(temporary)
            env = self.environment(directory)
            name = "RecoveryBoundary"
            self.create_locker(directory, env, name)
            self.kill_at(env, directory, "lock", name, "Lock.SourceDeleted")
            database = self.database(directory)
            pending = self.pending(database)
            if pending is None:
                raise AssertionError("Interrupted lock did not retain an operation")
            operation_id, _, _, target, staging = pending
            archives = [path / "locker.cdl" for path in (staging, target) if (path / "locker.cdl").is_file()]
            if len(archives) != 1:
                raise AssertionError(f"Expected one recovery archive, found {archives}")

            first_parent = directory / "first-recovery"
            first_parent.mkdir()
            first_destination = first_parent / name
            self.kill_at(env, directory, "recovery", operation_id, boundary, str(archives[0]), str(first_destination))
            if self.pending(database) is None:
                self.assert_payload(first_destination)
                return

            second_parent = directory / "second-recovery"
            second_parent.mkdir()
            second_destination = second_parent / name
            self.run_cli(env, "recovery-restore", operation_id, str(archives[0]), str(second_destination), "--password", PASSWORD)
            self.assert_payload(second_destination)

    def run(self) -> None:
        for boundary in LOCK_BOUNDARIES:
            print(f"RUN {boundary}", flush=True)
            self.lock_boundary(boundary)
            print(f"PASS {boundary}", flush=True)
        for boundary in UNLOCK_BOUNDARIES:
            print(f"RUN {boundary}", flush=True)
            self.unlock_boundary(boundary)
            print(f"PASS {boundary}", flush=True)
        for boundary in RECOVERY_BOUNDARIES:
            print(f"RUN {boundary}", flush=True)
            self.recovery_boundary(boundary)
            print(f"PASS {boundary}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    project = root / ".github" / "scripts" / "crash_probe" / "CrashProbe.csproj"
    subprocess.run(["dotnet", "build", str(project), "-c", "Release", "--nologo"], cwd=root, check=True, timeout=180)
    probe = root / "bin" / "Release" / "net10.0" / "ColDogLocker.CrashProbe.dll"
    work_dir = (args.work_dir or Path.home() / "Documents" / "ColDog Locker Crash Tests").resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    CrashBoundaryCheck(work_dir, args.cli.resolve(), probe).run()
    print(f"PASS: {len(LOCK_BOUNDARIES) + len(UNLOCK_BOUNDARIES) + len(RECOVERY_BOUNDARIES)} crash boundaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

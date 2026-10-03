#!/usr/bin/env python3
"""Cross-platform CLI end-to-end tests for the published cdlocker binary."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import shutil
import sqlite3
import time
import subprocess
import sys
import tempfile
import threading
import uuid
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path


LOCKER_NAME = "E2ETestLocker"
PASSWORD = "E2E-tst@5044$!"
NEW_PASSWORD = "E2E-new@5044$!"
WRONG_PASSWORD = "WrongPassword123!"
DELETE_LOCKER_NAME = "E2EDeleteLocker"
UPDATE_INSTALLER_NAME = "ColDogLocker-e2e-win-x64.msi"
UPDATE_INSTALLER_BYTES = b"fake installer payload for cli e2e"


@dataclass
class Result:
    name: str
    passed: bool
    message: str = ""


class UpdateStubServer:
    def __init__(self, routes: dict[str, tuple[int, str, bytes]]) -> None:
        self.routes = routes
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self.create_handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        address = self.server.server_address
        host = address[0]
        port = address[1]
        return f"http://{host}:{port}"

    def create_handler(self):
        routes = self.routes

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                route = routes.get(self.path)
                if route is None:
                    body = f"No route for {self.path}".encode("utf-8")
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                status, content_type, body = route
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:
                return

        return Handler

    def __enter__(self) -> "UpdateStubServer":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class CliE2E:
    def __init__(self, cli: Path, work_dir: Path | None = None) -> None:
        self.cli = cli
        self.results: list[Result] = []
        self.base_dir = (work_dir if work_dir is not None else Path.home() / "Documents" / "ColDog Locker").resolve()
        self.app_data_dir = self.base_dir / ".app-data"
        self.backup_dir = self.base_dir / f"database-backup-{uuid.uuid4()}"
        self.restore_profile_dir = self.base_dir / f".restore-profile-{uuid.uuid4()}"
        self.test_dir = self.base_dir / f"e2e-test-locker-{uuid.uuid4()}"
        self.locker_dir = self.test_dir / LOCKER_NAME
        self.password = PASSWORD
        self.env = self.create_cli_environment()
        self.seed_settings()

    def create_cli_environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env["LOCALAPPDATA"] = str(self.app_data_dir / "local")
        env["APPDATA"] = str(self.app_data_dir / "roaming")
        env["USERPROFILE"] = str(self.app_data_dir / "user-profile")
        env["HOME"] = str(self.app_data_dir / "home")
        env["XDG_DATA_HOME"] = str(self.app_data_dir / "xdg-data")
        env["XDG_CONFIG_HOME"] = str(self.app_data_dir / "xdg-config")
        for folder in ("local", "roaming", "user-profile", "home", "xdg-data", "xdg-config"):
            (self.app_data_dir / folder).mkdir(parents=True, exist_ok=True)
        return env

    def seed_settings(self) -> None:
        settings = {
            "DevMode": False,
            "AutoUpdate": False,
            "UpdateChannel": 0,
            "DatabaseVacuumInterval": 30,
            "LastDatabaseVacuum": None,
            "LogLevel": "Info",
            "LogFormat": "json",
            "MaxFileSizeMb": 10,
            "MaxRetainedFiles": 9,
            "EnableFileLogging": True,
            "EnableCompression": False,
            "IncludeTimestamps": True,
            "IncludeThreadId": False,
            "DateTimeFormat": "UTC",
            "AsyncLogging": True,
            "AppTheme": "Auto",
            "EnableAnimations": True,
            "DefaultLockerLocation": str(self.base_dir),
            "DefaultGuiViewMode": 0,
        }

        for data_root in (self.app_data_dir / "local", self.app_data_dir / "xdg-data"):
            settings_dir = data_root / "ColDog Studios" / "ColDog Locker"
            settings_dir.mkdir(parents=True, exist_ok=True)
            (settings_dir / "settings.json").write_text(json.dumps(settings, indent=2), encoding="utf-8")

    def run_cli(
        self,
        *args: str,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(self.cli), *args]
        env = self.env.copy()
        if extra_env is not None:
            env.update(extra_env)

        completed = subprocess.run(command, capture_output=True, text=True, check=False, env=env, timeout=120)
        if check and completed.returncode != 0:
            raise AssertionError(
                f"Command failed with exit code {completed.returncode}: {' '.join(command)}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            )
        return completed

    def output(self, completed: subprocess.CompletedProcess[str]) -> str:
        return f"{completed.stdout}\n{completed.stderr}".strip()

    def expect_contains(self, text: str, expected: str, message: str) -> None:
        if expected not in text:
            raise AssertionError(f"{message}\nExpected: {expected!r}\nActual:\n{text}")

    def expect_not_contains(self, text: str, unexpected: str, message: str) -> None:
        if unexpected in text:
            raise AssertionError(f"{message}\nUnexpected: {unexpected!r}\nActual:\n{text}")

    def expect_failed(self, completed: subprocess.CompletedProcess[str], message: str) -> str:
        text = self.output(completed)
        if completed.returncode == 0:
            raise AssertionError(f"{message}\nCommand unexpectedly succeeded.\nActual:\n{text}")
        return text

    def no_pending_operations(self) -> None:
        text = self.output(self.run_cli("recovery-list"))
        self.expect_contains(text, "No unfinished locker operations", "Successful operations left a journal")

    def interrupted_lock_is_recorded(self) -> None:
        name = "InterruptedLocker"
        source = self.create_locker_with_name(name)
        payload = source / "payload.bin"
        block = os.urandom(1024 * 1024)
        with payload.open("wb") as stream:
            for _ in range(32):
                stream.write(block)
        expected_hash = hashlib.sha256(payload.read_bytes()).hexdigest()
        databases = list(self.app_data_dir.rglob("lockers.db"))
        if len(databases) != 1:
            raise AssertionError(f"Expected one isolated database, got {databases}")
        process = subprocess.Popen([str(self.cli), "lock", name, "--password", self.password],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        observed = False
        try:
            deadline = time.monotonic() + 30
            with closing(sqlite3.connect(databases[0], timeout=1)) as connection:
                while process.poll() is None and time.monotonic() < deadline:
                    row = connection.execute(
                        "SELECT Phase FROM LockerOperations WHERE SourcePath = ?", (str(source),)).fetchone()
                    if row and row[0] == "Preparing":
                        observed = True
                        process.kill()
                        break
                    time.sleep(0.005)
            process.communicate(timeout=15)
            if not observed:
                raise AssertionError("Could not observe the journal before archive completion")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=15)
        if hashlib.sha256(payload.read_bytes()).hexdigest() != expected_hash:
            raise AssertionError("Source changed before archive completion")
        text = self.output(self.run_cli("recovery-list"))
        self.expect_contains(text, "Preparing", "Restart did not expose the retained journal")
        self.expect_contains(text, str(source), "Recovery listing omitted the original path")
        # The first attempt may additionally report an abandoned OS mutex.
        self.expect_failed(self.run_cli("lock", name, "--password", self.password, check=False), "Interrupted operation was allowed to restart")
        text = self.expect_failed(self.run_cli("lock", name, "--password", self.password, check=False), "Interrupted operation was allowed to restart")
        self.expect_contains(text, "requires recovery", "Retry did not fail on the persistent journal")
        if hashlib.sha256(payload.read_bytes()).hexdigest() != expected_hash:
            raise AssertionError("Blocked retries changed source data")
        with closing(sqlite3.connect(databases[0])) as connection:
            operation_id, staging = connection.execute(
                "SELECT OperationId, StagingPath FROM LockerOperations WHERE SourcePath = ?", (str(source),)).fetchone()
        self.run_cli("recovery-cancel", operation_id)
        history = self.output(self.run_cli("recovery-history"))
        self.expect_contains(history, operation_id, "Cancelled journal lost its history")
        self.expect_contains(history, staging, "Cancelled journal lost its retained staging path")
        self.run_cli("lock", name, "--password", self.password)
        self.run_cli("unlock", name, "--password", self.password)
        if hashlib.sha256(payload.read_bytes()).hexdigest() != expected_hash:
            raise AssertionError("Retry after cancellation changed original bytes")
        self.run_cli("remove", name, "--force", "--delete")

    def interrupted_deletion_can_be_restored(self) -> None:
        name = "InterruptedDeletionLocker"
        source = self.create_locker_with_name(name)
        for index in range(3000):
            (source / f"file-{index:04}.txt").write_text(f"original bytes {index}\n", encoding="utf-8")
        databases = list(self.app_data_dir.rglob("lockers.db"))
        if len(databases) != 1:
            raise AssertionError("Expected one isolated database")
        process = subprocess.Popen([str(self.cli), "lock", name, "--password", self.password],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        observed_destructive_state = False
        process_output = ""
        try:
            deadline = time.monotonic() + 45
            while process.poll() is None and time.monotonic() < deadline:
                # The source root stops being a directory only after the durable
                # SourceRemovalStarted journal commit. Watching that filesystem
                # transition avoids a tight SQLite read loop starving the writer
                # under Windows' rollback-journal locking behavior.
                if not source.is_dir():
                    observed_destructive_state = True
                    process.kill()
                    break
                time.sleep(0.001)
            stdout, stderr = process.communicate(timeout=15)
            process_output = f"stdout:\n{stdout}\nstderr:\n{stderr}"
            if not observed_destructive_state:
                raise AssertionError(
                    f"Did not observe the destructive lock boundary\n{process_output}"
                )
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=15)
        with closing(sqlite3.connect(databases[0], timeout=1)) as connection:
            observed = connection.execute(
                "SELECT OperationId, Phase, StagingPath, TargetPath FROM LockerOperations WHERE SourcePath = ?",
                (str(source),),
            ).fetchone()
        if observed is None or observed[1] not in ("SourceRemovalStarted", "Published"):
            raise AssertionError(
                f"Destructive lock did not retain its recovery journal: {observed!r}\n{process_output}"
            )
        operation_id, _, staging, target = observed
        candidates = [Path(staging) / "locker.cdl", Path(target) / "locker.cdl"]
        archives = [path for path in candidates if path.is_file()]
        if len(archives) != 1:
            raise AssertionError(f"Expected one retained complete archive, got {archives}")
        archive = archives[0]
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        survivors = {path.name: path.read_bytes() for path in source.glob("*.txt")} if source.exists() else {}
        destination = self.test_dir / "Recovered" / name
        recovery = subprocess.Popen(
            [str(self.cli), "recovery-restore", operation_id, str(archive), str(destination), "--password", self.password],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        partial_staging = None
        try:
            deadline = time.monotonic() + 45
            with closing(sqlite3.connect(databases[0], timeout=1)) as connection:
                while recovery.poll() is None and time.monotonic() < deadline:
                    row = connection.execute(
                        "SELECT StagingPath FROM LockerRecoveryAttempts "
                        "WHERE OperationId = ? AND State = 'Restoring' ORDER BY rowid DESC LIMIT 1",
                        (operation_id,),
                    ).fetchone()
                    if row:
                        candidate = Path(row[0])
                        if candidate.is_dir() and next(candidate.rglob("*"), None) is not None:
                            partial_staging = candidate
                            recovery.kill()
                            break
                    time.sleep(0.001)
            recovery.communicate(timeout=15)
            if partial_staging is None:
                raise AssertionError("Did not observe partial recovery staging before recovery completed")
        finally:
            if recovery.poll() is None:
                recovery.kill()
                recovery.communicate(timeout=15)
        if destination.exists():
            raise AssertionError("Killed recovery published its final destination")
        if not partial_staging.is_dir() or next(partial_staging.rglob("*"), None) is None:
            raise AssertionError("Killed recovery did not retain partial plaintext staging")
        if hashlib.sha256(archive.read_bytes()).hexdigest() != archive_hash:
            raise AssertionError("Killed recovery modified its retained archive")
        self.expect_contains(self.output(self.run_cli("recovery-list")), operation_id,
                             "Killed recovery lost its pending operation")

        # The first acquisition after process termination can report an abandoned
        # named mutex while releasing it. The second must resume from durable state.
        first_retry = self.run_cli("recovery-restore", operation_id, str(archive), str(destination),
                                   "--password", self.password, check=False)
        if first_retry.returncode != 0:
            self.expect_contains(self.output(first_retry), "terminated unexpectedly",
                                 "Recovery retry failed for an unexpected reason")
            self.run_cli("recovery-restore", operation_id, str(archive), str(destination),
                         "--password", self.password)
        if len(list(destination.glob("*.txt"))) != 3000:
            raise AssertionError("Recovered file count differs")
        for index in range(3000):
            if (destination / f"file-{index:04}.txt").read_text(encoding="utf-8") != f"original bytes {index}\n":
                raise AssertionError(f"Recovered content differs for file {index}")
        for name, content in survivors.items():
            if (source / name).read_bytes() != content:
                raise AssertionError("Recovery modified a surviving original")
        if hashlib.sha256(archive.read_bytes()).hexdigest() != archive_hash:
            raise AssertionError("Recovery modified its retained archive")
        self.expect_contains(self.output(self.run_cli("recovery-history")), operation_id, "Recovery history missing")
        self.no_pending_operations()

    def create_locker_with_name(self, name: str, password: str | None = None) -> Path:
        locker_dir = self.test_dir / name
        self.run_cli("new", name, "--path", str(self.test_dir), "--password", password or self.password)
        if not locker_dir.is_dir():
            raise AssertionError(f"Locker directory was not created: {locker_dir}")
        return locker_dir

    def update_env(self, server: UpdateStubServer) -> dict[str, str]:
        return {
            "CDLOCKER_E2E_ENABLE_UPDATE_OVERRIDES": "1",
            "CDLOCKER_E2E_UPDATE_API_BASE_URL": server.base_url,
            "CDLOCKER_E2E_UPDATE_CURRENT_VERSION": "1.0.0",
            "CDLOCKER_E2E_UPDATE_DOWNLOAD_DIR": str(self.app_data_dir / "downloads"),
            "CDLOCKER_E2E_UPDATE_PLATFORM": "windows-x64",
            "CDLOCKER_E2E_UPDATE_ALLOW_LOOPBACK_HTTP": "1",
            "CDLOCKER_E2E_UPDATE_SKIP_INSTALLER_LAUNCH": "1",
        }

    def update_release_json(
        self,
        server: UpdateStubServer,
        tag_name: str,
        installer_bytes: bytes = UPDATE_INSTALLER_BYTES,
        digest_bytes: bytes | None = None,
    ) -> bytes:
        digest_source = installer_bytes if digest_bytes is None else digest_bytes
        release = {
            "tag_name": tag_name,
            "name": f"ColDog Locker {tag_name}",
            "body": "E2E release notes",
            "html_url": f"{server.base_url}/releases/{tag_name}",
            "draft": False,
            "prerelease": "-" in tag_name,
            "assets": [
                {
                    "name": UPDATE_INSTALLER_NAME,
                    "browser_download_url": f"{server.base_url}/download/{UPDATE_INSTALLER_NAME}",
                    "digest": f"sha256:{hashlib.sha256(digest_source).hexdigest()}",
                    "size": len(installer_bytes),
                    "content_type": "application/octet-stream",
                }
            ],
        }
        return json.dumps(release).encode("utf-8")

    def test(self, name: str, func) -> None:
        print(f"\n=== {name} ===")
        try:
            func()
        except Exception as exc:
            self.results.append(Result(name, False, str(exc)))
            print(f"FAIL: {name}")
            print(exc)
        else:
            self.results.append(Result(name, True))
            print(f"PASS: {name}")

    def version_command(self) -> None:
        completed = self.run_cli("--version")
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "ColDog Locker", "Version output did not include product name.")

    def help_command(self) -> None:
        completed = self.run_cli("help")
        text = self.output(completed)
        print("\n".join(text.splitlines()[:8]))
        self.expect_contains(text, "USAGE", "General help did not include usage information.")

    def command_help_details(self) -> None:
        expectations = {
            "new": "CREATE NEW LOCKER",
            "remove": "REMOVE LOCKER",
            "lock": "LOCK LOCKER",
            "unlock": "UNLOCK LOCKER",
            "list": "LIST LOCKERS",
            "status": "SHOW LOCKER STATUS",
            "settings": "MANAGE SETTINGS",
            "change-password": "CHANGE LOCKER PASSWORD",
            "verify": "VERIFY LOCKER",
            "db-vacuum": "VACUUM DATABASE",
            "db-info": "DATABASE INFORMATION",
            "update": "CHECK FOR UPDATES",
            "gui": "LAUNCH GUI",
            "tui": "LAUNCH TERMINAL UI",
        }
        for command, expected in expectations.items():
            completed = self.run_cli("help", command)
            text = self.output(completed)
            print(f"{command}: {text.splitlines()[0] if text else ''}")
            self.expect_contains(text, expected, f"Help for {command!r} did not include expected heading.")

        completed = self.run_cli("help", "does-not-exist")
        text = self.output(completed)
        self.expect_contains(text, "No help available", "Unknown command help did not report that help is unavailable.")

    def unknown_command(self) -> None:
        completed = self.run_cli("definitely-not-a-command", check=False)
        text = self.expect_failed(completed, "Unknown command unexpectedly succeeded.")
        print(text)
        self.expect_contains(text, "Unknown command", "Unknown command did not report an error.")
        self.expect_contains(text, "USAGE", "Unknown command did not print general help.")

    def dev_command(self) -> None:
        completed = self.run_cli("dev")
        text = self.output(completed)
        print(text)
        for expected in ("Environment:", "Runtime Identifier:", "Local Config Location:"):
            self.expect_contains(text, expected, f"dev output did not include {expected!r}.")

    def update_command(self) -> None:
        routes: dict[str, tuple[int, str, bytes]] = {}
        with UpdateStubServer(routes) as server:
            routes["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] = (
                200,
                "application/json",
                self.update_release_json(server, "v1.0.0"),
            )

            completed = self.run_cli("update", extra_env=self.update_env(server))
            text = self.output(completed)
            print(text)
            self.expect_contains(text, "ColDog Locker is up to date", "update did not report the no-update case.")

        routes = {}
        with UpdateStubServer(routes) as server:
            routes["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] = (
                200,
                "application/json",
                self.update_release_json(server, "v1.0.1"),
            )
            routes[f"/download/{UPDATE_INSTALLER_NAME}"] = (200, "application/octet-stream", UPDATE_INSTALLER_BYTES)

            completed = self.run_cli("update", extra_env=self.update_env(server))
            text = self.output(completed)
            print(text)
            self.expect_contains(text, "A newer version is available", "update did not report an available update.")
            self.expect_contains(text, "cdlocker update --download", "update did not show download guidance.")

            download_dir = self.app_data_dir / "downloads"
            downloaded_file = download_dir / UPDATE_INSTALLER_NAME
            if downloaded_file.exists():
                downloaded_file.unlink()

            completed = self.run_cli("update", "--download", extra_env=self.update_env(server))
            text = self.output(completed)
            print(text)
            self.expect_contains(text, "Downloaded:", "update --download did not report a downloaded file.")
            if downloaded_file.read_bytes() != UPDATE_INSTALLER_BYTES:
                raise AssertionError("update --download did not write the expected installer bytes.")

        routes = {}
        with UpdateStubServer(routes) as server:
            routes["/repos/ColDog-Studios/ColDog-Locker/releases/latest"] = (
                200,
                "application/json",
                self.update_release_json(server, "v1.0.2", installer_bytes=b"tampered", digest_bytes=UPDATE_INSTALLER_BYTES),
            )
            routes[f"/download/{UPDATE_INSTALLER_NAME}"] = (200, "application/octet-stream", b"tampered")

            downloaded_file = self.app_data_dir / "downloads" / UPDATE_INSTALLER_NAME
            if downloaded_file.exists():
                downloaded_file.unlink()

            completed = self.run_cli("update", "--download", check=False, extra_env=self.update_env(server))
            text = self.expect_failed(completed, "update --download unexpectedly succeeded with a digest mismatch.")
            print(text)
            self.expect_contains(text, "release digest", "Digest mismatch did not report the expected validation error.")
            if downloaded_file.exists():
                raise AssertionError("Digest mismatch left a final installer file behind.")

    def list_empty_lockers(self) -> None:
        completed = self.run_cli("list")
        print(self.output(completed))

    def settings_command(self) -> None:
        completed = self.run_cli("settings")
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "Current Settings", "settings did not show current settings.")

        self.run_cli("settings", "auto-update", "false")
        completed = self.run_cli("settings", "auto-update")
        self.expect_contains(self.output(completed), "Auto Update: False", "auto-update false did not persist.")

        self.run_cli("settings", "update-channel", "unstable")
        completed = self.run_cli("settings", "update-channel")
        self.expect_contains(self.output(completed), "Update Channel: Unstable", "update-channel unstable did not persist.")

        self.run_cli("settings", "debug", "true")
        completed = self.run_cli("settings", "debug")
        self.expect_contains(self.output(completed), "Dev Mode: True", "debug true did not persist.")

        self.run_cli("settings", "debug", "false")
        completed = self.run_cli("settings", "debug")
        self.expect_contains(self.output(completed), "Dev Mode: False", "debug false did not persist.")

        self.run_cli("settings", "file-logging", "false")
        completed = self.run_cli("settings", "file-logging")
        self.expect_contains(self.output(completed), "File Logging: Disabled", "file-logging false did not persist.")

        self.run_cli("settings", "file-logging", "true")
        completed = self.run_cli("settings", "file-logging")
        self.expect_contains(self.output(completed), "File Logging: Enabled", "file-logging true did not persist.")

        self.run_cli("settings", "max-file-size", "12")
        completed = self.run_cli("settings", "max-file-size")
        self.expect_contains(self.output(completed), "Max File Size: 12 MB", "max-file-size did not persist.")

        completed = self.run_cli("settings", "debug", "sometimes", check=False)
        text = self.expect_failed(completed, "Invalid debug setting unexpectedly succeeded.")
        self.expect_contains(text, "Use 'true' or 'false'", "Invalid debug setting did not report expected validation.")

        completed = self.run_cli("settings", "unknown-setting", check=False)
        text = self.expect_failed(completed, "Unknown setting unexpectedly succeeded.")
        self.expect_contains(text, "Unknown setting", "Unknown setting did not report expected validation.")

        completed = self.run_cli("settings", "db-vacuum-interval", "-1", check=False)
        text = self.expect_failed(completed, "Invalid db-vacuum-interval unexpectedly succeeded.")
        self.expect_contains(text, "between 0 and 365 days", "Invalid db-vacuum-interval did not report expected validation.")

    def database_commands(self) -> None:
        completed = self.run_cli("db-info")
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "Database Information", "db-info did not print database information.")

        completed = self.run_cli("db-vacuum")
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "Database vacuumed successfully", "db-vacuum did not report success.")

    def unsupported_verifier_preserves_source(self) -> None:
        name = "UnsupportedVerifier"
        directory = self.create_locker_with_name(name)
        original = directory / "original.txt"
        original.write_text("preserve unsupported-verifier bytes", encoding="utf-8")
        legacy = "$2a$04$b9STetOS4I7Zinp/E655pO6q0DttM8rC0frGST6cq81p0LIJsCLBC"
        databases = list(self.app_data_dir.rglob("lockers.db"))
        if len(databases) != 1:
            raise AssertionError("Expected one isolated registry")
        with closing(sqlite3.connect(databases[0])) as connection:
            connection.execute("UPDATE Lockers SET Password = ? WHERE LockerName = ?", (legacy, name))
            connection.commit()
        result = self.run_cli("lock", name, "--password", "Legacy!Pass582", check=False)
        text = self.expect_failed(result, "Unsupported password verifier authorized locking")
        self.expect_contains(text, "Unsupported password verifier format", "Unexpected verifier failure")
        if original.read_text(encoding="utf-8") != "preserve unsupported-verifier bytes":
            raise AssertionError("Verifier refusal changed original contents")
        with closing(sqlite3.connect(databases[0])) as connection:
            row = connection.execute("SELECT Password, IsLocked, LockerLocation FROM Lockers WHERE LockerName = ?", (name,)).fetchone()
        if row != (legacy, 0, str(directory)):
            raise AssertionError("Verifier refusal changed registration")
        self.no_pending_operations()
        if (directory.parent / f".{name}").exists() or list(directory.parent.glob(f".{name}.*.locking")):
            raise AssertionError("Verifier refusal left archive output")
        self.run_cli("remove", name, "--force", "--delete")

    def empty_locker_and_file_round_trip(self) -> None:
        name = "EmptyRoundTrip"
        directory = self.create_locker_with_name(name)
        for with_file in (False, True):
            if with_file:
                (directory / "empty.txt").write_bytes(b"")
            self.run_cli("lock", name, "--password", self.password)
            self.run_cli("unlock", name, "--password", self.password)
            if with_file:
                if sorted(path.name for path in directory.iterdir()) != ["empty.txt"] or (directory / "empty.txt").read_bytes() != b"":
                    raise AssertionError("Zero-length file did not survive lock/unlock")
            elif list(directory.iterdir()):
                raise AssertionError("Empty locker gained unexpected contents")
        self.no_pending_operations()
        self.run_cli("remove", name, "--force", "--delete")

    def linked_content_inspection_is_refused(self) -> None:
        name = "LinkedInspection"
        directory = self.create_locker_with_name(name)
        original = directory / "original.txt"
        original.write_text("preserve inspection bytes", encoding="utf-8")
        cycle = directory / "cycle"
        cycle.symlink_to(directory, target_is_directory=True)
        try:
            for command in ("status", "verify"):
                failed = self.run_cli(command, name, check=False)
                text = self.expect_failed(failed, f"{command} accepted a linked directory cycle")
                self.expect_contains(text, "Contents: Unavailable", "Incomplete counts were not reported")
                self.expect_not_contains(text, "0 file(s)", "Incomplete inspection was reported as empty")
            if original.read_text(encoding="utf-8") != "preserve inspection bytes":
                raise AssertionError("Inspection changed source bytes")
        finally:
            cycle.unlink()
        self.run_cli("verify", name)
        self.run_cli("remove", name, "--force", "--delete")

    def hard_link_rejected_without_source_loss(self) -> None:
        name = "HardLinkedEntry"
        directory = self.create_locker_with_name(name)
        original = directory / "original.txt"
        alias = self.test_dir / "external-alias.txt"
        original.write_text("preserve linked bytes", encoding="utf-8")
        os.link(original, alias)
        failure = self.run_cli("lock", name, "--password", self.password, check=False)
        text = self.expect_failed(failure, "Locker containing a hard link was accepted.")
        self.expect_contains(text, "Hard-linked", "Lock failed for an unexpected reason.")
        for path in (original, alias):
            if path.read_text(encoding="utf-8") != "preserve linked bytes" or path.stat().st_nlink != 2:
                raise AssertionError("Rejected lock changed the hard-linked source")
        databases = list(self.app_data_dir.rglob("lockers.db"))
        if len(databases) != 1:
            raise AssertionError("Expected one isolated registry")
        with closing(sqlite3.connect(databases[0])) as connection:
            locker = connection.execute("SELECT IsLocked, LockerLocation FROM Lockers WHERE LockerName = ?", (name,)).fetchone()
        if locker != (0, str(directory)):
            raise AssertionError("Hard-link rejection changed registration")
        self.no_pending_operations()
        if (directory.parent / f".{name}").exists() or list(directory.parent.glob(f".{name}.*.locking")):
            raise AssertionError("Hard-link rejection left archive output")
        alias.unlink()
        self.run_cli("lock", name, "--password", self.password)
        self.run_cli("unlock", name, "--password", self.password)
        if original.read_text(encoding="utf-8") != "preserve linked bytes":
            raise AssertionError("Retry after removing the alias changed contents")
        self.run_cli("remove", name, "--force", "--delete")

    def fifo_rejected_without_source_loss(self) -> None:
        name = "UnsupportedEntry"
        directory = self.create_locker_with_name(name)
        original = directory / "original.txt"
        original.write_text("preserve original bytes", encoding="utf-8")
        fifo = directory / "pipe"
        os.mkfifo(fifo)
        failure = self.run_cli("lock", name, "--password", self.password, check=False)
        text = self.expect_failed(failure, "Locker containing a FIFO was accepted.")
        self.expect_contains(text, "Only regular files and directories", "Lock failed for an unexpected reason.")
        if original.read_text(encoding="utf-8") != "preserve original bytes" or not fifo.exists():
            raise AssertionError("Failed lock modified the source")
        databases = list(self.app_data_dir.rglob("lockers.db"))
        if len(databases) != 1:
            raise AssertionError("Expected one isolated registry")
        with closing(sqlite3.connect(databases[0])) as connection:
            row = connection.execute("SELECT OperationId, Phase FROM LockerOperations").fetchone()
            locker = connection.execute("SELECT IsLocked, LockerLocation FROM Lockers WHERE LockerName = ?", (name,)).fetchone()
        if row is not None:
            raise AssertionError("Cleanly rejected preparation retained an unfinished journal")
        if locker != (0, str(directory)):
            raise AssertionError("Rejected source changed the registration")
        if (directory.parent / f".{name}").exists() or list(directory.parent.glob(f".{name}.*.locking")):
            raise AssertionError("Rejected source left archive output")
        fifo.unlink()
        self.run_cli("lock", name, "--password", self.password)
        self.run_cli("unlock", name, "--password", self.password)
        if original.read_text(encoding="utf-8") != "preserve original bytes":
            raise AssertionError("Retry did not preserve original contents")
        self.run_cli("remove", name, "--force", "--delete")

    def extended_attribute_rejected_without_source_loss(self) -> None:
        name = "ExtendedAttributeEntry"
        directory = self.create_locker_with_name(name)
        original = directory / "original.txt"
        original.write_text("preserve xattr bytes", encoding="utf-8")
        attribute = "user.coldog-test"
        value = b"unsupported metadata"
        os.setxattr(original, attribute, value)
        failure = self.run_cli("lock", name, "--password", self.password, check=False)
        text = self.expect_failed(failure, "Locker containing an extended attribute was accepted.")
        self.expect_contains(text, "Extended attributes", "Lock failed for an unexpected reason.")
        if original.read_text(encoding="utf-8") != "preserve xattr bytes" or os.getxattr(original, attribute) != value:
            raise AssertionError("Rejected lock changed the extended-attribute source")
        databases = list(self.app_data_dir.rglob("lockers.db"))
        if len(databases) != 1:
            raise AssertionError("Expected one isolated registry")
        with closing(sqlite3.connect(databases[0])) as connection:
            pending = connection.execute("SELECT OperationId FROM LockerOperations").fetchone()
            locker = connection.execute(
                "SELECT IsLocked, LockerLocation FROM Lockers WHERE LockerName = ?", (name,)
            ).fetchone()
        if pending is not None or locker != (0, str(directory)):
            raise AssertionError("Extended-attribute rejection changed durable state")
        if (directory.parent / f".{name}").exists() or list(directory.parent.glob(f".{name}.*.locking")):
            raise AssertionError("Extended-attribute rejection left archive output")
        os.removexattr(original, attribute)
        self.run_cli("lock", name, "--password", self.password)
        self.run_cli("unlock", name, "--password", self.password)
        if original.read_text(encoding="utf-8") != "preserve xattr bytes":
            raise AssertionError("Retry after removing the extended attribute changed contents")
        self.run_cli("remove", name, "--force", "--delete")

    def database_backup(self) -> None:
        destination = self.backup_dir
        completed = self.run_cli("db-backup", str(destination))
        self.expect_contains(self.output(completed), "Verified database backup", "Backup did not report success.")
        backup_file = destination / "lockers.db"
        before = hashlib.sha256(backup_file.read_bytes()).hexdigest()
        with closing(sqlite3.connect(backup_file)) as connection:
            row = connection.execute("SELECT LockerName, IsLocked, LockedArchiveSha256 FROM Lockers WHERE LockerName = ?", (LOCKER_NAME,)).fetchone()
            if row is None or row[1] != 1 or not row[2]:
                raise AssertionError("Backup did not preserve locked registration and archive hash.")
            if connection.execute("SELECT COUNT(*) FROM LockerOperations").fetchone()[0] != 0:
                raise AssertionError("Backup unexpectedly contains a pending operation.")
        self.expect_failed(self.run_cli("db-backup", str(destination), check=False), "Backup overwrote an existing destination.")
        if hashlib.sha256(backup_file.read_bytes()).hexdigest() != before:
            raise AssertionError("Rejected overwrite changed the backup.")

    def database_restore(self) -> None:
        backup = self.backup_dir / "lockers.db"
        before = hashlib.sha256(backup.read_bytes()).hexdigest()
        profile = self.restore_profile_dir
        overrides = {}
        for key, folder in {"LOCALAPPDATA": "local", "APPDATA": "roaming", "USERPROFILE": "user-profile",
                            "HOME": "home", "XDG_DATA_HOME": "xdg-data", "XDG_CONFIG_HOME": "xdg-config"}.items():
            path = profile / folder
            path.mkdir(parents=True, exist_ok=True)
            overrides[key] = str(path)
        completed = self.run_cli("db-restore", str(backup), extra_env=overrides)
        self.expect_contains(self.output(completed), "Restored database", "Fresh-profile restore failed.")
        restored = list(profile.rglob("lockers.db"))
        if len(restored) != 1:
            raise AssertionError("Restore did not create exactly one registry in the fresh profile.")
        with closing(sqlite3.connect(restored[0])) as connection:
            row = connection.execute("SELECT LockerName, IsLocked FROM Lockers WHERE LockerName = ?", (LOCKER_NAME,)).fetchone()
            if row != (LOCKER_NAME, 1):
                raise AssertionError("Restored registration does not match the locked backup.")
        self.expect_contains(self.output(self.run_cli("list", extra_env=overrides)), LOCKER_NAME, "Restored locker is not listed.")
        self.run_cli("verify", LOCKER_NAME, extra_env=overrides)
        self.expect_failed(self.run_cli("db-restore", str(backup), check=False, extra_env=overrides), "Restore replaced an existing registry.")
        if hashlib.sha256(backup.read_bytes()).hexdigest() != before:
            raise AssertionError("Restore changed its input backup.")

    def create_locker(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        completed = self.run_cli("new", LOCKER_NAME, "--path", str(self.test_dir), "--password", self.password)
        print(self.output(completed))
        if not self.locker_dir.is_dir():
            raise AssertionError(f"Locker directory was not created: {self.locker_dir}")

    def new_command_validation_errors(self) -> None:
        completed = self.run_cli("new", "WeakPasswordLocker", "--path", str(self.test_dir), "--password", "weak", check=False)
        text = self.expect_failed(completed, "Creating a locker with a weak password unexpectedly succeeded.")
        self.expect_contains(text, "Password validation failed", "Weak password creation did not report validation failure.")

        absolute_name = str(self.test_dir / "AbsoluteLockerName")
        completed = self.run_cli("new", absolute_name, "--password", self.password, check=False)
        text = self.expect_failed(completed, "Creating a locker with an absolute name unexpectedly succeeded.")
        self.expect_contains(text, "relative name", "Absolute locker name did not report expected validation.")

        completed = self.run_cli(
            "new",
            "ProtectedPathLocker",
            "--path",
            tempfile.gettempdir(),
            "--password",
            self.password,
            check=False,
        )
        text = self.expect_failed(completed, "Creating a locker under a protected path unexpectedly succeeded.")
        self.expect_contains(text, "Cannot lock", "Protected path creation did not report expected validation.")

    def created_locker_validation_errors(self) -> None:
        completed = self.run_cli("new", LOCKER_NAME, "--path", str(self.test_dir), "--password", self.password, check=False)
        text = self.expect_failed(completed, "Creating a duplicate locker unexpectedly succeeded.")
        self.expect_contains(text, "already exists", "Duplicate locker did not report expected validation.")

        completed = self.run_cli(
            "change-password",
            LOCKER_NAME,
            "--old-password",
            self.password,
            check=False,
        )
        text = self.expect_failed(completed, "Incomplete non-interactive change-password unexpectedly succeeded.")
        self.expect_contains(text, "Both --old-password and --new-password", "Incomplete change-password did not report expected validation.")

    def create_test_files(self) -> None:
        if not self.locker_dir.is_dir():
            raise AssertionError(f"Locker directory does not exist: {self.locker_dir}")
        (self.locker_dir / "file1.txt").write_text("Secret Content 1\n", encoding="utf-8")
        (self.locker_dir / "file2.txt").write_text("Secret Content 2\n", encoding="utf-8")
        (self.locker_dir / "subfolder").mkdir(parents=True, exist_ok=True)
        (self.locker_dir / "subfolder" / "file3.txt").write_text("Secret Content 3\n", encoding="utf-8")

    def list_lockers(self) -> None:
        completed = self.run_cli("list")
        text = self.output(completed)
        print(text)
        self.expect_contains(text, LOCKER_NAME, "Created locker was not listed.")

    def lock_locker(self) -> None:
        completed = self.run_cli("lock", LOCKER_NAME, "--password", self.password)
        print(self.output(completed))

    def verify_locked(self) -> None:
        completed = self.run_cli("status", LOCKER_NAME)
        text = self.output(completed)
        print(text)
        self.expect_contains(text.lower(), "locked", "Locker status did not show as locked.")

    def verify_locked_command(self) -> None:
        completed = self.run_cli("verify", LOCKER_NAME)
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "Status: Locked", "verify did not report the locker as locked.")
        self.expect_contains(text, "Locked archive exists", "verify did not inspect the locked archive.")
        self.expect_contains(text, "Locked archive hash matches database", "verify did not inspect the archive hash.")
        self.expect_contains(text, "Locked archive metadata matches locker", "verify did not inspect archive metadata.")
        self.expect_contains(text, "Overall: VALID", "verify did not report a valid locked locker.")

    def already_locked_locker(self) -> None:
        completed = self.run_cli("lock", LOCKER_NAME, "--password", self.password)
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "already locked", "Locking an already locked locker did not report idempotent state.")

    def remove_locked_rejected(self) -> None:
        completed = self.run_cli("remove", LOCKER_NAME, "--force", check=False)
        text = self.expect_failed(completed, "Removing a locked locker unexpectedly succeeded.")
        print(text)
        self.expect_contains(text, "Cannot remove locked locker", "Locked remove did not report expected validation.")

    def change_password_locked_rejected(self) -> None:
        completed = self.run_cli(
            "change-password",
            LOCKER_NAME,
            "--old-password",
            self.password,
            "--new-password",
            NEW_PASSWORD,
            check=False,
        )
        text = self.expect_failed(completed, "Changing password for a locked locker unexpectedly succeeded.")
        print(text)
        self.expect_contains(text, "must be unlocked", "Locked change-password did not report expected validation.")

    def list_filters_locked(self) -> None:
        locked = self.output(self.run_cli("list", "--locked"))
        self.expect_contains(locked, LOCKER_NAME, "Locked locker was not shown by list --locked.")

        unlocked = self.output(self.run_cli("list", "--unlocked"))
        self.expect_not_contains(unlocked, LOCKER_NAME, "Locked locker was unexpectedly shown by list --unlocked.")

    def unlock_locker(self) -> None:
        completed = self.run_cli("unlock", LOCKER_NAME, "--password", self.password)
        print(self.output(completed))

    def already_unlocked_locker(self) -> None:
        completed = self.run_cli("unlock", LOCKER_NAME, "--password", self.password)
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "already unlocked", "Unlocking an already unlocked locker did not report idempotent state.")

    def list_filters_unlocked(self) -> None:
        unlocked = self.output(self.run_cli("list", "--unlocked"))
        self.expect_contains(unlocked, LOCKER_NAME, "Unlocked locker was not shown by list --unlocked.")

        locked = self.output(self.run_cli("list", "--locked"))
        self.expect_not_contains(locked, LOCKER_NAME, "Unlocked locker was unexpectedly shown by list --locked.")

    def verify_files_intact(self) -> None:
        expected = {
            self.locker_dir / "file1.txt": "Secret Content 1",
            self.locker_dir / "file2.txt": "Secret Content 2",
            self.locker_dir / "subfolder" / "file3.txt": "Secret Content 3",
        }
        for path, content in expected.items():
            if content not in path.read_text(encoding="utf-8"):
                raise AssertionError(f"File content was corrupted: {path}")

    def verify_command(self) -> None:
        completed = self.run_cli("verify", LOCKER_NAME)
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "Overall: VALID", "verify did not report a valid locker.")
        self.expect_contains(text, "3 file(s), 1 folder(s)", "verify did not report expected file and folder counts.")

    def change_password(self) -> None:
        completed = self.run_cli(
            "change-password",
            LOCKER_NAME,
            "--old-password",
            self.password,
            "--new-password",
            NEW_PASSWORD,
        )
        print(self.output(completed))
        self.expect_contains(self.output(completed), "Password changed successfully", "change-password did not report success.")

        old_password_result = self.run_cli("lock", LOCKER_NAME, "--password", self.password, check=False)
        if old_password_result.returncode == 0:
            raise AssertionError("Lock succeeded with the old password after password change.")

        self.password = NEW_PASSWORD
        self.run_cli("lock", LOCKER_NAME, "--password", self.password)
        self.run_cli("unlock", LOCKER_NAME, "--password", self.password)
        self.verify_files_intact()

    def missing_locker_errors(self) -> None:
        for command in ("status", "verify"):
            completed = self.run_cli(command, "MissingE2ELocker", check=False)
            text = self.output(completed)
            if completed.returncode == 0:
                raise AssertionError(f"{command} MissingE2ELocker unexpectedly succeeded.")
            self.expect_contains(text, "not found", f"{command} MissingE2ELocker did not report not found.")

    def unlock_with_wrong_password(self) -> None:
        self.run_cli("lock", LOCKER_NAME, "--password", self.password)
        completed = self.run_cli("unlock", LOCKER_NAME, "--password", WRONG_PASSWORD, check=False)
        if completed.returncode == 0:
            raise AssertionError("Unlock succeeded with the wrong password.")
        self.run_cli("unlock", LOCKER_NAME, "--password", self.password)

    def lock_with_wrong_password(self) -> None:
        completed = self.run_cli("lock", LOCKER_NAME, "--password", WRONG_PASSWORD, check=False)
        if completed.returncode == 0:
            raise AssertionError("Lock succeeded with the wrong password.")

    def remove_locker_delete(self) -> None:
        locker_dir = self.create_locker_with_name(DELETE_LOCKER_NAME)
        (locker_dir / "delete-me.txt").write_text("temporary secret\n", encoding="utf-8")

        completed = self.run_cli("remove", DELETE_LOCKER_NAME, "--force", "--delete")
        text = self.output(completed)
        print(text)
        self.expect_contains(text, "directory deleted", "remove --delete did not report directory deletion.")

        if locker_dir.exists():
            raise AssertionError(f"remove --delete left the locker directory behind: {locker_dir}")

        completed = self.run_cli("list")
        self.expect_not_contains(self.output(completed), DELETE_LOCKER_NAME, "Deleted locker still appears in list after remove --delete.")

    def remove_locker(self) -> None:
        completed = self.run_cli("remove", LOCKER_NAME, "--force")
        print(self.output(completed))

    def verify_removal(self) -> None:
        completed = self.run_cli("list")
        text = self.output(completed)
        print(text)
        self.expect_not_contains(text, LOCKER_NAME, "Locker still appears in list after removal.")

    def cleanup(self) -> None:
        self.run_cli("settings", "auto-update", "true", check=False)
        self.run_cli("settings", "update-channel", "stable", check=False)
        self.run_cli("settings", "debug", "false", check=False)
        self.run_cli("settings", "file-logging", "true", check=False)
        self.run_cli("settings", "max-file-size", "10", check=False)

        for locker_name in (LOCKER_NAME, DELETE_LOCKER_NAME):
            completed = self.run_cli("status", locker_name, check=False)
            if completed.returncode == 0:
                self.run_cli("unlock", locker_name, "--password", self.password, check=False)
                self.run_cli("remove", locker_name, "--force", "--delete", check=False)

        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

        if self.app_data_dir.exists():
            shutil.rmtree(self.app_data_dir, ignore_errors=True)
        for artifact in (self.backup_dir, self.restore_profile_dir):
            if artifact.exists():
                shutil.rmtree(artifact, ignore_errors=True)

    def run(self) -> int:
        tests = [
            ("Version Command", self.version_command),
            ("Help Command", self.help_command),
            ("Command Help Details", self.command_help_details),
            ("Unknown Command", self.unknown_command),
            ("Dev Command", self.dev_command),
            ("Update Command", self.update_command),
            ("List Empty Lockers", self.list_empty_lockers),
            ("Settings Command", self.settings_command),
            ("Database Commands", self.database_commands),
            ("New Command Validation Errors", self.new_command_validation_errors),
            ("Create Locker", self.create_locker),
            ("Created Locker Validation Errors", self.created_locker_validation_errors),
            ("Create Test Files", self.create_test_files),
            ("List Lockers", self.list_lockers),
            ("Lock Locker", self.lock_locker),
            ("Verify Locked", self.verify_locked),
            ("Database Backup", self.database_backup),
            ("Database Restore", self.database_restore),
            ("Verify Locked Command", self.verify_locked_command),
            ("Already Locked Locker", self.already_locked_locker),
            ("Remove Locked Rejected", self.remove_locked_rejected),
            ("Change Password Locked Rejected", self.change_password_locked_rejected),
            ("List Filters Locked", self.list_filters_locked),
            ("Unlock Locker", self.unlock_locker),
            ("Already Unlocked Locker", self.already_unlocked_locker),
            ("List Filters Unlocked", self.list_filters_unlocked),
            ("Verify Files Intact", self.verify_files_intact),
            ("Verify Command", self.verify_command),
            ("Change Password", self.change_password),
            ("Missing Locker Errors", self.missing_locker_errors),
            ("Unlock with Wrong Password", self.unlock_with_wrong_password),
            ("Lock with Wrong Password", self.lock_with_wrong_password),
            ("Remove Locker Delete", self.remove_locker_delete),
            ("Remove Locker", self.remove_locker),
            ("Verify Removal", self.verify_removal),
            ("Successful Operation Journals Cleared", self.no_pending_operations),
            ("Killed Lock Remains Recorded", self.interrupted_lock_is_recorded),
            ("Killed Destructive Lock Restored", self.interrupted_deletion_can_be_restored),
        ]

        tests.append(("Unsupported Verifier Preserves Source", self.unsupported_verifier_preserves_source))
        tests.append(("Empty Locker And File Round Trip", self.empty_locker_and_file_round_trip))
        tests.append(("Hard Link Rejected Without Source Loss", self.hard_link_rejected_without_source_loss))
        if os.name != "nt":
            tests.append(("FIFO Rejected Without Source Loss", self.fifo_rejected_without_source_loss))
            tests.append(("Extended Attribute Rejected Without Source Loss", self.extended_attribute_rejected_without_source_loss))
            tests.append(("Linked Content Inspection Refused", self.linked_content_inspection_is_refused))

        try:
            for name, func in tests:
                self.test(name, func)
        finally:
            print("\n=== Cleanup ===")
            self.cleanup()

        passed = sum(1 for result in self.results if result.passed)
        failed = len(self.results) - passed

        print("\nCLI End-to-End Test Results")
        print("=" * 32)
        for result in self.results:
            marker = "PASS" if result.passed else "FAIL"
            print(f"{marker:4} {result.name}")
            if result.message:
                print(f"     {result.message}")
        print(f"\nSummary: {passed} passed, {failed} failed")

        return 1 if failed else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ColDog Locker CLI E2E tests.")
    parser.add_argument("--cli", required=True, type=Path, help="Path to the published cdlocker executable.")
    parser.add_argument("--work-dir", type=Path, help="Directory where the temporary locker should be created.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cli = args.cli
    if not cli.exists():
        print(f"CLI executable not found: {cli}", file=sys.stderr)
        return 1

    return CliE2E(cli, args.work_dir).run()


if __name__ == "__main__":
    raise SystemExit(main())

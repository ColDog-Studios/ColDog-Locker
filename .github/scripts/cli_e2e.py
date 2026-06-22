#!/usr/bin/env python3
"""Cross-platform CLI end-to-end tests for the published cdlocker binary."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
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
        host, port = self.server.server_address
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

        completed = subprocess.run(command, capture_output=True, text=True, check=False, env=env)
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
            "terminal": "LAUNCH TERMINAL UI",
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
        ]

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

#!/usr/bin/env python3
"""Cross-platform CLI end-to-end tests for the published cdlocker binary."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path


LOCKER_NAME = "E2ETestLocker"
PASSWORD = "E2E-tst@5044$!"
WRONG_PASSWORD = "WrongPassword123!"


@dataclass
class Result:
    name: str
    passed: bool
    message: str = ""


class CliE2E:
    def __init__(self, cli: Path, work_dir: Path | None = None) -> None:
        self.cli = cli
        self.results: list[Result] = []
        self.base_dir = work_dir if work_dir is not None else Path.home() / "Documents" / "ColDog Locker"
        self.test_dir = self.base_dir / f"e2e-test-locker-{uuid.uuid4()}"
        self.locker_dir = self.test_dir / LOCKER_NAME

    def run_cli(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = [str(self.cli), *args]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
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
            "settings": "MANAGE SETTINGS",
            "verify": "VERIFY LOCKER",
            "db-info": "DATABASE INFORMATION",
        }
        for command, expected in expectations.items():
            completed = self.run_cli("help", command)
            text = self.output(completed)
            print(f"{command}: {text.splitlines()[0] if text else ''}")
            self.expect_contains(text, expected, f"Help for {command!r} did not include expected heading.")

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

        completed = self.run_cli("settings", "db-vacuum-interval", "-1", check=False)
        text = self.output(completed)
        if completed.returncode == 0:
            raise AssertionError("Invalid db-vacuum-interval unexpectedly succeeded.")
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
        completed = self.run_cli("new", LOCKER_NAME, "--path", str(self.test_dir), "--password", PASSWORD)
        print(self.output(completed))
        if not self.locker_dir.is_dir():
            raise AssertionError(f"Locker directory was not created: {self.locker_dir}")

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
        completed = self.run_cli("lock", LOCKER_NAME, "--password", PASSWORD)
        print(self.output(completed))

    def verify_locked(self) -> None:
        completed = self.run_cli("status", LOCKER_NAME)
        text = self.output(completed)
        print(text)
        self.expect_contains(text.lower(), "locked", "Locker status did not show as locked.")

    def list_filters_locked(self) -> None:
        locked = self.output(self.run_cli("list", "--locked"))
        self.expect_contains(locked, LOCKER_NAME, "Locked locker was not shown by list --locked.")

        unlocked = self.output(self.run_cli("list", "--unlocked"))
        self.expect_not_contains(unlocked, LOCKER_NAME, "Locked locker was unexpectedly shown by list --unlocked.")

    def unlock_locker(self) -> None:
        completed = self.run_cli("unlock", LOCKER_NAME, "--password", PASSWORD)
        print(self.output(completed))

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

    def missing_locker_errors(self) -> None:
        for command in ("status", "verify"):
            completed = self.run_cli(command, "MissingE2ELocker", check=False)
            text = self.output(completed)
            if completed.returncode == 0:
                raise AssertionError(f"{command} MissingE2ELocker unexpectedly succeeded.")
            self.expect_contains(text, "not found", f"{command} MissingE2ELocker did not report not found.")

    def unlock_with_wrong_password(self) -> None:
        self.run_cli("lock", LOCKER_NAME, "--password", PASSWORD)
        completed = self.run_cli("unlock", LOCKER_NAME, "--password", WRONG_PASSWORD, check=False)
        if completed.returncode == 0:
            raise AssertionError("Unlock succeeded with the wrong password.")
        self.run_cli("unlock", LOCKER_NAME, "--password", PASSWORD)

    def lock_with_wrong_password(self) -> None:
        completed = self.run_cli("lock", LOCKER_NAME, "--password", WRONG_PASSWORD, check=False)
        if completed.returncode == 0:
            raise AssertionError("Lock succeeded with the wrong password.")

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

        completed = self.run_cli("status", LOCKER_NAME, check=False)
        if completed.returncode == 0:
            self.run_cli("unlock", LOCKER_NAME, "--password", PASSWORD, check=False)
            self.run_cli("remove", LOCKER_NAME, "--force", check=False)

        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def run(self) -> int:
        tests = [
            ("Version Command", self.version_command),
            ("Help Command", self.help_command),
            ("Command Help Details", self.command_help_details),
            ("List Empty Lockers", self.list_empty_lockers),
            ("Settings Command", self.settings_command),
            ("Database Commands", self.database_commands),
            ("Create Locker", self.create_locker),
            ("Create Test Files", self.create_test_files),
            ("List Lockers", self.list_lockers),
            ("Lock Locker", self.lock_locker),
            ("Verify Locked", self.verify_locked),
            ("List Filters Locked", self.list_filters_locked),
            ("Unlock Locker", self.unlock_locker),
            ("List Filters Unlocked", self.list_filters_unlocked),
            ("Verify Files Intact", self.verify_files_intact),
            ("Verify Command", self.verify_command),
            ("Missing Locker Errors", self.missing_locker_errors),
            ("Unlock with Wrong Password", self.unlock_with_wrong_password),
            ("Lock with Wrong Password", self.lock_with_wrong_password),
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

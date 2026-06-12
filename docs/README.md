# ColDog Locker Documentation

This directory contains the working documentation for ColDog Locker.

## Start Here

- [How to Use ColDog Locker](how-to-use.md) - everyday GUI, TUI, and CLI workflows.
- [CLI Reference](cli-reference.md) - command-by-command reference for `cdlocker`.
- [cdlocker(1)](cdlocker.1.md) - man-style command reference.
- [FAQ](faq.md) - common user and maintainer questions.

## Technical Notes

- [Architecture](architecture.md) - current solution layout and runtime flow.
- [Security Features](security-features.md) - cryptography, password rules, path protection, and threat model.
- [GUI Status and Plans](gui-plans.md) - current WPF/Avalonia/TUI status and UI direction.
- [Distribution Plan](distribution-plan.md) - build, publish, packaging, update, and installer notes.
- [Local Packaging](packaging.md) - local package build and validation commands.
- [Release Automation](release-automation.md) - current release CI shape.

## Current Status

ColDog Locker is pre-release software. The CLI, TUI, and Avalonia GUI are implemented, while the WPF GUI remains temporarily as a legacy migration reference. Windows, Linux, and experimental macOS package projects are available for local builds, manual package CI, and automated releases from `main`. macOS `.pkg` builds are unsigned, unnotarized, and untested. CI covers unit and CLI E2E tests on Windows, Linux, and macOS; GUI E2E validation is still future work.

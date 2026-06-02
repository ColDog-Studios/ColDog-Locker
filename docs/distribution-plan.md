# Distribution Plan

ColDog Locker is pre-release. This document tracks the practical distribution plan based on the current project layout and publish settings.

## Current Build Reality

The active solution file is:

```text
ColDogLocker.slnx
```

The shared build configuration is in `Directory.Build.props`:

- Target framework: `.NET 10`
- Runtime identifiers: `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `linux-musl-x64`, `linux-musl-arm64`
- Version source: `0.5.0-alpha`

The CLI project is configured so RID-based publishes are:

- Single-file.
- Self-contained.
- Trimmed.
- Including native libraries for self-extract.

This differs from older framework-dependent, separate-DLL planning.

## Primary Artifacts

| Artifact | Project | Purpose |
| --- | --- | --- |
| `cdlocker` / `cdlocker.exe` | `ColDogLocker.Cli` | CLI, TUI launcher, GUI launcher, automation surface. |
| `ColDogLocker.exe` | `ColDogLocker.Gui.WPF` | Windows WPF GUI. |
| `ColDogLocker` | `ColDogLocker.Avalonia` | Experimental Avalonia GUI output. |

The `Application` and `Infrastructure` DLLs from older planning docs are not part of the current solution.

## Recommended Release Scope

### Windows

Windows should be the first packaged release target because the WPF GUI is the most complete GUI.

Recommended package:

- MSI installer for `win-x64`.
- Optional `win-arm64` once tested.
- Install the CLI and WPF GUI together.
- Add Start Menu entry for the GUI.
- Optionally add install directory to `PATH` for `cdlocker`.

### Linux

Linux packaging is useful for CLI/TUI first, with Avalonia labeled experimental until feature parity improves.

Possible packages:

- `.deb` for Debian/Ubuntu-family distributions.
- `.rpm` for Fedora/RHEL/openSUSE-family distributions.
- Tarball for generic CLI/TUI use if installers are not ready.

### macOS

macOS GUI launching is not implemented. Treat macOS as future work unless a CLI/TUI-only package is intentionally produced and tested.

## Publish Commands

CLI examples:

```bash
dotnet publish ColDogLocker.Cli/ColDogLocker.Cli.csproj -c Release -r win-x64
dotnet publish ColDogLocker.Cli/ColDogLocker.Cli.csproj -c Release -r linux-x64
```

WPF GUI:

```bash
dotnet publish ColDogLocker.Gui.WPF/ColDogLocker.Gui.WPF.csproj -c Release -r win-x64
```

Avalonia GUI:

```bash
dotnet publish ColDogLocker.Avalonia/ColDogLocker.Avalonia.csproj -c Release -r linux-x64
```

## Installer Layout

Suggested Windows install directory:

```text
C:\Program Files\ColDog Studios\ColDog Locker\
```

Suggested contents:

```text
ColDog Locker\
├── cdlocker.exe
├── ColDogLocker.exe
├── LICENSE
└── README.md
```

If a framework-dependent WPF build is used for the GUI, include the required DLLs and runtime dependencies in the app directory. If the release stays self-contained/single-file for CLI, keep that packaging choice explicit in release notes.

## User Data

User data is per-user and must remain outside Program Files:

```text
%LOCALAPPDATA%\ColDog Studios\ColDog Locker\
├── settings.json
├── lockers.db
└── logs\
```

Uninstallers should preserve this data by default. If data removal is offered, it should be an explicit unchecked option.

## Updates

The application update checker uses GitHub Releases.

Current behavior:

- Stable channel checks the latest stable release.
- Unstable channel scans published non-draft releases.
- Platform detection chooses Windows, Linux DEB, Linux RPM, macOS, or unsupported.
- Automatic download requires a matching asset and a GitHub `sha256:` digest.
- Downloads go to the user's Downloads folder.
- The installer must still be run manually.

Release assets should use names that the update selector can match by OS, architecture, and package family.

Suggested names:

```text
ColDogLocker-0.5.0-alpha-win-x64.msi
ColDogLocker-0.5.0-alpha-win-arm64.msi
ColDogLocker-0.5.0-alpha-linux-x64.deb
ColDogLocker-0.5.0-alpha-linux-x64.rpm
```

## Code Signing

Current expected state:

- No code signing.
- SmartScreen warnings may appear on Windows.
- Antivirus false positives are possible because the app encrypts files.

Future stable releases should consider:

- Windows code signing certificate.
- Submitting release builds to Microsoft Defender.
- Clear release notes explaining legitimate encryption behavior.

## Release Checklist

1. Run tests:

```bash
dotnet test
```

2. Publish target artifacts.
3. Test on a clean machine or VM for each target.
4. Confirm `cdlocker --version`.
5. Confirm `cdlocker new`, `lock`, `unlock`, `verify`, and `remove`.
6. Confirm WPF GUI workflows on Windows.
7. Confirm TUI workflows on non-GUI environments.
8. Confirm update asset naming and SHA-256 digest availability.
9. Create a GitHub Release with clear stable/unstable intent.
10. Verify `cdlocker update --notes` and `cdlocker update --download` behavior after publishing.

## Open Distribution Decisions

- Whether Windows releases should bundle WPF as framework-dependent or self-contained.
- Whether CLI and GUI should be installed as one package or split packages.
- Whether Linux should start as CLI/TUI-only until Avalonia reaches parity.
- Whether ARM64 packages are supported now or only published after hardware/VM testing.
- Whether macOS is intentionally unsupported for the current release line.

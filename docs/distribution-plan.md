# Distribution Plan

ColDog Locker is pre-release. This document tracks the practical distribution plan based on the current project layout and publish settings.

## Current Build Reality

The active solution file is:

```text
ColDogLocker.slnx
```

The shared build configuration is in `Directory.Build.props`:

- Target framework: `.NET 10`
- Runtime identifiers: `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `linux-musl-x64`, `linux-musl-arm64`, `osx-x64`, `osx-arm64`
- Version source: the `Version` property in `Directory.Build.props`

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
| `ColDogLocker.exe` / `ColDogLocker` | `ColDogLocker.Avalonia` | Active graphical interface. |
| `ColDogLocker.exe` | `ColDogLocker.Gui.WPF` | Legacy Windows WPF GUI kept temporarily as a migration reference. |

The `Application` and `Infrastructure` DLLs from older planning docs are not part of the current solution.

## Recommended Release Scope

### Windows

Windows local packaging is implemented through WiX MSI builds for `win-x64` and `win-arm64`.

Implemented package behavior:

- Install the CLI and Avalonia GUI together.
- Install per-machine only under `Program Files`.
- Add the install directory to the machine `PATH` for `cdlocker`.
- Add a Start Menu entry for the GUI.
- Offer the desktop shortcut as an optional per-user MSI feature, not through `Public\Desktop`.
- Do not split CLI and GUI into separate installers.

### Linux

Linux local packaging is implemented for `linux-x64` and `linux-arm64`.

Implemented packages:

- `.deb` for Debian/Ubuntu-family distributions.
- `.rpm` for Fedora/RHEL/openSUSE-family distributions.
- The CLI and Avalonia GUI are installed together under `/opt/coldog-locker`.
- `/usr/bin/cdlocker` links to `/opt/coldog-locker/cdlocker`.
- `/usr/share/applications/coldog-locker.desktop` launches the Avalonia GUI from desktop menus.
- `/usr/share/applications/cdlocker.desktop` opens the terminal interface with `cdlocker tui`.
- `/usr/share/icons/hicolor/256x256/apps/coldog-locker.png` provides the desktop menu icon.
- Do not split CLI and GUI into separate packages.

### macOS

macOS local packaging is implemented as an experimental unsigned `.pkg` for `osx-x64` and `osx-arm64`.

Experimental package behavior:

- Install the CLI and Avalonia GUI together.
- Install the GUI app bundle under `/Applications/ColDog Locker.app`.
- Install the CLI command as `/usr/local/bin/cdlocker`.
- Do not split CLI and GUI into separate packages.
- Treat macOS release assets as experimental until macOS validation, signing, and notarization decisions are revisited.

The current CLI still reports macOS GUI launching as unsupported. Launch the experimental GUI directly from `/Applications/ColDog Locker.app` when testing the `.pkg`.

## Publish Commands

CLI examples:

```bash
dotnet publish ColDogLocker.Cli/ColDogLocker.Cli.csproj -c Release -r win-x64
dotnet publish ColDogLocker.Cli/ColDogLocker.Cli.csproj -c Release -r linux-x64
```

Installer packages are built through:

```bash
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=x64
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=deb -p:PackageArchitecture=x64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=rpm -p:PackageArchitecture=x64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=x64 -p:Configuration=Release
```

See [Local Packaging](packaging.md) for prerequisites, exact commands, and output paths.

WPF GUI:

```bash
dotnet publish ColDogLocker.Gui.WPF/ColDogLocker.Gui.WPF.csproj -c Release -r win-x64
```

Avalonia GUI:

```bash
dotnet publish ColDogLocker.Avalonia/ColDogLocker.Avalonia.csproj -c Release -r linux-x64
```

## Installer Layout

Windows install directory:

```text
C:\Program Files\ColDogStudios\ColDogLocker\
```

Windows contents:

```text
ColDog Locker\
├── cdlocker.exe
├── ColDogLocker.exe
├── LICENSE
└── README.md
```

In the recommended package, `ColDogLocker.exe` is the Avalonia GUI. If the legacy WPF app is packaged temporarily, keep it in a separate folder because it uses the same executable name. If the release stays self-contained/single-file for CLI, keep that packaging choice explicit in release notes.

## User Data

User data is per-user and remains outside Program Files and `/opt`:

```text
%LOCALAPPDATA%\ColDog Studios\ColDog Locker\
├── settings.json
├── lockers.db
└── logs\
```

The MSI includes an uninstall cleanup action controlled by the `REMOVE_USER_DATA_ON_UNINSTALL` property, defaulted to `1`. MSI same-version major upgrades are enabled so prerelease and stable packages that share the same numeric Windows Installer `ProductVersion` can still replace each other. Linux package managers do not provide an interactive per-user uninstall checkbox; package removal leaves per-user app data in place, and Debian purge removes reserved system config/data directories if future versions add them.

The experimental macOS `.pkg` does not provide a native uninstall checkbox. Remove `/Applications/ColDog Locker.app` and `/usr/local/bin/cdlocker` manually during testing.

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
On Windows, the updater prefers the `.msi` asset when both `.msi` and setup `.exe` assets are present because the installed app already has the required .NET runtime available.
Conventional Commit release notes are generated during release publishing and rendered automatically by update checks when available.

Suggested names:

```text
ColDogLocker-<version>-win-x64.msi
ColDogLocker-<version>-win-arm64.msi
ColDogLocker-<version>-win-x64-setup.exe
ColDogLocker-<version>-win-arm64-setup.exe
ColDogLocker-<version>-linux-x64.deb
ColDogLocker-<version>-linux-arm64.deb
ColDogLocker-<version>-linux-x64.rpm
ColDogLocker-<version>-linux-arm64.rpm
ColDogLocker-<version>-macos-x64.pkg
ColDogLocker-<version>-macos-arm64.pkg
```

## Code Signing

Current expected state:

- No code signing.
- SmartScreen warnings may appear on Windows.
- Gatekeeper warnings should be expected for unsigned, unnotarized experimental macOS packages.
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

CI also runs unit and CLI E2E tests on Windows, Linux, and macOS. macOS GUI E2E testing is not implemented yet.

2. Publish target artifacts.
3. Test on a clean machine or VM for each target.
4. Confirm `cdlocker --version`.
5. Confirm `cdlocker new`, `lock`, `unlock`, `verify`, and `remove`.
6. Confirm Avalonia GUI workflows on Windows.
7. Confirm Linux desktop menu entries for `ColDogLocker` and `cdlocker`.
8. Confirm experimental macOS `.pkg` install, `/usr/local/bin/cdlocker`, and `/Applications/ColDog Locker.app`.
9. Confirm TUI workflows on non-GUI environments.
10. Validate RPM metadata and paths locally on Fedora with `rpm -qpi` and `rpm -qpl`.
11. Confirm update asset naming and SHA-256 digest availability.
12. Verify `cdlocker update` release notes and `cdlocker update --download` behavior after publishing.

## Open Distribution Decisions

- Whether macOS should remain experimental/unsigned or be promoted later with Developer ID signing and notarization.
- Whether Linux GUI package dependencies should be declared explicitly once clean distro VM testing identifies the minimum native library set.

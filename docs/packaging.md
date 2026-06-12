# Local Packaging

ColDog Locker packages are built from the current MSBuild version metadata in `Directory.Build.props`. The installer projects inherit that metadata at build time, so package names and metadata follow the same `Version`, `FileVersion`, `InformationalVersion`, and `AssemblyVersion` values used by the app.

Release automation passes the computed release version with `-p:Version=<release-version>` so prerelease sequence tags, package names, and the app-reported version stay aligned. Local package builds can use the same property override when validating a release candidate.

## Supported Packages

| OS | Format | Architectures | Install scope |
| --- | --- | --- | --- |
| Windows | `.msi` through WiX | `x64`, `arm64` | Per-machine only |
| Windows | `.exe` setup bundle through WiX Burn | `x64`, `arm64` | Per-machine only |
| Linux | `.deb` | `x64`, `arm64` | System package |
| Linux | `.rpm` | `x64`, `arm64` | System package |
| macOS | `.pkg` through `pkgbuild` | `x64`, `arm64` | System package, experimental |

macOS packages are unsigned, unnotarized, untested, and experimental. They are intended for local validation only until macOS support is deliberately promoted.

The active package contents are:

- `ColDogLocker.Cli` as `cdlocker` / `cdlocker.exe`.
- `ColDogLocker.Avalonia` as `ColDogLocker` / `ColDogLocker.exe`.
- `README.md`, `LICENSE`, and the shared icon.

On macOS, the CLI is installed as `/usr/local/bin/cdlocker` and the GUI is installed as `/Applications/ColDog Locker.app`.

Each installer/package is intentionally a combined app package. The CLI and GUI are not built or distributed as separate installers.

The legacy WPF project is not packaged.

## Prerequisites

- .NET SDK 10.
- WiX 6 is restored through `WixToolset.Sdk` and NuGet when building Windows installers.
- A Windows host for `.msi` and `.exe` setup bundles; WiX restores on Linux but Windows installer build execution is Windows-only.
- `ar`, `tar`, and `gzip` for `.deb`.
- `rpmbuild` for `.rpm`.
- A native or compatible RPM build host for arm64 RPMs.
- A macOS host with Xcode command line tools for `.pkg`; `pkgbuild` is not available on Linux or Windows.

Fedora/RHEL example for RPM tooling:

```bash
sudo dnf install rpm-build
```

Fedora local RPM validation can be done with `rpm` after building the package:

```bash
rpm -qpi artifacts/packages/dist/ColDogLocker-<version>-linux-x64.rpm
rpm -qpl artifacts/packages/dist/ColDogLocker-<version>-linux-x64.rpm
```

For a real install/remove smoke test on Fedora, use a clean machine or VM and run `sudo dnf install ./artifacts/packages/dist/ColDogLocker-<version>-linux-x64.rpm`, then remove it with `sudo dnf remove coldog-locker`.

## Build Commands

Manual CI packaging is available from the `Packages` workflow in GitHub Actions. Automated releases are published by the `Release` workflow on pushes to `main` and by manual dispatch.

The manual `Packages` workflow still keeps the macOS package job opt-in because those packages are experimental and unsigned. The automated `Release` workflow includes macOS `.pkg` assets so update checks can see the same platform matrix as Windows and Linux.

Windows MSI and setup EXE:

```bash
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=x64
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=arm64
```

Windows MSI only:

```bash
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=x64 -p:BuildSetupBundle=false
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=arm64 -p:BuildSetupBundle=false
```

Linux DEB:

```bash
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=deb -p:PackageArchitecture=x64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=deb -p:PackageArchitecture=arm64 -p:Configuration=Release
```

Linux RPM:

```bash
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=rpm -p:PackageArchitecture=x64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=rpm -p:PackageArchitecture=arm64 -p:Configuration=Release
```

Local RPM metadata validation on Fedora:

```bash
rpm -qpi artifacts/packages/dist/ColDogLocker-<version>-linux-x64.rpm
rpm -qpl artifacts/packages/dist/ColDogLocker-<version>-linux-x64.rpm
```

macOS PKG, experimental unsigned:

```bash
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=x64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=arm64 -p:Configuration=Release
```

In practice, run MSI builds on Windows, Linux package builds on Linux, and macOS package builds on macOS. RPM arm64 builds need an arm64 RPM-capable runner or build environment; an x64 Fedora host may reject `aarch64` package builds as an incompatible build architecture.

Expected package output:

```text
artifacts/packages/dist/ColDogLocker-<version>-win-x64.msi
artifacts/packages/dist/ColDogLocker-<version>-win-arm64.msi
artifacts/packages/dist/ColDogLocker-<version>-win-x64-setup.exe
artifacts/packages/dist/ColDogLocker-<version>-win-arm64-setup.exe
artifacts/packages/dist/ColDogLocker-<version>-linux-x64.deb
artifacts/packages/dist/ColDogLocker-<version>-linux-arm64.deb
artifacts/packages/dist/ColDogLocker-<version>-linux-x64.rpm
artifacts/packages/dist/ColDogLocker-<version>-linux-arm64.rpm
artifacts/packages/dist/ColDogLocker-<version>-macos-x64.pkg
artifacts/packages/dist/ColDogLocker-<version>-macos-arm64.pkg
```

Publish output, staging trees, generated Debian control files, and generated RPM specs are under `artifacts/packages/`.

## Windows Installer Behavior

The MSI installs per-machine under:

```text
C:\Program Files\ColDog Studios\ColDog Locker\
```

It adds that install directory to the machine `PATH`, which exposes `cdlocker.exe` as `cdlocker` from new command prompts after installation.

The MSI is framework-dependent and requires the .NET 10 Runtime for the target architecture. If the runtime is missing, direct MSI installation is blocked with a link to the .NET 10 download page.

The setup EXE is the recommended Windows installer for normal users. It checks for the .NET 10 Core Runtime, downloads and installs the pinned Microsoft runtime package if needed, then launches the MSI UI. The EXE does not embed the .NET runtime, so its size stays close to the MSI plus bootstrapper overhead. Update `DotNetRuntimeVersion`, `DotNetRuntimeDownloadUrl`, `DotNetRuntimeSha512`, and `DotNetRuntimeSize` in `ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj` when moving to a newer .NET 10 runtime package.

The desktop shortcut is an optional MSI feature and targets the installing user's desktop through `DesktopFolder`; it is not placed in `Public\Desktop`.

The Start Menu shortcut is installed by default.

The MSI has a feature-tree option named `Remove stored config and data on uninstall`, selected by default. Silent uninstall can also set `REMOVE_USER_DATA_ON_UNINSTALL=0` to preserve ColDog Locker settings, logs, locker metadata, and the default locker folder.

Code signing is not configured.

MSI major upgrades use a stable `UpgradeCode`, so newer package versions replace older versions normally. The MSI `ProductVersion` uses the numeric base version because Windows Installer does not accept semantic prerelease labels. Same-version major upgrades are enabled so a prerelease and stable package with the same numeric base version can still replace each other.

## Linux Package Layout

Linux packages install root-owned app files under:

```text
/opt/coldog-locker/
```

The CLI command is exposed through:

```text
/usr/bin/cdlocker -> /opt/coldog-locker/cdlocker
```

Linux desktop application entries are installed under:

```text
/usr/share/applications/coldog-locker.desktop
/usr/share/applications/cdlocker.desktop
```

`coldog-locker.desktop` appears as `ColDogLocker` and launches the Avalonia GUI from `/opt/coldog-locker/ColDogLocker`. `cdlocker.desktop` appears as `cdlocker` and opens the terminal interface with `cdlocker tui` so desktop users can see that the CLI/TUI entrypoint is installed.

The desktop icon is installed under:

```text
/usr/share/icons/hicolor/256x256/apps/coldog-locker.png
```

The app currently stores runtime data per user through .NET `LocalApplicationData`. On Linux, that normally resolves under the user's local data area, for example:

```text
~/.local/share/ColDog Studios/ColDog Locker/
```

The default locker parent directory remains the user's documents folder as defined by `AppPaths.CdlDir`. The packages do not create `/etc/coldog-locker` or `/var/lib/coldog-locker` because the current app does not read system-wide config or shared state.

Debian package purge removes reserved system config/data directories if they are added later. Normal package removal leaves per-user app data in place because Debian and RPM package managers do not provide an interactive uninstall checkbox for per-user home directories.

On Fedora, use `rpm -qpi` and `rpm -qpl` to validate RPM metadata and installed paths without installing it. Use a clean machine or VM for real `sudo dnf install` / `sudo dnf remove` smoke tests.

## macOS Package Layout

The macOS `.pkg` is experimental, unsigned, unnotarized, and untested. It installs system-wide and may trigger Gatekeeper warnings or require manual override on first launch.

The GUI app bundle is installed under:

```text
/Applications/ColDog Locker.app
```

The CLI command is installed under:

```text
/usr/local/bin/cdlocker
```

The package installs both the CLI and Avalonia GUI together. The current CLI still reports macOS GUI launching as unsupported, so launch the experimental GUI directly from `/Applications/ColDog Locker.app` when validating it.

The `.pkg` format does not provide a native uninstall checkbox. Remove the experimental macOS package files manually:

```bash
sudo rm -rf "/Applications/ColDog Locker.app"
sudo rm -f /usr/local/bin/cdlocker
```

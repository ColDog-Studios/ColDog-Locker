# Release Automation

Release automation is wired through `.github/workflows/release.yml`.

Current policy:

- Pushes to `main` publish an automated release.
- Other branches do not publish releases automatically.
- `workflow_dispatch` can run the same release flow manually.
- macOS `.pkg` assets are included, but they remain unsigned, unnotarized, and experimental.
- `conventional-changelog` generates release notes from Conventional Commit messages so the app can render the release markdown through update checks.
- Release note sections are configured in `.github/conventional-changelog.config.mjs`.

## Version And Tags

The workflow reads `Version` from `Directory.Build.props`.

If `Version` contains a prerelease label, the workflow checks existing GitHub releases and remote tags, then uses the next sequence number for that base version and label:

```text
v<major>.<minor>.<patch>-<alpha|beta|rc>.<sequence>
```

For example, if no existing `0.8.0-alpha` release exists, `0.8.0-alpha` becomes:

```text
v0.8.0-alpha.1
```

If `v0.8.0-alpha.1` and `v0.8.0-alpha.2` already exist, the next release becomes `v0.8.0-alpha.3`.

Only `alpha`, `beta`, and `rc` prerelease labels are accepted by the automated metadata step. If `Version` is stable-shaped, the release tag uses that version directly and the workflow fails if the tag already exists:

```text
v0.8.0
```

Automated package builds override the MSBuild `Version` value with the computed release version. Package filenames, package metadata, and the generated `AppInfo.SemanticVersion` value inside the app therefore match the GitHub release tag used by update checks.

## Automated Flow

For `main` and manual dispatch:

1. Check out the triggering commit.
2. Read `Version` from `Directory.Build.props`.
3. Restore, build, and test the Core, Services, and Avalonia test projects in `Release`.
4. Publish the CLI and run the CLI E2E workflow against the published binary.
5. Build Windows x64 and arm64 `.msi` plus setup `.exe` installers.
6. Build Linux x64 and arm64 `.deb` packages.
7. Build Linux x64 and arm64 `.rpm` packages.
8. Build experimental unsigned macOS x64 and arm64 `.pkg` packages.
9. Download all package artifacts into one release asset directory.
10. Create the GitHub release for the computed tag.
11. Upload `.msi`, `.exe`, `.deb`, `.rpm`, and `.pkg` assets.
12. Generate release notes from Conventional Commit messages with the `conventionalcommits` preset.

The release job uses `contents: write` so it can create tags and GitHub Releases.

## Current Package Build Entrypoints

Windows MSI and setup EXE:

```powershell
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=x64 -p:Version=<release-version>
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=arm64 -p:Version=<release-version>
```

Linux DEB/RPM:

```bash
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=deb -p:PackageArchitecture=x64 -p:Configuration=Release -p:Version=<release-version>
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=deb -p:PackageArchitecture=arm64 -p:Configuration=Release -p:Version=<release-version>
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=rpm -p:PackageArchitecture=x64 -p:Configuration=Release -p:Version=<release-version>
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=rpm -p:PackageArchitecture=arm64 -p:Configuration=Release -p:Version=<release-version>
```

macOS PKG, experimental unsigned:

```bash
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=x64 -p:Configuration=Release -p:Version=<release-version>
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=arm64 -p:Configuration=Release -p:Version=<release-version>
```

## Release Validation

After the release is published:

1. Confirm all expected Windows, Linux, and macOS assets are attached.
2. Confirm GitHub shows digest metadata for package assets.
3. Confirm `cdlocker update` renders the generated Conventional Commit release notes when the app is on the matching update channel.
4. Confirm `cdlocker update --download` downloads and verifies the matching package. On Windows, this should be the `.msi` asset when both `.msi` and setup `.exe` assets are attached.
5. Test installers on clean Windows, Linux, and macOS machines or VMs before treating the release as broadly usable.

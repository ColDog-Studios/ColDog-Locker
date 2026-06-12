# Release Automation

Release automation is wired through `.github/workflows/release.yml`.

Current alpha policy:

- Pushes to `main` publish an automated prerelease.
- Pushes to `test` publish an automated prerelease.
- `workflow_dispatch` can publish the same prerelease flow manually.
- macOS packages remain excluded from automated releases because they are unsigned, unnotarized, and experimental.

## Version And Tags

The workflow reads `Version` from `Directory.Build.props`.

Automated prerelease tags include the source branch and workflow run identifiers so repeated alpha builds do not collide:

```text
v<version>.<branch>.<run-number>.<run-attempt>
v<version>-<branch>.<run-number>.<run-attempt>
```

If `Version` already contains a prerelease label, the branch/run suffix is appended to that label. For example, `0.8.0-alpha` on `main` becomes:

```text
v0.8.0-alpha.main.123.1
```

If `Version` is stable-shaped, the workflow still publishes a prerelease by adding a prerelease suffix. For example, `0.8.0` on `test` becomes:

```text
v0.8.0-test.123.1
```

Package filenames still use the MSBuild `Version` value, so assets keep the app/package version while release tags stay unique during alpha testing.

## Automated Flow

For `main`, `test`, and manual dispatch:

1. Check out the triggering commit.
2. Read `Version` from `Directory.Build.props`.
3. Run `dotnet test` in `Release`.
4. Build Windows x64 and arm64 `.msi` plus setup `.exe` installers.
5. Build Linux x64 and arm64 `.deb` packages.
6. Build Linux x64 and arm64 `.rpm` packages.
7. Download all package artifacts into one release asset directory.
8. Generate `SHA256SUMS.txt`.
9. Create a GitHub prerelease for the unique tag.
10. Upload `.msi`, `.exe`, `.deb`, `.rpm`, and `SHA256SUMS.txt` assets.

The release job uses `contents: write` so it can create tags and GitHub Releases.

## Current Package Build Entrypoints

Windows MSI and setup EXE:

```powershell
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=x64
dotnet build ColDogLocker.Installer.Windows/ColDogLocker.Installer.Windows.wixproj -c Release -p:PackageArchitecture=arm64
```

Linux DEB/RPM:

```bash
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=deb -p:PackageArchitecture=x64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=deb -p:PackageArchitecture=arm64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=rpm -p:PackageArchitecture=x64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Linux/ColDogLocker.Installer.Linux.proj -t:Build -p:PackageFormat=rpm -p:PackageArchitecture=arm64 -p:Configuration=Release
```

macOS PKG, experimental unsigned:

```bash
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=x64 -p:Configuration=Release
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=arm64 -p:Configuration=Release
```

## Release Validation

After the prerelease is published:

1. Confirm all expected Windows and Linux assets are attached.
2. Confirm GitHub shows `sha256:` digests for package assets.
3. Confirm `cdlocker update --notes` sees the prerelease when the app is on the unstable update channel.
4. Confirm `cdlocker update --download` downloads and verifies the matching package. On Windows, this should be the `.msi` asset when both `.msi` and setup `.exe` assets are attached.
5. Test installers on clean Windows and Linux machines or VMs before treating the prerelease as broadly usable.

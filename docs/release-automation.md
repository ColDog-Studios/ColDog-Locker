# Release Automation Plan

This is the intended shape for future CI release automation. It is not wired into workflows yet.

Package artifact CI is wired through `.github/workflows/package.yml` as a manual workflow. Its future `push` trigger is intentionally commented out until release automation is ready.

The workflow has an opt-in macOS package job for experimental unsigned `.pkg` artifacts. That job defaults off and should stay excluded from supported release automation until macOS validation, signing, and notarization decisions are revisited.

## Branch Model

Use branch pushes, not pull request events, as the release trigger:

- `main`: create a production GitHub Release.
- `test` or `staging`: create a prerelease GitHub Release.

With branch protection, a push to `main` normally means an accepted pull request was merged. If direct pushes are allowed, they will trigger the same release workflow.

## Version Source

The workflow should read `Version` from `Directory.Build.props` and use it as the release version source.

Recommended tag names:

```text
v<version>
v<version-with-prerelease>
```

For repeated prerelease builds from a staging branch, the workflow needs either:

- A unique version in `Directory.Build.props` for each prerelease, or
- A CI suffix in the staging tag and asset names, such as `v<version>.42`.

Git tags and release asset names must be unique. Reusing the same version for repeated staging releases will conflict unless the workflow deletes/replaces the existing prerelease, which is not a good default.

## Production Release Flow

For `main`:

1. Check out the merge commit.
2. Read `Version` from `Directory.Build.props`.
3. Fail if tag `v<Version>` or a release for that tag already exists.
4. Run tests.
5. Build package artifacts for Windows and Linux.
6. Create tag `v<Version>` at the merge commit.
7. Create a GitHub Release for the tag.
8. Generate release notes from merged pull requests.
9. Upload `.msi`, `.deb`, and `.rpm` assets.
10. Mark the release as latest.

The release job needs `contents: write` permissions.

## Staging Prerelease Flow

For `test` or `staging`:

1. Check out the staging commit.
2. Read `Version` from `Directory.Build.props`.
3. Add a unique CI suffix if the branch can publish more than one prerelease per version.
4. Run tests.
5. Build package artifacts.
6. Create a staging tag.
7. Create a GitHub prerelease.
8. Generate release notes.
9. Upload package assets.

Prereleases should not be marked as latest. GitHub does not allow drafts or prereleases to be latest releases.

GitHub-hosted macOS runners are available for manual package validation and automated tests. The test workflow runs unit and CLI E2E jobs on `macos-15-intel` for x64 and `macos-15` for arm64. GUI E2E coverage still needs deliberate design before it should be considered a supported release gate.

## Current Package Build Entrypoints

Windows MSI:

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

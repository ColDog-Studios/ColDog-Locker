# Release Automation

Release automation is wired through `.github/workflows/release.yml`.

Current policy:

- Pushes to `main` publish an automated release.
- Other branches do not publish releases automatically.
- `workflow_dispatch` can run the same release flow manually.
- The active public `Main Branch Rules` ruleset protects the default branch from deletion, requires a pull request, requires test contexts including `Test Summary`, and enforces CodeQL results.
- Package signing on every platform, including macOS notarization, is explicitly deferred by the maintainer. Packages remain unsigned; checksums and the release manifest do not authenticate a publisher.
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

GitHub release classification is label-specific:

- Stable versions with no suffix are full releases and are explicitly marked latest.
- `alpha`, `beta`, and `rc` versions are published as prereleases and explicitly marked not latest.
- The stable client independently rejects draft, prerelease-flagged, and semantically prerelease builds, including older RCs incorrectly marked latest.

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
8. Build unsigned macOS x64 and arm64 `.pkg` packages.
9. On native x64 and ARM64 runners, rebuild each Linux package and require byte identity, then validate it in clean Ubuntu 24.04 or Fedora 43 containers (architecture, installed CLI E2E, GUI startup, reinstall, uninstall).
10. Download package artifacts and generate `SHA256SUMS` plus `release-manifest.json` with the source commit, pinned SDK, artifact sizes/hashes, dependency lock contents, and the validated third-party component inventory. Add the project license and third-party notice/inventory as release assets.
11. Create a signed GitHub artifact attestation over every subject in `SHA256SUMS` using the workflow's short-lived OIDC identity. Verify a downloaded artifact with `gh attestation verify <artifact> --repo ColDog-Studios/ColDog-Locker`.
12. Generate release notes using the npm lock file and `conventionalcommits` preset.
13. Create the release and upload installers, checksums, and manifest.

The release job alone uses `contents: write` so it can create tags and GitHub Releases. It also has `id-token: write` and `attestations: write` for short-lived signed provenance; build jobs retain read-only repository permission.

## Main Branch Protection

The public GitHub API confirmed an active `Main Branch Rules` ruleset on the default branch on 2026-09-25. It currently:

- prevents branch deletion;
- requires a pull request;
- requires `Test Summary` and the listed Windows/Linux/macOS unit and CLI E2E contexts; and
- enforces CodeQL high-or-higher security alerts and error-level analysis results.

The ruleset does not currently require a branch to be up to date before merging. Enable strict required-status-check behavior if stale-base merges are not acceptable. Keep `Test Summary` required because it fails unless the dependency audit and every unit/CLI matrix dependency succeed.

The dependency audit restores with NuGet security warnings `NU1901` through `NU1904` promoted to errors, then prints the full direct and transitive vulnerability report.

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

macOS PKG, unsigned:

```bash
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=x64 -p:Configuration=Release -p:Version=<release-version>
dotnet msbuild ColDogLocker.Installer.Mac/ColDogLocker.Installer.Mac.proj -t:Build -p:PackageArchitecture=arm64 -p:Configuration=Release -p:Version=<release-version>
```

## Release Validation

After the release is published:

1. Confirm all expected Windows, Linux, and macOS assets plus `LICENSE`, `THIRD-PARTY-NOTICES.md`, and `THIRD-PARTY-COMPONENTS.json` are attached.
2. Confirm GitHub shows digest metadata for package assets.
3. Confirm `cdlocker update` renders the generated Conventional Commit release notes when the app is on the matching update channel.
4. Confirm `cdlocker update --download` downloads and verifies the matching package. On Windows, this should be the `.msi` asset when both `.msi` and setup `.exe` assets are attached. On macOS, it should select the matching `.pkg` and open Installer.
5. Test installers on clean Windows, Linux, and macOS machines or VMs before treating the release as broadly usable.

## Pinned inputs

Workflow actions use immutable commit references. `global.json` selects SDK 10.0.112 without roll-forward; all CI .NET setup steps read it, including Linux container builds. NuGet lock files are checked in and workflows set `RestoreLockedMode=true`. Single-file analysis stays enabled for ordinary builds as well as publishes, keeping the SDK analyzer package graph stable. `DisableImplicitLibraryPacksFolder` prevents distro-repacked SDK archives from writing non-portable package hashes into those locks. Regenerate locks deliberately with `dotnet restore ColDogLocker.slnx --force-evaluate` after changing dependency versions, and restore `.github/scripts/crash_probe/CrashProbe.csproj` separately. Restore the WiX project separately to update its lock.

Release-note dependencies live in `.github/package.json` and `.github/package-lock.json` and install through `npm ci --ignore-scripts`. Build metadata records a source revision, not the current clock. Linux package archives normalize ordering, ownership and timestamps through `SourceDateEpoch`; repeated-package comparison is enforced for x64 and ARM64. Current WiX releases still generate random MSI package codes and current summary timestamps, so Windows installer byte identity is not claimed. macOS package byte identity also remains unverified. The JSON release manifest is unsigned metadata, while GitHub's artifact attestation binds the checksummed release subjects to the workflow identity and source revision. It does not replace platform code signing. The checked-in notices and component inventory are shipped in each installer and as release assets; they are an engineering inventory, not a legal-compliance opinion.

## Security incident and release rollback

Handle vulnerability reports in a private GitHub security advisory. Record the affected source revision, package names, release-manifest digests, archive/database format versions and reproduction evidence before changing public assets. If a published artifact may be compromised, remove that artifact from distribution, publish a visible warning and prepare a higher-version replacement from reviewed source. Do not silently replace an asset under the same filename or digest.

Use a forward security release. Prerelease format changes can make downgrade unsafe, and the updater has no transactional application rollback. Release notes and the advisory must identify affected versions, whether users should unlock/export first, any database/archive compatibility boundary, recovery steps, and the new asset digests. Run the full source suite, crash-boundary harness, package inventory check and native install/update matrix before restoring normal publication. Rotate any exposed repository, signing or package credentials and replace compromised action/tool pins before rebuilding.

After publication, verify the public assets and digests independently, confirm the update client selects the fixed release, and update the advisory with remediation and disclosure timing. Preserve evidence and withdrawn artifacts in restricted storage for investigation; do not leave known-vulnerable packages available merely to support downgrade.

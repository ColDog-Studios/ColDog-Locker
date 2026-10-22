# Launch review baseline

Reviewed commit: `9d1a618f21d75e46b330ea94e232b740bc5a11ce`, September 16, 2026 (America/Detroit). This file preserves the original scope, not a list of current defects. Current implementation and evidence live in [launch remediation](launch-fixes.md). Detailed original reproduction logs and obsolete source line references remain in Git history.

## Original findings

| ID | Original finding |
| --- | --- |
| F01 | Critical: rollback discards the only complete copy after partial deletion |
| F02 | High: files written during locking can be silently omitted and then deleted |
| F03 | High: no durable recovery protocol for interrupted operations |
| F04 | High: unlocking weakens file permissions and destroys filesystem metadata |
| F05 | High: BCrypt and encryption disagree about what the password is |
| F06 | High: the Properties dialog lets users make locked archives unopenable |
| F07 | High: destructive operations have no shared ownership or concurrency control |
| F08 | High: path protection misses Unix roots and follows protected ancestors through aliases |
| F09 | High: two lockers can own the same directory or overlapping trees |
| F10 | High: creation can produce archives that exceed its own extraction limit |
| F11 | High: normal recovery depends on a database users are not taught to back up |
| F12 | Medium: archive KDF policy needs review before freezing format version 1 |
| F13 | Medium: updater verification does not bind the bytes eventually installed |
| F14 | Medium: update downloads can hang after response headers |
| F15 | Medium: basic CLI commands depend on writable state and network initialization |
| F16 | Medium: published-artifact tests do not currently exercise the shipped configuration reliably |
| F17 | Medium: Linux packages omit native dependency declarations |
| F18 | Medium: release-candidate builds are delivered through the stable channel |
| F19 | Medium: package provenance and release reproducibility are incomplete |
| F20 | Medium: expensive work is repeatedly performed on the GUI thread or across whole trees |
| F21 | Medium: service state can diverge after persistence failures |
| F22 | Low: formatting and exception handling create unnecessary review noise |
| F23 | Medium: public security documentation overstates several guarantees |

## Required launch evidence

- Installed Windows/macOS/Linux packages on x64/ARM64: install, architecture, CLI, GUI startup, upgrade/repair/downgrade refusal where implemented, reinstall, ordinary removal/data preservation and Windows explicit opt-in cleanup. Include no-runtime and unsigned-package prompts.
- Representative files and storage failures: long/Unicode names, large files/entry counts, low space, denied access/read-only input, locked files and safe refusal of unsupported types/storage. Unsupported network/cloud/removable storage must be explicit in public guidance.
- Human GUI assessment: keyboard traversal/focus, real screen-reader speech/names, scaling/high contrast, long text, error dialogs, password paste/password-manager use, close/shutdown during tracked operations.
- Support/security-fix policy, private vulnerability reporting, incident response and forward-fix release policy.
- Artifact inventory: native libraries, runtimes, licenses/notices, digests, provenance, package metadata. NuGet advisory results alone cannot prove artifact safety.

The user permits breaking prerelease changes without backward compatibility and defers signing/notarization. Preserve current-version round trips, authenticated recovery and failure preservation. External cryptographic review remains recommended before stable-format claims.

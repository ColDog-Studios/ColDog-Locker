# GUI Status and Plans

ColDog Locker currently has multiple user interfaces with different maturity levels.

## Status Matrix

| Interface | Status | Notes |
| --- | --- | --- |
| Avalonia GUI | Active graphical interface | Default GUI launched by `cdlocker gui`; remaining work is refinement and cross-platform validation. |
| TUI | Functional terminal menu | Useful where GUI support is unavailable. |
| CLI | Most complete command surface | Best reference for automation and exact behavior. |

## Avalonia GUI

The Avalonia project is the active graphical interface and cross-platform GUI direction.

Current migration focus:

- Refine migrated dialogs and interaction polish.
- Continue replacing platform-specific assumptions with cross-platform behavior.
- Validate the supported graphical workflows on Windows, Linux, and macOS.

The Avalonia project builds the GUI executable as `ColDogLocker.exe` on Windows and `ColDogLocker` on Unix-like platforms.

## GUI Launcher

The CLI owns the GUI launcher:

- Windows: launches the Avalonia GUI executable.
- Linux: launches the Avalonia GUI executable beside the CLI, from source-build paths, or from `/opt/coldog-locker/ColDogLocker` when installed.
- macOS: launches the Avalonia GUI executable beside the CLI, from source-build paths, or from `/Applications/ColDog Locker.app/Contents/MacOS/ColDogLocker` when installed.

The launcher is intentionally a lightweight starter: after the GUI process starts successfully, `cdlocker gui` releases the process handle and returns success instead of staying alive until the GUI exits. Source-build candidates are checked before installed package fallbacks so local development builds do not accidentally launch an already-installed GUI.

## Next GUI Work

1. Validate Avalonia workflows for new, lock, unlock, remove, properties, open location, settings, updates, and dialogs.
2. Polish Avalonia-only behavior and layout details.
3. Validate the installed macOS app-bundle launcher and update handoff on both supported architectures.

## Operation shutdown guard and headless tests

The main window rejects ordinary close requests while tracked startup, refresh, creation, lock/unlock, removal or location-opening work is active. A reference count keeps nested/overlapping work busy until all tracked operations and their error dialogs complete; the status bar explains that the user should wait and close again. This is not cancellation and does not prevent forced termination or establish behavior for every OS shutdown route. Recovery journaling remains required.

The GUI tests use explicit `HeadlessUnitTestSession` dispatch with ordinary xUnit attributes, following [Avalonia's headless session API](https://docs.avaloniaui.net/docs/testing/setting-up-the-headless-platform). The previously excluded MainWindow and Dialog suites are compiled again; the incompatible xUnit-specific adapter is replaced by the base headless package. Each test creates and disposes its own session, and tests remain nonparallel. Coverage includes real XAML bindings, locked-name editing, close rejection during work, handled failures, and overlapping operations.

## Bounded display metadata scans

Locker size display now shares an iterative scanner with a 200,000-entry limit, depth limit 256, and a five-second elapsed-time budget checked between filesystem calls. Missing/inaccessible trees, encountered links/reparse points, overflow or exhausted limits yield an unknown size, not a partial total or zero. Empty directories still display zero. This is best-effort display metadata, not snapshot consistency or a filesystem security boundary; an individual blocked OS call cannot be interrupted by these checks.

New-locker row construction and properties metadata loading run on background tasks. Properties start with loading text, cancel their scan when closed, and do not update closed controls. Main refresh remains background work and scans each locker sequentially. Shared status/theme brushes are immutable so background-created row models and separate UI sessions do not capture a dispatcher-owned mutable brush.

## Refresh cancellation and progress

Refresh owns a cancellation token propagated through the background loader into size traversal. The status bar reports the current locker and exposes Cancel refresh. Cancellation preserves the previously displayed collection and is not shown as an error. Starting a newer refresh cancels its predecessor; cancelled results cannot publish, and queued progress from completed/superseded scans is ignored. Busy tracking remains active until the worker returns. Individual OS calls/SQLite load cannot be forcibly interrupted by this token.

## Recent size cache

Automatic refreshes reuse display size estimates for at most 30 seconds, keyed by locker GUID plus location/revision/lock state. Explicit Refresh always requests fresh size scans. The per-window cache holds at most 256 entries and evicts the oldest sample when full; failed/unknown estimates remain unknown, and cancellation prevents a scan from populating the cache. Filesystem reads run outside the cache lock. The cache is not used by any archive, recovery, integrity or deletion operation. External edits may make a displayed estimate stale within the cache interval; explicit refresh or opening properties obtains a new estimate.

## Locker operation progress and safe cancellation

Lock and unlock run outside the UI thread and publish phase, item and percentage information to the status bar. Archive creation reports inspection and capacity information followed by determinate item progress. Extraction reports each restored item with an indeterminate bar because the authenticated payload does not expose a trusted entry count before it is read.

The operation cancellation token reaches archive enumeration and file reads as well as authenticated extraction and metadata restoration. The Cancel operation command is enabled only before publication. Lock stops accepting cancellation immediately before the source directory is claimed; unlock stops immediately before plaintext staging is published. A request that arrives after that boundary does not interrupt the durable transition. The status bar disables cancellation and explains that publication is underway. Service tests cover cancellation on both safe paths and a request at the lock publication boundary; a headless window test covers the real progress and command bindings.

Lock preflight compares a conservative archive-space estimate with the destination filesystem's available bytes and fails before archive creation when capacity is clearly insufficient. Both lock and unlock report known destination capacity. The current archive header does not expose authenticated plaintext size, so unlock reports that its exact restored size is learned during extraction rather than presenting an unreliable requirement.

## Accessibility metadata

Icon-only toolbar buttons and custom-header menus expose explicit automation names rather than relying on tooltips or nested visual text. Search, sort, locker lists, progress controls and core dialog form fields expose names or label relationships. Status and error text use polite or assertive live announcements as appropriate. The application itself reports `ColDog Locker` instead of Avalonia's generic name. A headless regression checks the main menu/toolbar names and dynamic-status setting.

A real Linux Wayland/AT-SPI inspection on 2026-09-25 found every visible focusable main-window control named and found the expected menu, toolbar, filter, sort and view controls. It invoked New Locker through AT-SPI, verified named Name/Location/Password/Confirm fields and buttons, and successfully moved accessibility focus to every entry. Actual Orca speech, sequential Tab/Shift+Tab behavior, visual focus, high contrast, scaling, and Windows Narrator/macOS VoiceOver still require interactive native testing.

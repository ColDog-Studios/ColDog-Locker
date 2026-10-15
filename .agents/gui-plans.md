# Interface guidance

Avalonia is the active desktop GUI. CLI and GUI expose the same user operations through shared services; TUI scope is essential locker workflows. See [user workflows](../docs/how-to-use.md) and [CLI reference](../docs/cli-reference.md).

## Capability map

| Workflow | CLI | GUI |
| --- | --- | --- |
| Create, lock, unlock, list/status | new, lock, unlock, list/status | File > New Locker; Locker actions; search/grid/list/Properties |
| Edit registration; open location | edit; open | Locker > Properties; Open Location |
| Password change; integrity check | change-password; verify | Locker > Change Password; Verify Integrity |
| Remove registration or delete files | remove; remove --delete | Locker > Remove; Delete Locker and Files (explicit confirmation) |
| Independent archive extraction | recover | Tools > Backup and Recovery > Recover files |
| Pending operations, resolve preparation/committed output, restore registration, history | recovery-list/cancel/finish/restore/history | Backup and Recovery > Recover files > Interrupted operations and recovery history |
| Database information, vacuum, backup, restore | db-info/vacuum/backup/restore | Backup and Recovery > Database; Settings also has vacuum |
| All persisted user settings and reset | settings | Tools > Settings |
| Updates, notes, verified install | update [--download] | Tools > Check for Updates |
| Build/platform info; attributions | --version/dev; about | Help > About; developer information |

Presentation controls (search, sorting, selected-item context menus, dialogs) correspond to CLI queries/options, not terminal rendering. Developer dialog demonstrations are UI development aids rather than user data operations.

## Implementation boundaries

`MainWindowViewModel` injects dialogs/platform/update workflow. Main-window mutation commands respect IsBusy and per-locker service leases. Dialogs take owned snapshots or invoke validated service APIs. A modal maintenance window tracks background work, refuses close/duplicate actions while active, clears passwords afterward and remains usable after startup failure. Recovery never runs a shell/CLI process. Main-window close and desktop shutdown requests refuse tracked active work; forced termination relies on durable journals.

Source-build GUI launcher candidates precede installed fallback paths. `cdlocker gui` returns after starting the child; it bypasses CLI database initialization. Installed binaries are `ColDogLocker.exe` on Windows and `ColDogLocker` on Unix.

## Responsiveness and interaction

Password hashing, locker loading and bounded display scans run off the dispatcher. The size scanner caps entries (200,000), depth (256), and time (five seconds between OS calls); incomplete sizes are unknown. A 256-entry/30-second display cache is bypassed by explicit Refresh. Display estimates never authorize archive/deletion behavior. Properties cancels scans on close; cancelled/superseded refresh retains the old collection.

Lock/unlock report bounded phase/item progress. Cancel is available only before source claim/plaintext publication; safe-cancellation refusal is explained in the status bar. Operations report capacity; exact authenticated restore size is known only during extraction. Never improve timing by removing flushes or weakening validation; [measured baselines](performance.md) inform optimization.

Empty/search states explain what to do next. Ctrl+N creates, F5 refreshes, Ctrl+I opens properties; double-click opens properties. Tooltips reveal truncated names/paths. Password prompts focus input, support Enter/Escape and optional reveal, and clear the input after closing.

New menu and maintenance actions use the existing Material icons with visible text and explicit accessible names. Attributions come from the embedded component/license catalog, grouped by library family with all license terms retained and entries sorted alphabetically. Fonts and ANGLE remain separate because they have their own licensing identity. The packaged inventory records resolved versions and hashes from restored assets, so routine Dependabot version updates do not require hand-editing About or the catalog. Don't hard-code another list.

## Validation

Headless tests use separate `HeadlessUnitTestSession` dispatch and nonparallel xUnit execution. Cover real XAML bindings, service refusal/failure preservation, close guards, safe cancellation and background-work lifetime. Do not claim headless layout or automated control names prove actual screen-reader speech, sequential keyboard traversal, high contrast, scaling or password-manager interaction.

Historical Linux Wayland/AT-SPI inspection found named controls and focusable New Locker fields. Windows Narrator, macOS VoiceOver and manual desktop usability remain required; retain the OS/package/commit and native workflow results when validating a release.

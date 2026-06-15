# GUI Status and Plans

ColDog Locker currently has multiple user interfaces with different maturity levels.

## Status Matrix

| Interface | Status | Notes |
| --- | --- | --- |
| Avalonia GUI | Active migration target | Default GUI launched by `cdlocker gui`; remaining work is refinement and parity validation. |
| WPF GUI | Legacy Windows GUI | Kept temporarily as a reference until the Avalonia migration is ready to fully replace it. |
| TUI | Functional terminal menu | Useful where GUI support is unavailable. |
| CLI | Most complete command surface | Best reference for automation and exact behavior. |

## WPF GUI

The WPF GUI is the older Windows-first graphical app. It remains in the solution for now as a reference during the Avalonia migration.

Implemented capabilities include:

- Load and display lockers.
- Create lockers.
- Optionally lock a new locker immediately.
- Lock and unlock selected lockers.
- Remove unlocked lockers from metadata.
- Open locker properties.
- Open locker locations.
- Toggle grid/list views.
- Refresh locker data.
- Open settings.
- Check for updates.
- Show about, error, password, progress, and message dialogs.
- Apply GUI themes.

Known UI issue:

- WPF menus and toolbar controls still use Segoe Fluent Icons. These should be replaced with redistributable icons so the app is not tied to Windows 10/11 icon availability and so the same icon set can support the Avalonia/Linux GUI work.

## Avalonia GUI

The Avalonia project is the active graphical interface and cross-platform GUI direction.

Current migration focus:

- Validate feature parity against the WPF reference.
- Refine migrated dialogs and interaction polish.
- Continue replacing platform-specific assumptions with cross-platform behavior.

The Avalonia project builds the GUI executable as `ColDogLocker.exe` on Windows and `ColDogLocker` on Unix-like platforms.

## GUI Launcher

The CLI owns the GUI launcher:

- Windows: launches the Avalonia GUI executable.
- Linux: attempts to launch the Avalonia GUI executable.
- macOS: currently unsupported and directs users to the TUI. Experimental `.pkg` builds install `/Applications/ColDog Locker.app` for direct validation, but that path is not treated as supported GUI launch behavior yet.

## Next GUI Work

1. Replace Segoe Fluent Icons with redistributable icon assets or a shared icon library.
2. Validate Avalonia parity for new, lock, unlock, remove, properties, open location, settings, updates, and dialogs.
3. Polish Avalonia-only behavior and layout details.
4. Remove the WPF project once Avalonia is fully accepted as the replacement.

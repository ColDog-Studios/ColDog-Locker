# GUI Status and Plans

ColDog Locker currently has multiple user interfaces with different maturity levels.

## Status Matrix

| Interface | Status | Notes |
| --- | --- | --- |
| WPF GUI | Functional Windows GUI | Primary graphical interface today. |
| Avalonia GUI | Prototype | Cross-platform direction, but not feature-complete. |
| TUI | Functional terminal menu | Useful where GUI support is unavailable. |
| CLI | Most complete command surface | Best reference for automation and exact behavior. |

## WPF GUI

The WPF GUI is the current Windows-first graphical app.

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

The Avalonia project exists as the cross-platform GUI direction.

Current limitations:

- The app shell and menus exist, but locker operations are mostly TODOs or logging placeholders.
- Shared initialization for settings, logging, and database setup is commented out.
- Locker loading is not wired.
- The Linux GUI launcher expects `ColDogLocker.Avalonia.exe`, while the Avalonia project currently builds an assembly named `ColDogLocker`; the launcher/output naming needs to be reconciled.

Avalonia should eventually replace the WPF-specific icon and platform assumptions, but it is not yet at WPF feature parity.

## GUI Launcher

The CLI uses the `ColDogLocker.Gui` launcher abstraction:

- Windows: launches the WPF GUI.
- Linux: attempts to launch Avalonia.
- macOS: currently unsupported and directs users to the TUI.

## Next GUI Work

1. Replace Segoe Fluent Icons with redistributable icon assets or a shared icon library.
2. Fix Avalonia executable naming or launcher lookup.
3. Enable shared initialization in Avalonia.
4. Wire Avalonia locker loading.
5. Port core WPF workflows to Avalonia: new, lock, unlock, remove, properties, open location, settings, updates, and dialogs.
6. Decide whether WPF remains a Windows-specific app or becomes a legacy/compatibility frontend after Avalonia reaches parity.

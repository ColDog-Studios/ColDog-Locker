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
- Linux: attempts to launch the Avalonia GUI executable.
- macOS: launches `/Applications/ColDog Locker.app` from the installed CLI.

## Next GUI Work

1. Validate Avalonia workflows for new, lock, unlock, remove, properties, open location, settings, updates, and dialogs.
2. Polish Avalonia-only behavior and layout details.
3. Validate the installed macOS app-bundle launcher and update handoff on both supported architectures.

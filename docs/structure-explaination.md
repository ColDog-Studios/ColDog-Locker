# ColDogLocker Project Structure

This project follows Clean Architecture principles, organizing code into distinct layers with clear dependencies flowing inward.

## Unified Entry Point

ColDogLocker provides a single executable (`cdlocker.exe`) that acts as a unified entry point to all interfaces:

**Default Behavior** (no parameters):
```bash
cdlocker.exe
# Launches the GUI
```

**Interface Selection**:
```bash
cdlocker.exe gui                                      # Launch GUI explicitly
cdlocker.exe tui                                      # Launch Terminal User Interface
```

**Command-Line Operations** (subcommand-based for cross-platform compatibility):
```bash
cdlocker.exe new <Locker Name>                        # Create new locker
cdlocker.exe new <Locker Name> --path "D:\Lockers"    # Create with custom path

cdlocker.exe remove <Locker Name>                     # Remove locker (prompts for confirmation)
cdlocker.exe remove <Locker Name> --force             # Remove without confirmation

cdlocker.exe lock <Locker Name>                       # Lock a locker (prompts for password)
cdlocker.exe lock <Locker Name> --password <pass>     # Lock with password (scripting)

cdlocker.exe unlock <Locker Name>                     # Unlock a locker (prompts for password)
cdlocker.exe unlock <Locker Name> --password <pass>   # Unlock with password (scripting)

cdlocker.exe list                                     # List all lockers and their status
cdlocker.exe status <Locker Name>                     # Show detailed status of a locker

cdlocker.exe help                                     # Show help information
cdlocker.exe help new                                 # Show help for specific command
cdlocker.exe --version                                # Show version information
```

**PATH Integration**:
When added to the system PATH, the application can be invoked from any working directory:
```bash
cdlocker list
cdlocker lock <Locker Name>
cdlocker terminal
```

**Notes**:
- Commands use a subcommand pattern (like `git`, `docker`, `dotnet`) for better organization
- Sensitive operations (lock/unlock) prompt for passwords by default for security
- The `--password` flag is available for automation but should be used cautiously
- Both `.exe` extension (Windows) and extension-less (Linux) invocations will be supported

## ColDogLocker.Core

The innermost layer containing enterprise business logic and entities.

- **Models**: Domain entities and value objects
- **Interfaces**: Core abstractions and contracts
- **Domain Services**: Business rules and domain logic
- **Enums**: Domain-specific enumerations
- **Exceptions**: Domain-specific exceptions
- **Constants**: Global constants and configuration values

**Dependencies**: None (no external dependencies)

## ColDogLocker.Application

Application business logic and use cases layer.

- **Use Cases**: Application-specific business rules
- **DTOs**: Data Transfer Objects for inter-layer communication
- **Services**: Application services orchestrating domain logic
- **Interfaces**: Application service contracts
- **Mapping**: Object mapping configurations
- **Validation**: Input validation logic
- **Commands/Queries**: CQRS pattern implementation (if applicable)

**Dependencies**: ColDogLocker.Core

## ColDogLocker.Infrastructure

External concerns and implementations of core interfaces.

- **Data Access**: Repository implementations
- **File System**: File operations and storage
- **Encryption**: Cryptographic implementations
- **External Services**: Third-party service integrations
- **Persistence**: Database/storage implementations
  - **Current**: JSON file-based storage for locker database
  - **Planned Migration**: SQLite (or similar lightweight database) for locker data
  - **Configuration**: JSON will remain for application settings and configuration
- **Logging**: Logging infrastructure
- **Configuration**: Configuration providers

**Dependencies**: ColDogLocker.Core, ColDogLocker.Application

**Storage Strategy**:
- **Locker Database**: Currently JSON, planned migration to SQLite for better query performance, transaction support, and data integrity
- **App Configuration**: JSON-based (settings, preferences, user options) - no migration planned
- The repository pattern allows for seamless migration without affecting other layers

## ColDogLocker.Cli

Command-line argument parsing and routing layer. This project handles:

- **Argument Parsing**: Command-line parameter processing
- **Command Routing**: Directing commands to appropriate handlers
- **Interface Selection**: Launching GUI, TUI, or executing CLI commands
- **Help System**: Displaying usage information and documentation
- **Exit Codes**: Returning appropriate status codes for scripting
- **Password Prompting**: Secure password input for lock/unlock operations

The CLI layer serves as the entry point that routes requests to either:
- **GUI** for interactive graphical usage (default behavior or `gui` subcommand)
- **TUI** for terminal-based interactive usage (`tui` subcommand)
- **Direct Commands** for automation and scripting (`new`, `remove`, `lock`, `unlock`, `list`, `status`)

**Dependencies**: ColDogLocker.Application, ColDogLocker.Infrastructure, ColDogLocker.Gui, ColDogLocker.Tui

## ColDogLocker.Gui

Graphical user interface for interactive desktop usage.

- **Views**: User interface screens
- **ViewModels**: MVVM pattern view models
- **Controls**: Custom UI components
- **Converters**: Data binding converters
- **Resources**: UI resources (styles, templates)
- **Services**: GUI-specific services

**Dependencies**: ColDogLocker.Application, ColDogLocker.Infrastructure

## ColDogLocker.Tui

Terminal User Interface, similar to the GUI but for environments with no available graphical interface.

- **Views**: Text-based UI screens
- **Components**: Terminal UI widgets
- **Input Handlers**: Keyboard and mouse event handling
- **Rendering**: Terminal output formatting
- **Navigation**: Screen navigation logic

**Dependencies**: ColDogLocker.Application, ColDogLocker.Infrastructure

## Versioning and Build Information

ColDogLocker uses **automatic build-time version generation** to ensure every build is uniquely identified without manual file editing or pre-build scripts.

### Version Format

The project follows **Semantic Versioning (SemVer)** with build metadata:

- **Version**: `0.1.0-pre` (Semantic version - manually updated in .csproj)
- **BuildNumber**: `20251230.1445` (UTC date/time: `yyyyMMdd.HHmm`)
- **BuildVersion**: `0.1.0-pre+20251230.1445` (Full version with build metadata)
- **BuildDate**: `2025-12-30` (ISO format date)
- **BuildTime**: `14:45:32 UTC` (UTC time with timezone indicator)

### Windows Properties Display

When you right-click on `cdlocker.exe` or `ColDogLocker.exe` → Properties → Details:
- **File Version**: `0.1.0.20251230` (Numeric only, as required by Windows)
- **Product Version**: `0.1.0-pre+20251230.1445` (Full SemVer with build metadata)

### Accessing Build Information in Code

A `BuildInfo` class is automatically generated during compilation at `obj/Debug/net10.0/BuildInfo.g.cs`:

```csharp
using ColDogLocker.Cli;

// Access version information
Console.WriteLine($"Version: {BuildInfo.Version}");
Console.WriteLine($"Build: {BuildInfo.BuildVersion}");
Console.WriteLine($"Built on: {BuildInfo.BuildDate} at {BuildInfo.BuildTime}");
```

**Available Properties**:
- `BuildInfo.Version` - Semantic version (e.g., "0.1.0-pre")
- `BuildInfo.BuildNumber` - Build number (e.g., "20251230.1445")
- `BuildInfo.BuildVersion` - Full version with build metadata (e.g., "0.1.0-pre+20251230.1445")
- `BuildInfo.BuildDate` - Build date in ISO format (e.g., "2025-12-30")
- `BuildInfo.BuildTime` - Build time in UTC (e.g., "14:45:32 UTC")

### How It Works

The version information is generated automatically via an MSBuild target in `ColDogLocker.Cli.csproj`:

1. **At build time**, MSBuild calculates the build number from the current UTC date/time
2. A `BuildInfo.g.cs` file is generated in the `obj/` directory
3. The file is included in compilation automatically
4. **No source files are modified** - the generated file is not tracked by Git
5. Every build gets a unique, traceable identifier

### Updating the Version

To update the semantic version, edit the `<Version>` property in `ColDogLocker.Cli.csproj`:

```xml
<PropertyGroup>
  <Version>0.2.0-beta</Version>  <!-- Update this for new releases -->
</PropertyGroup>
```

The build number is always auto-generated, ensuring deterministic builds and eliminating version conflicts.

## Test Projects

Each layer has a corresponding test project:

- **ColDogLocker.Core.Tests**: Unit tests for domain logic
- **ColDogLocker.Application.Tests**: Application use case tests
- **ColDogLocker.Infrastructure.Tests**: Infrastructure integration tests
- **ColDogLocker.Cli.Tests**: CLI command tests
- **ColDogLocker.Gui.Tests**: GUI interaction tests
- **ColDogLocker.Tui.Tests**: TUI interaction tests

## Dependency Flow

```
        ┌─────────────┐
        │    Core     │ ← Domain layer (no dependencies)
        └─────────────┘
              ↑
        ┌─────────────┐
        │ Application │ ← Use cases layer
        └─────────────┘
              ↑
        ┌──────────────┐
        │Infrastructure│ ← External concerns
        └──────────────┘
              ↑
      ┌───────┴───┬──────────┐
      ↓           ↓          ↓
  ┌───────┐   ┌───────┐  ┌───────┐
  │  TUI  │───│  CLI  │  │  GUI  │ ← Interfaces
  └───────┘   └───────┘  └───────┘
```

**Architecture Notes**:
- **CLI Project** is the main entry point that builds into `cdlocker.exe`
- CLI routes to GUI (default), TUI (with `tui` command), or executes commands directly
- Uses subcommand pattern for clarity and cross-platform compatibility
- GUI and TUI remain independent UI implementations that CLI can launch
- All presentation layers depend on Application and Infrastructure
- Core remains completely independent with no external dependencies

This structure ensures maintainability, testability, and allows swapping implementations without affecting core business logic.
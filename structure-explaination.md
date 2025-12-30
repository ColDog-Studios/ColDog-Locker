# ColDogLocker Project Structure

This project follows Clean Architecture principles, organizing code into distinct layers with clear dependencies flowing inward.

## Unified Entry Point

ColDogLocker provides a single executable (`ColDogLocker.exe`) that acts as a unified entry point to all interfaces:

**Default Behavior** (no parameters):
```bash
ColDogLocker.exe
# Launches the GUI
```

**Interface Selection**:
```bash
ColDogLocker.exe gui                                    # Launch GUI explicitly
ColDogLocker.exe terminal                               # Launch Terminal User Interface
```

**Command-Line Operations** (subcommand-based for cross-platform compatibility):
```bash
ColDogLocker.exe new <Locker Name>                      # Create new locker
ColDogLocker.exe new <Locker Name> --path "D:\Lockers"  # Create with custom path

ColDogLocker.exe remove <Locker Name>                   # Remove locker (prompts for confirmation)
ColDogLocker.exe remove <Locker Name> --force           # Remove without confirmation

ColDogLocker.exe lock <Locker Name>                     # Lock a locker (prompts for password)
ColDogLocker.exe lock <Locker Name> --password <pass>   # Lock with password (scripting)

ColDogLocker.exe unlock <Locker Name>                   # Unlock a locker (prompts for password)
ColDogLocker.exe unlock <Locker Name> --password <pass> # Unlock with password (scripting)

ColDogLocker.exe list                                   # List all lockers and their status
ColDogLocker.exe status <Locker Name>                   # Show detailed status of a locker

ColDogLocker.exe help                                   # Show help information
ColDogLocker.exe help new                               # Show help for specific command
ColDogLocker.exe --version                              # Show version information
```

**PATH Integration**:
When added to the system PATH, the application can be invoked with shorter aliases:
```bash
cdl list
cdl lock <Locker Name>
coldoglocker terminal
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
        ┌─────┴──────┐
        │            │
   ┌────┴───┐    ┌───┴────┐
   │  GUI   │    │  TUI   │ ← UI implementations
   └────────┘    └────────┘
        │            │
        └─────┬──────┘
              ↓
        ┌─────────────┐
        │     CLI     │ ← Unified entry point & router
        └─────────────┘
```

**Architecture Notes**:
- **CLI Project** is the main entry point that builds into `ColDogLocker.exe`
- CLI routes to GUI (default), TUI (with `tui` command), or executes commands directly
- Uses subcommand pattern for clarity and cross-platform compatibility
- GUI and TUI remain independent UI implementations that CLI can launch
- All presentation layers depend on Application and Infrastructure
- Core remains completely independent with no external dependencies

This structure ensures maintainability, testability, and allows swapping implementations without affecting core business logic.
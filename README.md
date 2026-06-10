<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->

[![Stable Release][stable-release-shield]][stable-release-url]
[![Unstable Release][unstable-release-shield]][unstable-release-url]
[![Downloads][downloads-shield]][downloads-url]
[![Tests][tests-shield]][tests-url]
[![Issues][issues-shield]][issues-url]
[![Stargazers][stars-shield]][stars-url]
[![License][license-shield]][license-url]

<br />
<div align="center">
  <a href="https://github.com/ColDog-Studios/ColDog-Locker">
    <img src="resources/cdlIcon.ico" alt="Logo">
  </a>

<h1 align="center">ColDog Locker</h1>

  <p align="center">
    ColDog Locker is a desktop app for securely locking, unlocking, and managing encrypted file lockers.
    <br />
    <a href="https://github.com/ColDog-Studios/ColDog-Locker"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/ColDog-Studios/ColDog-Locker/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/ColDog-Studios/ColDog-Locker/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#building-from-source">Building from Source</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

## About The Project

ColDog Locker is a desktop app for securely locking, unlocking, and managing encrypted file lockers.
It was created by Collin 'ColDog' Laney on 11/17/21 for a security project in Cybersecurity class.

> [!NOTE]
> ColDog Locker is still in development and does not currently have an official supported release

> [!WARNING]
> macOS `.pkg` builds are experimental, unsigned, unnotarized, and untested. They are provided for local validation only and should not be treated as official macOS support.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

- [![.Net][.Net-shield]][.Net-url]
- [![C#][C#-shield]][C#-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

There are currently no official supported release binaries available yet.
You can build from source following the instructions below. Installer/package build notes are in [Local Packaging](docs/packaging.md).

### Prerequisites

- [![.Net][.Net-shield]][.Net-url] .Net 10 SDK

```bash
dotnet --version
```

### Building from Source

1. Clone the repository

```bash
git clone https://github.com/ColDog-Studios/ColDog-Locker.git
```

2. Navigate to the project directory

```bash
cd ColDog-Locker
```

3. Restore dependencies

```bash
dotnet restore
```

4. Build the project

```bash
dotnet build
```

5. Run the project

```bash
dotnet run --project ColDogLocker.Cli
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

ColDog Locker is a desktop app for securely locking, unlocking, and managing encrypted file lockers.

> [!NOTE]
> `dotnet run --project ColDogLocker.Cli` and `cdlocker` can be used interchangeably.
> On Windows, the compiled executable is `cdlocker.exe`; on Linux and macOS it is `cdlocker`.

### Interactive Modes

- **GUI (Graphical User Interface)**: Run `cdlocker gui` for a graphical interface (in development)
- **TUI (Terminal User Interface)**: Run `cdlocker tui` for an interactive terminal menu

### Command-Line Interface

For scripting, automation, and quick operations, use the CLI commands:

#### Locker Commands

```bash
# Create a new locker
cdlocker new <name> [--path <path>] [--password <pass>]

# Lock a locker (encrypt and hide)
cdlocker lock <name> [--password <pass>]

# Unlock a locker (decrypt and unhide)
cdlocker unlock <name> [--password <pass>]

# List all lockers
cdlocker list [--locked | --unlocked]

# Show locker status
cdlocker status <name>

# Remove a locker
cdlocker remove <name> [--force] [--delete]
```

#### Locker Management

```bash
# Change locker password
cdlocker change-password <name>

# Verify locker integrity
cdlocker verify <name>
```

#### Settings & Database

```bash
# View or modify settings
cdlocker settings [set <key> <value>]

# Optimize database
cdlocker db-vacuum

# Show database information
cdlocker db-info
```

#### Help & Version

```bash
# Display help
cdlocker help [command]

# Show version
cdlocker --version
```

### Quick Examples

```bash
# Create a locker with automatic password prompt
cdlocker new MySecrets

# Create a locker at specific path
cdlocker new Docs --path "C:\Sensitive\Documents"

# Lock a locker
cdlocker lock MySecrets

# List only locked lockers
cdlocker list --locked

# Remove locker and delete its contents
cdlocker remove OldLocker --force --delete

# Check locker integrity
cdlocker verify MySecrets
```

> [!TIP]
> For detailed command documentation, use `cdlocker help <command>` or check the `/docs` folder.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Roadmap

See the [open issues](https://github.com/ColDog-Studios/ColDog-Locker/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

ColDog Locker is proprietary software and is not currently accepting public contributions. However, feedback and bug reports are always welcome!

If you encounter a bug or have a suggestion for improvement:

1. Open an issue with the appropriate tag ("bug" or "enhancement")
2. Provide detailed information about the issue or suggestion
3. The ColDog Studios team will review and respond

For business inquiries or collaboration opportunities, please contact us directly.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

ColDog Locker is free software licensed under the GNU General Public License v3.0. Copyright © 2026 ColDog Studios.

See [LICENSE](LICENSE) for the full terms and conditions of the GNU GPLv3.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->

## Contact

ColDog Studios - [@ColDogStudios](https://twitter.com/ColDogStudios) - contact@coldogstudios.com

[![@ColDog5044][twitter-shield]][twitter-cds-url]
[![Collin-Laney][linkedin-shield]][linkedin-cds-url]

Collin Laney (ColDog5044) - [@ColDog5044](https://twitter.com/ColDog5044) - collin.laney@coldogstudios.com

[![@ColDog5044][twitter-shield]][twitter-coldog-url]
[![Collin-Laney][linkedin-shield]][linkedin-coldog-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Third-Party Libraries

- [Avalonia UI](https://avaloniaui.net/)
- [BCrypt.Net-Next](https://github.com/BcryptNet/bcrypt.net)
- [CommunityToolkit.Mvvm](https://www.nuget.org/packages/CommunityToolkit.Mvvm)
- [Microsoft.Data.Sqlite](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/)
- [Microsoft.Extensions.DependencyInjection](https://www.nuget.org/packages/microsoft.extensions.dependencyinjection)
- [Newtonsoft.Json](https://www.newtonsoft.com/json)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->

[stable-release-shield]: https://img.shields.io/github/v/release/ColDog-Studios/ColDog-Locker?style=for-the-badge&label=Stable%20Release
[stable-release-url]: https://github.com/ColDog-Studios/ColDog-Locker/releases
[unstable-release-shield]: https://img.shields.io/github/v/release/ColDog-Studios/ColDog-Locker?include_prereleases&style=for-the-badge&label=Latest%20Release
[unstable-release-url]: https://github.com/ColDog-Studios/ColDog-Locker/releases
[downloads-shield]: https://img.shields.io/github/downloads/ColDog-Studios/ColDog-Locker/total.svg?style=for-the-badge
[downloads-url]: https://github.com/ColDog-Studios/ColDog-Locker/releases
[tests-shield]: https://img.shields.io/github/actions/workflow/status/ColDog-Studios/ColDog-Locker/test.yml?style=for-the-badge&label=Tests
[tests-url]: https://github.com/ColDog-Studios/ColDog-Locker/actions/workflows/test.yml
[issues-shield]: https://img.shields.io/github/issues/ColDog-Studios/ColDog-Locker.svg?style=for-the-badge
[issues-url]: https://github.com/ColDog-Studios/ColDog-Locker/issues
[stars-shield]: https://img.shields.io/github/stars/ColDog-Studios/ColDog-Locker.svg?style=for-the-badge
[stars-url]: https://github.com/ColDog-Studios/ColDog-Locker/stargazers
[license-shield]: https://img.shields.io/github/license/ColDog-Studios/ColDog-Locker?style=for-the-badge
[license-url]: https://github.com/ColDog-Studios/ColDog-Locker/blob/main/LICENSE
[github-shield]: https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white
[github-url]: https://github.com/ColDog-Studios
[twitter-shield]: https://img.shields.io/badge/Twitter-%231DA1F2.svg?style=for-the-badge&logo=Twitter&logoColor=white
[linkedin-shield]: https://img.shields.io/badge/linkedin-%230077B5.svg?style=for-the-badge&logo=linkedin&logoColor=white
[twitter-cds-url]: https://twitter.com/ColDogStudios
[linkedin-cds-url]: https://www.linkedin.com/company/coldog-studios
[twitter-coldog-url]: https://twitter.com/ColDog5044
[linkedin-coldog-url]: https://www.linkedin.com/in/collin-laney/
[PowerShell-shield]: https://img.shields.io/badge/PowerShell-%235391FE.svg?style=for-the-badge&logo=powershell&logoColor=white
[PowerShell-url]: https://docs.microsoft.com/en-us/powershell/
[C#-shield]: https://img.shields.io/badge/c%23-%23239120.svg?style=for-the-badge&logo=c-sharp&logoColor=white
[C#-url]: https://docs.microsoft.com/en-us/dotnet/csharp/
[.Net-shield]: https://img.shields.io/badge/.NET-5C2D91?style=for-the-badge&logo=.net&logoColor=white
[.Net-url]: https://dotnet.microsoft.com/

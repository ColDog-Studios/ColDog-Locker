<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->

[![Release][release-shield]][release-url]
[![Downloads][downloads-shield]][downloads-url]
[![Issues][issues-shield]][issues-url]
[![Stargazers][stars-shield]][stars-url]
[![LinkedIn][linkedin-shield]][linkedin-cds-url]

<br />
<div align="center">
  <a href="https://github.com/ColDog-Studios/ColDog-Locker">
    <img src="resources/cdlIcon.ico" alt="Logo">
  </a>

<h1 align="center">ColDog Locker</h1>

  <p align="center">
    A simple file locker that allows you to encrypt and decrypt the contents of a 'managed' directory with a password.
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

ColDog Locker is a simple file locker that allows you to encrypt and decrypt the contents of a 'managed' directory with a password. It was created by Collin 'ColDog' Laney on 11/17/21 for a security project in Cybersecurity class.

> [!NOTE]
> ColDog Locker is still in development and does not currently have an official supported release

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

- [![.Net][.Net-shield]][.Net-url]
- [![C#][C#-shield]][C#-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

The source code is publicly available for viewing and personal use. There are currently no official release binaries available yet. You can build from source following the instructions below.

> [!IMPORTANT]
> While the source code is public, this is proprietary software. Please review the [LICENSE](LICENSE) for usage restrictions before building or using.

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

ColDog Locker allows you to manage directories by encrypting and decrypting their contents with a password.

### Interactive Modes
- **GUI (Graphical User Interface)**: Run `dotnet run --project ColDogLocker.Cli gui` for a graphical interface (in development)
- **TUI (Terminal User Interface)**: Run `dotnet run --project ColDogLocker.Cli terminal` for an interactive terminal menu

### Command-Line Interface

For scripting, automation, and quick operations, use the CLI commands:

#### Locker Commands
```bash
# Create a new locker
dotnet run --project ColDogLocker.Cli new <name> [--path <path>] [--password <pass>]

# Lock a locker (encrypt and hide)
dotnet run --project ColDogLocker.Cli lock <name> [--password <pass>]

# Unlock a locker (decrypt and unhide)
dotnet run --project ColDogLocker.Cli unlock <name> [--password <pass>]

# List all lockers
dotnet run --project ColDogLocker.Cli list [--locked | --unlocked]

# Show locker status
dotnet run --project ColDogLocker.Cli status <name>

# Remove a locker
dotnet run --project ColDogLocker.Cli remove <name> [--force] [--delete]
```

#### Locker Management
```bash
# Change locker password
dotnet run --project ColDogLocker.Cli change-password <name>

# Verify locker integrity
dotnet run --project ColDogLocker.Cli verify <name>
```

#### Settings & Database
```bash
# View or modify settings
dotnet run --project ColDogLocker.Cli settings [set <key> <value>]

# Optimize database
dotnet run --project ColDogLocker.Cli db-vacuum

# Show database information
dotnet run --project ColDogLocker.Cli db-info
```

#### Help & Version
```bash
# Display help
dotnet run --project ColDogLocker.Cli help [command]

# Show version
dotnet run --project ColDogLocker.Cli --version
```

### Quick Examples

```bash
# Create a locker with automatic password prompt
dotnet run --project ColDogLocker.Cli new MySecrets

# Create a locker at specific path
dotnet run --project ColDogLocker.Cli new Docs --path "C:\Sensitive\Documents"

# Lock a locker
dotnet run --project ColDogLocker.Cli lock MySecrets

# List only locked lockers
dotnet run --project ColDogLocker.Cli list --locked

# Remove locker and delete its contents
dotnet run --project ColDogLocker.Cli remove OldLocker --force --delete

# Check locker integrity
dotnet run --project ColDogLocker.Cli verify MySecrets
```

> [!TIP]
> For detailed command documentation, use `dotnet run --project ColDogLocker.Cli help <command>` or check the `/docs` folder (coming soon).

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

ColDog Locker is proprietary software. Copyright © 2025 Collin Laney. All Rights Reserved.

This software is licensed for personal and internal business use only. Public distribution, commercial distribution, and SaaS hosting are not permitted. See [LICENSE](LICENSE) for complete terms and conditions.

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

## Acknowledgments

- [BCrypt.Net-Next](https://github.com/BcryptNet/bcrypt.net)
- [Microsoft .NET](https://dotnet.microsoft.com/)
- [Microsoft.Data.Sqlite](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/)
- [Newtonsoft.Json](https://www.newtonsoft.com/json)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->

[release-shield]: https://img.shields.io/github/v/release/ColDog-Studios/ColDog-Locker?style=for-the-badge
[release-url]: https://github.com/ColDog-Studios/ColDog-Locker
[downloads-shield]: https://img.shields.io/github/downloads/ColDog-Studios/ColDog-Locker/total.svg?style=for-the-badge
[downloads-url]: https://github.com/ColDog-Studios/ColDog-Locker
[issues-shield]: https://img.shields.io/github/issues/ColDog-Studios/ColDog-Locker.svg?style=for-the-badge
[issues-url]: https://github.com/ColDog-Studios/ColDog-Locker/issues
[stars-shield]: https://img.shields.io/github/stars/ColDog-Studios/ColDog-Locker.svg?style=for-the-badge
[stars-url]: https://github.com/ColDogStudios/ColDog-Locker/stargazers
[github-shield]: https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white
[github-url]: https://github.com/ColDogStudios
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

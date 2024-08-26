<a name="readme-top"></a>

<!-- PROJECT SHIELDS -->

[![Release][release-shield]][release-url]
[![Downloads][downloads-shield]][downloads-url]
[![Issues][issues-shield]][issues-url]
[![Stargazers][stars-shield]][stars-url]
[![LinkedIn][linkedin-shield]][linkedin-cds-url]

<!-- PROJECT LOGO -->
<br>
<div align="center">
    <a href="https://github.com/ColDogStudios/ColDog-Locker">
      <img src="images/cdlIcon.png" alt="Logo" width="500">
    </a>
    
  <p align="center">
    <br>
    <em>Copyright © ColDog Studios. All rights reserved.</em>
    <br>
    <br>
    <a href="https://github.com/ColDogStudios/ColDog-Locker/tree/CDS/docs"><strong>Explore the docs »</strong></a>
    <br>
    <br>
    <a href="https://github.com/ColDogStudios/ColDog-Locker/issues/new?assignees=&labels=type%3A+question&template=ask_a_question.yml&title=%5BQuestion%5D%3A+">Ask a Question</a>
    ·
    <a href="https://github.com/ColDogStudios/ColDog-Locker/issues/new?assignees=&labels=type%3A+bug&template=bug_report.yml&title=%5BBug%5D%3A+">Report Bug</a>
    ·
    <a href="https://github.com/ColDogStudios/ColDog-Locker/issues/new?assignees=&labels=type%3A+feature&template=feature_request.yml&title=%5BFeature+Request%5D%3A+">Request Feature</a>
    ·
    <a href="https://github.com/ColDogStudios/ColDog-Locker/issues/new?assignees=&labels=type%3A+security&template=security.yml&title=%5BSecurity%5D%3A+">Security Issue</a>
    ·
    <a href="https://github.com/ColDogStudios/ColDog-Locker/security/advisories/new">Report a Vulnerability</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
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
        <li><a href="#important-notice-and-disclaimer">Important Notice and Disclaimer</a></li>
        <li><a href="#compatibility">Compatibility</a></li>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#features">Features</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

> [!NOTE]
> ColDog Locker is still in development and does not currently have an official supported release

### Built With

-   [![PowerShell][PowerShell-shield]][PowerShell-url]
-   [![C#][C#-shield]][C#-url]
-   [![.Net][.Net-shield]][.Net-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->

## Getting Started

> [!NOTE]
>
> ### Important Notice
>
> ColDog Studios is committed to keeping your files secure and will fix any security vulnerability immediately. ColDog Studios does not receive any information from you such as passwords. All of the configuration is stored on your local machine.
>
> -   By using this software, you agree that ColDog Studios is not held responsible for any data lost, stolen, or accessed.
> -   The software is provided as is and without warranty as to its features, functionality, or performance.
> -   Any unauthorized copying, distributing, or selling of this software is prohibited.

> [!WARNING]
> Your anti-virus will potentially flag ColDog Locker as a virus. This is a false positive and you will need to make an exclusion.

> [!IMPORTANT]
>
> ### Disclaimer of Warranties
>
> THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT. LICENSOR DOES NOT WARRANT THAT THE SOFTWARE WILL MEET LICENSEE'S REQUIREMENTS OR THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE.

### Compatibility

|                           |    Requirements    |       Recommendations       |
| ------------------------- | :----------------: | :-------------------------: |
| Operating System (64 bit) |     Windows 10     |     Windows 10 or later     |
| PowerShell Version        |   PowerShell 5.1   |   PowerShell 5.1 or later   |
| .Net Framework            | .Net Framework 4.0 | .Net Framework 4.5 or later |

### Prerequisites

What you need before you can install and run ColDog Locker

-   Windows 10 or 11 (64 bit)
-   PowerShell 5.1 or later (Preinstalled on Windows)
-   .Net 4.5 or later (Preinstalled on Windows)

### Installation

1. Run PowerShell and input the following commands:

```PowerShell
# Allows signed PowerShell scripts to be executed only on the current signed-in user
PS > Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Allow the execution of ColDog Locker because it is not signed
PS > Unblock-File .\ColDog-Locker.ps1
```

or

```PowerShell
# Allows signed PowerShell scripts to be executed by any signed-in user
PS > Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# Allow the execution of ColDog Locker because it is not signed
PS > Unblock-File .\ColDog-Locker.ps1
```

2. Run `ColDog Locker Setup` and install the software

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
<!--## Usage


Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

*For more examples, please refer to the [Documentation](https://example.com)*

<p align="right">(<a href="#readme-top">back to top</a>)</p>
-->

<!-- FEATURES -->

## Features

-   Folder encryption (AES-256)
-   Password protected folders
-   Multiple folders
-   Failed attempts lockout
-   GitHub integrated updates
-   Optional automatically check for updates

See the [open issues](https://github.com/ColDogStudios/ColDog-Locker/issues) for a full list of proposed features (and known issues).
See the ColDog Locker [Project Board](https://github.com/orgs/ColDogStudios/projects/2) for a full list of features being worked on

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

<!-- CONTRIBUTORS -->

## Contributors

<a href="https://github.com/ColDog-Studios/ColDog-Locker/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ColDog-Studios/ColDog-Locker" />
</a>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->

## Acknowledgments

-   [Wayne Boggs]() - Cybersecurity Instructor
-   []()
-   []()

<p align="right">(<a href="#readme-top">back to top</a>)</p>

      _____      _ _____                   _                _
     / ____|    | |  __ \                 | |              | |
    | |     ___ | | |  | | ___   __ _     | |     ___   ___| | _____ _ __
    | |    / _ \| | |  | |/ _ \ / _` |    | |    / _ \ / __| |/ / _ \ '__|
    | |___| (_) | | |__| | (_) | (_| |    | |___| (_) | (__|   <  __/ |
     \_____\___/|_|_____/ \___/ \__, |    |______\___/ \___|_|\_\___|_|
                                 __/ |
                                |___/

<!-- MARKDOWN LINKS & IMAGES -->

[release-shield]: https://img.shields.io/github/v/release/ColDogStudios/ColDog-Locker?style=for-the-badge
[release-url]: https://github.com/ColDogStudios/ColDog-Locker
[downloads-shield]: https://img.shields.io/github/downloads/ColDogStudios/ColDog-Locker/total.svg?style=for-the-badge
[downloads-url]: https://github.com/ColDogStudios/ColDog-Locker
[issues-shield]: https://img.shields.io/github/issues/ColDogStudios/ColDog-Locker.svg?style=for-the-badge
[issues-url]: https://github.com/ColDogStudios/ColDog-Locker/issues
[stars-shield]: https://img.shields.io/github/stars/ColDogStudios/ColDog-Locker.svg?style=for-the-badge
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

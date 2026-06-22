/*
 **  Copyright (C) 2026 ColDog Studios
 **
 **  This program is free software: you can redistribute it and/or modify
 **  it under the terms of the GNU General Public License as published by
 **  the Free Software Foundation, either version 3 of the License, or
 **  (at your option) any later version.
 **
 **  This program is distributed in the hope that it will be useful,
 **  but WITHOUT ANY WARRANTY; without even the implied warranty of
 **  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 **  GNU General Public License for more details.
 **
 **  You should have received a copy of the GNU General Public License
 **  long with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

using System.Diagnostics;
using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Services.Tests.Updates
{
    public class UpdateInstallerTests
    {
        [Fact]
        public void CreateInstallCommand_WindowsMsi_UsesElevatedMsiexec()
        {
            // Arrange
            var installer = CreateInstaller([]);
            var platform = new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = Architecture.X64 };

            // Act
            var command = installer.CreateInstallCommand(@"C:\Downloads\ColDogLocker.msi", platform);

            // Assert
            Assert.Equal("msiexec.exe", command.FileName);
            Assert.Equal(["/i", @"C:\Downloads\ColDogLocker.msi"], command.Arguments);
            Assert.True(command.UseShellExecute);
            Assert.Equal("runas", command.Verb);
            Assert.False(command.WaitForExit);
        }

        [Fact]
        public void CreateInstallCommand_MacOsPkg_OpensInstallerPackage()
        {
            // Arrange
            var installer = CreateInstaller([]);
            var platform = new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.MacOS, Architecture = Architecture.Arm64 };

            // Act
            var command = installer.CreateInstallCommand("/Users/test/Downloads/ColDogLocker.pkg", platform);

            // Assert
            Assert.Equal("/usr/bin/open", command.FileName);
            Assert.Equal(["/Users/test/Downloads/ColDogLocker.pkg"], command.Arguments);
            Assert.False(command.UseShellExecute);
            Assert.False(command.WaitForExit);
        }

        [Fact]
        public void CreateInstallCommand_MacOsNonPkg_ThrowsInstallFailed()
        {
            // Arrange
            var installer = CreateInstaller([]);
            var platform = new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.MacOS, Architecture = Architecture.X64 };

            // Act
            var exception = Assert.Throws<UpdateException>(() =>
                installer.CreateInstallCommand("/Users/test/Downloads/ColDogLocker.zip", platform));

            // Assert
            Assert.Equal(UpdateFailureKind.InstallFailed, exception.FailureKind);
            Assert.Contains("PKG", exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void CreateInstallCommand_LinuxDebWithGraphicalSession_UsesPkexecRemoveThenAptGetInstall()
        {
            // Arrange
            var installer = CreateInstaller(["apt-get", "pkexec", "sudo"], isAdministrator: false, display: ":0");
            var platform = new UpdatePlatform
            {
                OperatingSystem = UpdateOperatingSystem.Linux,
                LinuxPackageFormat = LinuxPackageFormat.Deb,
                Architecture = Architecture.X64
            };

            // Act
            var command = installer.CreateInstallCommand("/home/user/Downloads/ColDogLocker.deb", platform);

            // Assert
            Assert.Equal("pkexec", command.FileName);
            Assert.Equal(
                [
                    "sh",
                    "-c",
                    "if dpkg -s coldog-locker >/dev/null 2>&1; then apt-get remove -y coldog-locker; fi && apt-get install -y \"$1\"",
                    "cdlocker-updater",
                    "/home/user/Downloads/ColDogLocker.deb"
                ],
                command.Arguments);
            Assert.False(command.UseShellExecute);
            Assert.True(command.WaitForExit);
        }

        [Fact]
        public void CreateInstallCommand_LinuxDebWithoutGraphicalSession_UsesSudo()
        {
            // Arrange
            var installer = CreateInstaller(["apt", "sudo"], isAdministrator: false);
            var platform = new UpdatePlatform
            {
                OperatingSystem = UpdateOperatingSystem.Linux,
                LinuxPackageFormat = LinuxPackageFormat.Deb,
                Architecture = Architecture.X64
            };

            // Act
            var command = installer.CreateInstallCommand("/tmp/ColDogLocker.deb", platform);

            // Assert
            Assert.Equal("sudo", command.FileName);
            Assert.Equal(
                [
                    "sh",
                    "-c",
                    "if dpkg -s coldog-locker >/dev/null 2>&1; then apt remove -y coldog-locker; fi && apt install -y \"$1\"",
                    "cdlocker-updater",
                    "/tmp/ColDogLocker.deb"
                ],
                command.Arguments);
            Assert.True(command.WaitForExit);
        }

        [Fact]
        public void CreateInstallCommand_LinuxRpmAsRoot_RemovesExistingPackageBeforeDnfInstall()
        {
            // Arrange
            var installer = CreateInstaller(["dnf", "sudo"], isAdministrator: true);
            var platform = new UpdatePlatform
            {
                OperatingSystem = UpdateOperatingSystem.Linux,
                LinuxPackageFormat = LinuxPackageFormat.Rpm,
                Architecture = Architecture.X64
            };

            // Act
            var command = installer.CreateInstallCommand("/tmp/ColDogLocker.rpm", platform);

            // Assert
            Assert.Equal("sh", command.FileName);
            Assert.Equal(
                [
                    "-c",
                    "if rpm -q coldog-locker >/dev/null 2>&1; then dnf remove -y coldog-locker; fi && dnf install -y \"$1\"",
                    "cdlocker-updater",
                    "/tmp/ColDogLocker.rpm"
                ],
                command.Arguments);
            Assert.True(command.WaitForExit);
        }

        [Fact]
        public void CreateInstallCommand_LinuxRpmWithGraphicalSession_UsesPkexecRemoveThenInstall()
        {
            // Arrange
            var installer = CreateInstaller(["dnf", "pkexec"], isAdministrator: false, display: ":0");
            var platform = new UpdatePlatform
            {
                OperatingSystem = UpdateOperatingSystem.Linux,
                LinuxPackageFormat = LinuxPackageFormat.Rpm,
                Architecture = Architecture.X64
            };

            // Act
            var command = installer.CreateInstallCommand("/tmp/ColDogLocker.rpm", platform);

            // Assert
            Assert.Equal("pkexec", command.FileName);
            Assert.Equal(
                [
                    "sh",
                    "-c",
                    "if rpm -q coldog-locker >/dev/null 2>&1; then dnf remove -y coldog-locker; fi && dnf install -y \"$1\"",
                    "cdlocker-updater",
                    "/tmp/ColDogLocker.rpm"
                ],
                command.Arguments);
            Assert.True(command.WaitForExit);
        }

        [Fact]
        public void CreateInstallCommand_LinuxUnknownFormat_UsesFileExtension()
        {
            // Arrange
            var installer = CreateInstaller(["dpkg", "sudo"], isAdministrator: false);
            var platform = new UpdatePlatform
            {
                OperatingSystem = UpdateOperatingSystem.Linux,
                LinuxPackageFormat = LinuxPackageFormat.Unknown,
                Architecture = Architecture.X64
            };

            // Act
            var command = installer.CreateInstallCommand("/tmp/ColDogLocker.deb", platform);

            // Assert
            Assert.Equal("sudo", command.FileName);
            Assert.Equal(
                [
                    "sh",
                    "-c",
                    "if dpkg -s coldog-locker >/dev/null 2>&1; then dpkg -r coldog-locker; fi && dpkg -i \"$1\"",
                    "cdlocker-updater",
                    "/tmp/ColDogLocker.deb"
                ],
                command.Arguments);
        }

        [Fact]
        public void CreateInstallCommand_LinuxWithoutPrivilegeTool_ThrowsInstallFailed()
        {
            // Arrange
            var installer = CreateInstaller(["apt-get"], isAdministrator: false);
            var platform = new UpdatePlatform
            {
                OperatingSystem = UpdateOperatingSystem.Linux,
                LinuxPackageFormat = LinuxPackageFormat.Deb,
                Architecture = Architecture.X64
            };

            // Act
            var exception = Assert.Throws<UpdateException>(() =>
                installer.CreateInstallCommand("/tmp/ColDogLocker.deb", platform));

            // Assert
            Assert.Equal(UpdateFailureKind.InstallFailed, exception.FailureKind);
            Assert.Contains("administrator", exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        private static UpdateInstaller CreateInstaller(
            IReadOnlyCollection<string> availableCommands,
            bool isAdministrator = false,
            string? display = null)
        {
            return new UpdateInstaller(
                availableCommands.Contains,
                () => isAdministrator,
                name => name switch
                {
                    "DISPLAY" => display,
                    "WAYLAND_DISPLAY" => null,
                    _ => null
                },
                (_, _, _) => Task.FromResult(new UpdateProcessResult(0)));
        }
    }
}

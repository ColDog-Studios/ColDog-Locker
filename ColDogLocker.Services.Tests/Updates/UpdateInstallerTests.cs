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
using System.Security.Cryptography;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Services.Tests.Updates
{
    public class UpdateInstallerTests
    {
        private const string Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        [Fact]
        public void CreateInstallCommand_WindowsMsi_UsesElevatedMsiexec()
        {
            // Arrange
            var installer = CreateInstaller([]);
            var platform = new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = Architecture.X64 };

            // Act
            var command = installer.CreateInstallCommand(@"C:\Downloads\ColDogLocker.msi", platform, Digest);

            // Assert
            Assert.Equal("powershell.exe", command.FileName);
            Assert.Contains("-EncodedCommand", command.Arguments);
            Assert.True(command.UseShellExecute);
            Assert.Equal("runas", command.Verb);
            Assert.True(command.WaitForExit);
            var script = DecodePowerShell(command);
            Assert.Contains(@"C:\Downloads\ColDogLocker.msi", script);
            Assert.Contains("Get-FileHash", script);
            Assert.Contains("msiexec.exe", script);
            Assert.Contains(Digest, script);
            Assert.Contains("FileAttributes]::ReparsePoint", script);
            Assert.Contains("AreAccessRulesProtected", script);
            Assert.Contains("GetOwner([System.Security.Principal.SecurityIdentifier])", script);
            Assert.True(script.IndexOf("File]::Copy", StringComparison.Ordinal) <
                        script.IndexOf("Get-FileHash", StringComparison.Ordinal));
            Assert.True(script.IndexOf("Get-FileHash", StringComparison.Ordinal) <
                        script.IndexOf("Start-Process", StringComparison.Ordinal));
        }

        [Fact]
        public void CreateInstallCommand_MacOsPkg_OpensInstallerPackage()
        {
            // Arrange
            var installer = CreateInstaller([]);
            var platform = new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.MacOS, Architecture = Architecture.Arm64 };

            // Act
            var command = installer.CreateInstallCommand("/Users/test/Downloads/ColDogLocker.pkg", platform, Digest);

            // Assert
            Assert.Equal("/usr/bin/osascript", command.FileName);
            Assert.Equal("-e", command.Arguments[0]);
            Assert.Contains("with administrator privileges", command.Arguments[1]);
            Assert.Contains(Digest, command.Arguments[1]);
            Assert.Contains(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("/Users/test/Downloads/ColDogLocker.pkg")), command.Arguments[1]);
            var encodedScript = command.Arguments[1].Split("printf %s ", 2, StringSplitOptions.None)[1]
                .Split(" |", 2, StringSplitOptions.None)[0];
            var script = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encodedScript));
            Assert.Contains("shasum -a 256", script);
            Assert.Contains("/usr/sbin/installer", script);
            Assert.DoesNotContain("/bin/cp --", script);
            Assert.True(script.IndexOf("/bin/cp", StringComparison.Ordinal) <
                        script.IndexOf("shasum", StringComparison.Ordinal));
            Assert.True(script.IndexOf("shasum", StringComparison.Ordinal) <
                        script.IndexOf("/usr/sbin/installer", StringComparison.Ordinal));
            Assert.False(command.UseShellExecute);
            Assert.True(command.WaitForExit);
        }

        [Fact]
        public void CreateInstallCommand_MacOsNonPkg_ThrowsInstallFailed()
        {
            // Arrange
            var installer = CreateInstaller([]);
            var platform = new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.MacOS, Architecture = Architecture.X64 };

            // Act
            var exception = Assert.Throws<UpdateException>(() =>
                installer.CreateInstallCommand("/Users/test/Downloads/ColDogLocker.zip", platform, Digest));

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
            var command = installer.CreateInstallCommand("/home/user/Downloads/ColDogLocker.deb", platform, Digest);

            // Assert
            Assert.Equal("pkexec", command.FileName);
            Assert.Equal("sh", command.Arguments[0]);
            Assert.Equal("-c", command.Arguments[1]);
            Assert.Contains("sha256sum", command.Arguments[2]);
            Assert.Contains("apt-get install -y \"$package\"", command.Arguments[2]);
            Assert.Equal("/home/user/Downloads/ColDogLocker.deb", command.Arguments[^2]);
            Assert.Equal(Digest, command.Arguments[^1]);
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
            var command = installer.CreateInstallCommand("/tmp/ColDogLocker.deb", platform, Digest);

            // Assert
            Assert.Equal("sudo", command.FileName);
            Assert.Equal("sh", command.Arguments[0]);
            Assert.Contains("sha256sum", command.Arguments[2]);
            Assert.Contains("apt install -y \"$package\"", command.Arguments[2]);
            Assert.Equal("/tmp/ColDogLocker.deb", command.Arguments[^2]);
            Assert.Equal(Digest, command.Arguments[^1]);
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
            var command = installer.CreateInstallCommand("/tmp/ColDogLocker.rpm", platform, Digest);

            // Assert
            Assert.Equal("sh", command.FileName);
            Assert.Equal("-c", command.Arguments[0]);
            Assert.Contains("sha256sum", command.Arguments[1]);
            Assert.Contains("dnf install -y \"$package\"", command.Arguments[1]);
            Assert.Equal("/tmp/ColDogLocker.rpm", command.Arguments[^2]);
            Assert.Equal(Digest, command.Arguments[^1]);
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
            var command = installer.CreateInstallCommand("/tmp/ColDogLocker.rpm", platform, Digest);

            // Assert
            Assert.Equal("pkexec", command.FileName);
            Assert.Equal("sh", command.Arguments[0]);
            Assert.Contains("sha256sum", command.Arguments[2]);
            Assert.Contains("dnf install -y \"$package\"", command.Arguments[2]);
            Assert.Equal("/tmp/ColDogLocker.rpm", command.Arguments[^2]);
            Assert.Equal(Digest, command.Arguments[^1]);
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
            var command = installer.CreateInstallCommand("/tmp/ColDogLocker.deb", platform, Digest);

            // Assert
            Assert.Equal("sudo", command.FileName);
            Assert.Equal("sh", command.Arguments[0]);
            Assert.Contains("sha256sum", command.Arguments[2]);
            Assert.Contains("dpkg -i \"$package\"", command.Arguments[2]);
            Assert.Equal("/tmp/ColDogLocker.deb", command.Arguments[^2]);
            Assert.Equal(Digest, command.Arguments[^1]);
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
                installer.CreateInstallCommand("/tmp/ColDogLocker.deb", platform, Digest));

            // Assert
            Assert.Equal(UpdateFailureKind.InstallFailed, exception.FailureKind);
            Assert.Contains("administrator", exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [LinuxFact]
        public void VerifiedLinuxStaging_RejectsWrongDigestBeforeConsumerAndAcceptsMatchingCopy()
        {
            var directory = Directory.CreateTempSubdirectory("cdl-update-stage-").FullName;
            try
            {
                var source = Path.Join(directory, "source.deb");
                var marker = Path.Join(directory, "consumed.txt");
                File.WriteAllText(source, "verified installer bytes");
                var script = UpdateInstaller.CreateVerifiedLinuxStagingScript(
                    "deb",
                    "/usr/bin/printf consumed > \"$3\"");

                var refused = RunShell(script, source, Digest, marker);
                Assert.Equal(65, refused);
                Assert.False(File.Exists(marker));

                var matching = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(source)));
                Assert.Equal(0, RunShell(script, source, matching, marker));
                Assert.Equal("consumed", File.ReadAllText(marker));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
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

        private static string DecodePowerShell(UpdateInstallerCommand command)
        {
            var encodedIndex = command.Arguments.ToList().IndexOf("-EncodedCommand");
            Assert.True(encodedIndex >= 0);
            return System.Text.Encoding.Unicode.GetString(Convert.FromBase64String(command.Arguments[encodedIndex + 1]));
        }

        private static int RunShell(string script, string source, string digest, string marker)
        {
            var start = new ProcessStartInfo("/bin/sh") { UseShellExecute = false };
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add(script);
            start.ArgumentList.Add("cdlocker-updater-test");
            start.ArgumentList.Add(source);
            start.ArgumentList.Add(digest);
            start.ArgumentList.Add(marker);
            using var process = Process.Start(start)!;
            Assert.True(process.WaitForExit(5000));
            return process.ExitCode;
        }
    }

    public sealed class LinuxFactAttribute : FactAttribute
    {
        public LinuxFactAttribute()
        {
            if (!OperatingSystem.IsLinux())
            {
                Skip = "Linux privileged-staging script validation requires a Linux host.";
            }
        }
    }
}

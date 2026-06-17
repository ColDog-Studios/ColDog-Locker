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
using System.Security.Principal;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Services.Updates
{
    public sealed class UpdateInstallResult
    {
        public string FilePath { get; set; } = string.Empty;
        public string Command { get; set; } = string.Empty;
        public bool InstallerStarted { get; set; }
        public bool Completed { get; set; }
        public int? ExitCode { get; set; }
        public string UserMessage { get; set; } = string.Empty;
    }

    internal sealed class UpdateInstaller
    {
        private const string LinuxPackageId = "coldog-locker";

        private readonly Func<string, bool> _commandExists;
        private readonly Func<string, string?> _environmentVariableProvider;
        private readonly Func<bool> _isAdministrator;
        private readonly Func<ProcessStartInfo, bool, CancellationToken, Task<UpdateProcessResult>> _processRunner;

        public UpdateInstaller()
            : this(
                CommandExists,
                IsRunningAsAdministrator,
                Environment.GetEnvironmentVariable,
                RunProcessAsync)
        {
        }

        internal UpdateInstaller(
            Func<string, bool> commandExists,
            Func<bool> isAdministrator,
            Func<string, string?> environmentVariableProvider,
            Func<ProcessStartInfo, bool, CancellationToken, Task<UpdateProcessResult>> processRunner)
        {
            _commandExists = commandExists;
            _isAdministrator = isAdministrator;
            _environmentVariableProvider = environmentVariableProvider;
            _processRunner = processRunner;
        }

        public async Task<UpdateInstallResult> InstallAsync(
            string installerPath,
            UpdatePlatform platform,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(installerPath))
            {
                throw new UpdateException(UpdateFailureKind.InstallFailed, "The update installer path is empty.");
            }

            var fullPath = Path.GetFullPath(installerPath);
            if (!File.Exists(fullPath))
            {
                throw new UpdateException(UpdateFailureKind.InstallFailed, $"The update installer was not found: {fullPath}");
            }

            var command = CreateInstallCommand(fullPath, platform);
            Logger.Log(LogLevel.Info, $"Starting update installer: {command.DisplayCommand}");

            try
            {
                var processResult = await _processRunner(command.ToStartInfo(), command.WaitForExit, cancellationToken);
                if (command.WaitForExit && processResult.ExitCode != 0)
                {
                    Logger.Log(LogLevel.Error, $"Update installer failed with exit code {processResult.ExitCode}: {command.DisplayCommand}");
                    throw new UpdateException(UpdateFailureKind.InstallFailed,
                        $"The update installer exited with code {processResult.ExitCode}. The downloaded installer remains at {fullPath}.");
                }

                return new UpdateInstallResult
                {
                    FilePath = fullPath,
                    Command = command.DisplayCommand,
                    InstallerStarted = true,
                    Completed = command.WaitForExit,
                    ExitCode = processResult.ExitCode,
                    UserMessage = command.SuccessMessage
                };
            }
            catch (UpdateException)
            {
                throw;
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
            {
                Logger.Log(LogLevel.Error, $"Failed to start update installer: {command.DisplayCommand}", ex);
                throw new UpdateException(UpdateFailureKind.InstallFailed,
                    $"The update was downloaded, but the installer could not be started. The downloaded installer remains at {fullPath}.", ex);
            }
        }

        internal UpdateInstallerCommand CreateInstallCommand(string installerPath, UpdatePlatform platform)
        {
            return platform.OperatingSystem switch
            {
                UpdateOperatingSystem.Windows => CreateWindowsInstallCommand(installerPath),
                UpdateOperatingSystem.Linux => CreateLinuxInstallCommand(installerPath, platform),
                UpdateOperatingSystem.MacOS => throw new UpdateException(UpdateFailureKind.UnsupportedPlatform,
                    "Automatic macOS installation is not supported. Run the downloaded package manually."),
                _ => throw new UpdateException(UpdateFailureKind.UnsupportedPlatform,
                    "Automatic installation is not supported on this platform.")
            };
        }

        private static UpdateInstallerCommand CreateWindowsInstallCommand(string installerPath)
        {
            var extension = Path.GetExtension(installerPath).ToLowerInvariant();
            if (extension == ".msi")
            {
                return new UpdateInstallerCommand(
                    "msiexec.exe",
                    ["/i", installerPath],
                    useShellExecute: true,
                    verb: "runas",
                    waitForExit: false,
                    "Installer started. Follow the installer prompts, then restart ColDog Locker when it finishes.");
            }

            if (extension == ".exe")
            {
                return new UpdateInstallerCommand(
                    installerPath,
                    [],
                    useShellExecute: true,
                    verb: "runas",
                    waitForExit: false,
                    "Installer started. Follow the installer prompts, then restart ColDog Locker when it finishes.");
            }

            throw new UpdateException(UpdateFailureKind.InstallFailed,
                "The downloaded Windows update is not an MSI or EXE installer.");
        }

        private UpdateInstallerCommand CreateLinuxInstallCommand(string installerPath, UpdatePlatform platform)
        {
            var extension = Path.GetExtension(installerPath).ToLowerInvariant();
            var packageFormat = platform.LinuxPackageFormat;
            if (packageFormat == LinuxPackageFormat.Unknown)
            {
                packageFormat = extension switch
                {
                    ".deb" => LinuxPackageFormat.Deb,
                    ".rpm" => LinuxPackageFormat.Rpm,
                    _ => LinuxPackageFormat.Unknown
                };
            }

            return packageFormat switch
            {
                LinuxPackageFormat.Deb => CreateDebInstallCommand(installerPath),
                LinuxPackageFormat.Rpm => CreateRpmInstallCommand(installerPath),
                _ => throw new UpdateException(UpdateFailureKind.UnsupportedPlatform,
                    "Automatic Linux installation needs a .deb or .rpm package.")
            };
        }

        private UpdateInstallerCommand CreateDebInstallCommand(string installerPath)
        {
            var baseCommand = FirstExistingCommand("apt-get", "apt", "dpkg")
                              ?? throw new UpdateException(UpdateFailureKind.InstallFailed,
                                  "No supported Debian package installer was found. Install the downloaded .deb package manually.");

            var script = baseCommand switch
            {
                "apt-get" => CreateDebReplaceScript("apt-get remove -y", "apt-get install -y"),
                "apt" => CreateDebReplaceScript("apt remove -y", "apt install -y"),
                _ => CreateDebReplaceScript("dpkg -r", "dpkg -i")
            };

            return CreatePrivilegedLinuxCommand(
                "sh",
                ["-c", script, "cdlocker-updater", installerPath],
                "Update package installed. Restart ColDog Locker to use the new version.");
        }

        private static string CreateDebReplaceScript(string removeCommand, string installCommand)
        {
            return $"if dpkg -s {LinuxPackageId} >/dev/null 2>&1; then {removeCommand} {LinuxPackageId}; fi && {installCommand} \"$1\"";
        }

        private UpdateInstallerCommand CreateRpmInstallCommand(string installerPath)
        {
            var baseCommand = FirstExistingCommand("dnf", "yum", "zypper", "rpm")
                              ?? throw new UpdateException(UpdateFailureKind.InstallFailed,
                                  "No supported RPM package installer was found. Install the downloaded .rpm package manually.");

            var script = baseCommand switch
            {
                "dnf" => CreateRpmReplaceScript("dnf remove -y", "dnf install -y"),
                "yum" => CreateRpmReplaceScript("yum remove -y", "yum localinstall -y"),
                "zypper" => CreateRpmReplaceScript("zypper --non-interactive remove", "zypper --non-interactive install"),
                _ => CreateRpmReplaceScript("rpm -e", "rpm -i")
            };

            return CreatePrivilegedLinuxCommand(
                "sh",
                ["-c", script, "cdlocker-updater", installerPath],
                "Update package installed. Restart ColDog Locker to use the new version.");
        }

        private static string CreateRpmReplaceScript(string removeCommand, string installCommand)
        {
            return $"if rpm -q {LinuxPackageId} >/dev/null 2>&1; then {removeCommand} {LinuxPackageId}; fi && {installCommand} \"$1\"";
        }

        private UpdateInstallerCommand CreatePrivilegedLinuxCommand(
            string baseCommand,
            IReadOnlyList<string> baseArguments,
            string successMessage)
        {
            if (_isAdministrator())
            {
                return new UpdateInstallerCommand(
                    baseCommand,
                    baseArguments,
                    useShellExecute: false,
                    verb: null,
                    waitForExit: true,
                    successMessage);
            }

            if (HasGraphicalAuthSession() && _commandExists("pkexec"))
            {
                return new UpdateInstallerCommand(
                    "pkexec",
                    [baseCommand, .. baseArguments],
                    useShellExecute: false,
                    verb: null,
                    waitForExit: true,
                    successMessage);
            }

            if (_commandExists("sudo"))
            {
                return new UpdateInstallerCommand(
                    "sudo",
                    [baseCommand, .. baseArguments],
                    useShellExecute: false,
                    verb: null,
                    waitForExit: true,
                    successMessage);
            }

            if (_commandExists("pkexec"))
            {
                return new UpdateInstallerCommand(
                    "pkexec",
                    [baseCommand, .. baseArguments],
                    useShellExecute: false,
                    verb: null,
                    waitForExit: true,
                    successMessage);
            }

            throw new UpdateException(UpdateFailureKind.InstallFailed,
                "Installing this update requires administrator privileges. Install the downloaded package manually with your system package manager.");
        }

        private string? FirstExistingCommand(params string[] commands)
        {
            return commands.FirstOrDefault(_commandExists);
        }

        private bool HasGraphicalAuthSession()
        {
            return !string.IsNullOrWhiteSpace(_environmentVariableProvider("DISPLAY")) ||
                   !string.IsNullOrWhiteSpace(_environmentVariableProvider("WAYLAND_DISPLAY"));
        }

        private static bool CommandExists(string command)
        {
            var paths = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            return paths.Any(path => File.Exists(Path.Combine(path, command)));
        }

        private static bool IsRunningAsAdministrator()
        {
            if (OperatingSystem.IsWindows())
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }

            return Environment.UserName.Equals("root", StringComparison.OrdinalIgnoreCase);
        }

        private static async Task<UpdateProcessResult> RunProcessAsync(
            ProcessStartInfo startInfo,
            bool waitForExit,
            CancellationToken cancellationToken)
        {
            using var process = Process.Start(startInfo)
                                ?? throw new InvalidOperationException($"Failed to launch '{startInfo.FileName}'.");

            if (!waitForExit)
            {
                return new UpdateProcessResult(null);
            }

            await process.WaitForExitAsync(cancellationToken);
            return new UpdateProcessResult(process.ExitCode);
        }
    }

    internal sealed class UpdateInstallerCommand
    {
        public UpdateInstallerCommand(
            string fileName,
            IReadOnlyList<string> arguments,
            bool useShellExecute,
            string? verb,
            bool waitForExit,
            string successMessage)
        {
            FileName = fileName;
            Arguments = arguments;
            UseShellExecute = useShellExecute;
            Verb = verb;
            WaitForExit = waitForExit;
            SuccessMessage = successMessage;
            DisplayCommand = FormatCommand(fileName, arguments);
        }

        public string FileName { get; }
        public IReadOnlyList<string> Arguments { get; }
        public bool UseShellExecute { get; }
        public string? Verb { get; }
        public bool WaitForExit { get; }
        public string SuccessMessage { get; }
        public string DisplayCommand { get; }

        public ProcessStartInfo ToStartInfo()
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = FileName,
                UseShellExecute = UseShellExecute
            };

            if (!string.IsNullOrWhiteSpace(Verb))
            {
                startInfo.Verb = Verb;
            }

            if (UseShellExecute)
            {
                startInfo.Arguments = FormatProcessArguments(Arguments);
            }
            else
            {
                foreach (var argument in Arguments)
                {
                    startInfo.ArgumentList.Add(argument);
                }
            }

            return startInfo;
        }

        private static string FormatCommand(string fileName, IReadOnlyList<string> arguments)
        {
            return string.Join(" ", new[] { fileName }.Concat(arguments).Select(QuoteForDisplay));
        }

        private static string FormatProcessArguments(IReadOnlyList<string> arguments)
        {
            return string.Join(" ", arguments.Select(QuoteForProcess));
        }

        private static string QuoteForDisplay(string value)
        {
            if (value.All(c => !char.IsWhiteSpace(c) && c != '\'' && c != '"' && c != '\\'))
            {
                return value;
            }

            return $"'{value.Replace("'", "'\"'\"'")}'";
        }

        private static string QuoteForProcess(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "\"\"";
            }

            if (value.All(c => !char.IsWhiteSpace(c) && c != '"'))
            {
                return value;
            }

            return $"\"{value.Replace("\"", "\\\"")}\"";
        }
    }

    internal sealed class UpdateProcessResult
    {
        public UpdateProcessResult(int? exitCode)
        {
            ExitCode = exitCode;
        }

        public int? ExitCode { get; }
    }
}

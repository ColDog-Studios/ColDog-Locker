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
using System.Security.Principal;
using System.Text;
using ColDogStudios.ColDogLocker.Services.FileSystem;
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
            string expectedSha256,
            UpdatePlatform platform,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(installerPath))
            {
                throw new UpdateException(UpdateFailureKind.InstallFailed, "The update installer path is empty.");
            }

            if (expectedSha256 is null || expectedSha256.Length != 64 || !expectedSha256.All(char.IsAsciiHexDigit))
            {
                throw new UpdateException(UpdateFailureKind.MissingDigest,
                    "The downloaded update has no valid SHA-256 digest. Download the update again before installing it.");
            }

            var fullPath = Path.GetFullPath(installerPath);
            var stagingDirectory = Path.GetDirectoryName(fullPath)
                ?? throw new UpdateException(UpdateFailureKind.InstallFailed, "The update installer has no parent directory.");
            try
            {
                PrivateDirectory.Ensure(stagingDirectory);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or PlatformNotSupportedException)
            {
                throw new UpdateException(UpdateFailureKind.InstallFailed,
                    "The update installer is not in a protected staging directory. Installation was refused.", ex);
            }

            if (!File.Exists(fullPath))
            {
                throw new UpdateException(UpdateFailureKind.InstallFailed, $"The update installer was not found: {fullPath}");
            }

            // Detect changed downloads before requesting elevation. The privileged
            // consumer must still bind its input to these bytes across the handoff.
            await VerifyInstallerAsync(fullPath, expectedSha256, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            var command = CreateInstallCommand(fullPath, platform, expectedSha256.ToLowerInvariant());
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

        private static async Task VerifyInstallerAsync(string path, string expectedSha256, CancellationToken cancellationToken)
        {
            try
            {
                using var stream = FileSystemEntryPolicy.OpenRead(path);
                var actualHash = await SHA256.HashDataAsync(stream, cancellationToken);
                if (!CryptographicOperations.FixedTimeEquals(actualHash, Convert.FromHexString(expectedSha256)))
                {
                    throw new UpdateException(UpdateFailureKind.DigestMismatch,
                        "The downloaded installer has changed since verification. Installation was refused; download the update again.");
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or PlatformNotSupportedException)
            {
                throw new UpdateException(UpdateFailureKind.InstallFailed,
                    "The downloaded installer could not be safely read for verification. Installation was refused.", ex);
            }
        }

        internal UpdateInstallerCommand CreateInstallCommand(
            string installerPath,
            UpdatePlatform platform,
            string expectedSha256)
        {
            if (expectedSha256.Length != 64 || !expectedSha256.All(char.IsAsciiHexDigit))
            {
                throw new UpdateException(UpdateFailureKind.MissingDigest, "A valid SHA-256 digest is required for privileged installation.");
            }

            expectedSha256 = expectedSha256.ToLowerInvariant();

            return platform.OperatingSystem switch
            {
                UpdateOperatingSystem.Windows => CreateWindowsInstallCommand(installerPath, expectedSha256),
                UpdateOperatingSystem.Linux => CreateLinuxInstallCommand(installerPath, expectedSha256, platform),
                UpdateOperatingSystem.MacOS => CreateMacOsInstallCommand(installerPath, expectedSha256),
                _ => throw new UpdateException(UpdateFailureKind.UnsupportedPlatform,
                    "Automatic installation is not supported on this platform.")
            };
        }

        private static UpdateInstallerCommand CreateMacOsInstallCommand(string installerPath, string expectedSha256)
        {
            if (!Path.GetExtension(installerPath).Equals(".pkg", StringComparison.OrdinalIgnoreCase))
            {
                throw new UpdateException(UpdateFailureKind.InstallFailed,
                    "The downloaded macOS update is not a PKG installer.");
            }

            var script = CreateVerifiedMacOsInstallScript();
            var encodedScript = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
            var encodedPath = Convert.ToBase64String(Encoding.UTF8.GetBytes(installerPath));
            var appleScript = $"do shell script \"printf %s {encodedScript} | /usr/bin/base64 -D | /bin/sh -s -- {encodedPath} {expectedSha256}\" with administrator privileges";
            return new UpdateInstallerCommand(
                "/usr/bin/osascript",
                ["-e", appleScript],
                useShellExecute: false,
                verb: null,
                waitForExit: true,
                "Update package installed. Restart ColDog Locker to use the new version.");
        }

        private static UpdateInstallerCommand CreateWindowsInstallCommand(string installerPath, string expectedSha256)
        {
            var extension = Path.GetExtension(installerPath).ToLowerInvariant();
            if (extension is not (".msi" or ".exe"))
            {
                throw new UpdateException(UpdateFailureKind.InstallFailed,
                    "The downloaded Windows update is not an MSI or EXE installer.");
            }

            var script = CreateVerifiedWindowsInstallScript(installerPath, expectedSha256, extension);
            var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            return new UpdateInstallerCommand(
                "powershell.exe",
                ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedCommand],
                useShellExecute: true,
                verb: "runas",
                waitForExit: true,
                "Update package installed. Restart ColDog Locker to use the new version.");
        }

        private UpdateInstallerCommand CreateLinuxInstallCommand(
            string installerPath,
            string expectedSha256,
            UpdatePlatform platform)
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
                LinuxPackageFormat.Deb => CreateDebInstallCommand(installerPath, expectedSha256),
                LinuxPackageFormat.Rpm => CreateRpmInstallCommand(installerPath, expectedSha256),
                _ => throw new UpdateException(UpdateFailureKind.UnsupportedPlatform,
                    "Automatic Linux installation needs a .deb or .rpm package.")
            };
        }

        private UpdateInstallerCommand CreateDebInstallCommand(string installerPath, string expectedSha256)
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
                ["-c", CreateVerifiedLinuxStagingScript("deb", script), "cdlocker-updater", installerPath, expectedSha256],
                "Update package installed. Restart ColDog Locker to use the new version.");
        }

        private static string CreateDebReplaceScript(string removeCommand, string installCommand)
        {
            return $"if dpkg -s {LinuxPackageId} >/dev/null 2>&1; then {removeCommand} {LinuxPackageId}; fi && {installCommand} \"$package\"";
        }

        private UpdateInstallerCommand CreateRpmInstallCommand(string installerPath, string expectedSha256)
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
                ["-c", CreateVerifiedLinuxStagingScript("rpm", script), "cdlocker-updater", installerPath, expectedSha256],
                "Update package installed. Restart ColDog Locker to use the new version.");
        }

        private static string CreateRpmReplaceScript(string removeCommand, string installCommand)
        {
            return $"if rpm -q {LinuxPackageId} >/dev/null 2>&1; then {removeCommand} {LinuxPackageId}; fi && {installCommand} \"$package\"";
        }

        internal static string CreateVerifiedLinuxStagingScript(string extension, string installScript)
        {
            return "set -eu; " +
                   "stage=$(/usr/bin/mktemp -d /var/tmp/cdlocker-update.XXXXXX); " +
                   "trap '/bin/rm -rf -- \"$stage\"' EXIT HUP INT TERM; " +
                   $"package=\"$stage/package.{extension}\"; " +
                   "/usr/bin/install -m 0600 -- \"$1\" \"$package\"; " +
                   "actual=$(/usr/bin/sha256sum \"$package\" | /usr/bin/cut -d ' ' -f 1); " +
                   "if [ \"$actual\" != \"$2\" ]; then echo 'Update digest changed during privileged staging.' >&2; exit 65; fi; " +
                   installScript;
        }

        private static string CreateVerifiedMacOsInstallScript()
        {
            return "set -eu; " +
                   "source=$(printf %s \"$1\" | /usr/bin/base64 -D); " +
                   "stage=$(/usr/bin/mktemp -d /private/var/tmp/cdlocker-update.XXXXXX); " +
                   "trap '/bin/rm -rf \"$stage\"' EXIT HUP INT TERM; " +
                   "package=\"$stage/package.pkg\"; " +
                   "/bin/cp \"$source\" \"$package\"; /bin/chmod 0600 \"$package\"; " +
                   "actual=$(/usr/bin/shasum -a 256 \"$package\" | /usr/bin/cut -d ' ' -f 1); " +
                   "if [ \"$actual\" != \"$2\" ]; then echo 'Update digest changed during privileged staging.' >&2; exit 65; fi; " +
                   "/usr/sbin/installer -pkg \"$package\" -target /";
        }

        private static string CreateVerifiedWindowsInstallScript(
            string installerPath,
            string expectedSha256,
            string extension)
        {
            var source = installerPath.Replace("'", "''", StringComparison.Ordinal);
            var launch = extension == ".msi"
                ? "$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', ('\"' + $package + '\"')) -PassThru -Wait;"
                : "$process = Start-Process -FilePath $package -PassThru -Wait;";
            return "$ErrorActionPreference = 'Stop'; " +
                   $"$source = '{source}'; $expected = '{expectedSha256}'; " +
                   "$stage = Join-Path $env:ProgramData ('ColDogLocker-Update-' + [Guid]::NewGuid().ToString('N')); " +
                   "$admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'); " +
                   "$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'); " +
                   "$acl = [System.Security.AccessControl.DirectorySecurity]::new(); " +
                   "$acl.SetAccessRuleProtection($true, $false); $acl.SetOwner($admins); " +
                   "$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'; " +
                   "$propagation = [System.Security.AccessControl.PropagationFlags]::None; " +
                   "$allow = [System.Security.AccessControl.AccessControlType]::Allow; " +
                   "$rights = [System.Security.AccessControl.FileSystemRights]::FullControl; " +
                   "$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($admins, $rights, $inherit, $propagation, $allow)); " +
                   "$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($system, $rights, $inherit, $propagation, $allow)); " +
                   "[System.IO.Directory]::CreateDirectory($stage) | Out-Null; try { Set-Acl -LiteralPath $stage -AclObject $acl; " +
                   "$attributes = [System.IO.File]::GetAttributes($stage); " +
                   "if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Privileged update staging resolved through a reparse point.' }; " +
                   "$appliedAcl = Get-Acl -LiteralPath $stage; " +
                   "$appliedOwner = $appliedAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; " +
                   "if (-not $appliedAcl.AreAccessRulesProtected -or $appliedOwner -ne $admins.Value) { throw 'Privileged update staging ACL verification failed.' }; " +
                   $"$package = Join-Path $stage 'package{extension}'; " +
                   "[System.IO.File]::Copy($source, $package, $false); " +
                   "$actual = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash; " +
                   "if ($actual -ine $expected) { throw 'Update digest changed during privileged staging.' }; " +
                   launch + " if ($process.ExitCode -ne 0) { exit $process.ExitCode } } " +
                   "finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }";
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
            if (string.IsNullOrWhiteSpace(command))
            {
                return false;
            }

            var candidate = Path.GetFileName(command);
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return false;
            }

            if (Path.IsPathRooted(candidate))
            {
                return false;
            }

            var paths = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            return paths.Any(path => File.Exists(Path.Join(path, candidate)));
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
            if (IsE2EInstallerLaunchSuppressed())
            {
                return new UpdateProcessResult(waitForExit ? 0 : null);
            }

            using var process = Process.Start(startInfo)
                                ?? throw new InvalidOperationException($"Failed to launch '{startInfo.FileName}'.");

            if (!waitForExit)
            {
                return new UpdateProcessResult(null);
            }

            await process.WaitForExitAsync(cancellationToken);
            return new UpdateProcessResult(process.ExitCode);
        }

        private static bool IsE2EInstallerLaunchSuppressed()
        {
            return IsEnabled(Environment.GetEnvironmentVariable("CDLOCKER_E2E_ENABLE_UPDATE_OVERRIDES")) &&
                   IsEnabled(Environment.GetEnvironmentVariable("CDLOCKER_E2E_UPDATE_SKIP_INSTALLER_LAUNCH"));
        }

        private static bool IsEnabled(string? value)
        {
            return value is not null &&
                   (value.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                    value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                    value.Equals("yes", StringComparison.OrdinalIgnoreCase));
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

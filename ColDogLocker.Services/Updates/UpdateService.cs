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

using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Core.Versioning;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Services.Updates
{
    public interface IUpdateService
    {
        Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken cancellationToken = default);
        Task<UpdateDownloadResult> DownloadUpdateAsync(UpdateCheckResult updateInfo, CancellationToken cancellationToken = default);
    }

    public class UpdateCheckResult
    {
        public bool UpdateAvailable { get; set; }
        public bool CanDownload { get; set; }
        public bool IsSupportedPlatform { get; set; } = true;
        public string CurrentVersion { get; set; } = string.Empty;
        public string LatestVersion { get; set; } = string.Empty;
        public string PlatformName { get; set; } = string.Empty;
        public string? DownloadUrl { get; set; }
        public string? InstallerFileName { get; set; }
        public string? AssetDigest { get; set; }
        public string? ReleaseName { get; set; }
        public string? ReleaseUrl { get; set; }
        public string? ReleaseNotesMarkdown { get; set; }
        public string? UserMessage { get; set; }
        public string? ManualUpdateInstructions { get; set; }
    }

    public class UpdateDownloadResult
    {
        public string FilePath { get; set; } = string.Empty;
        public string Sha256 { get; set; } = string.Empty;
        public long BytesDownloaded { get; set; }
    }

    public enum UpdateFailureKind
    {
        NoReleases,
        InvalidVersion,
        UnsupportedPlatform,
        MissingAsset,
        MissingDigest,
        DigestMismatch,
        DownloadTooLarge,
        InvalidDownloadUrl,
        Network,
        Timeout,
        FileSystem,
        Unknown
    }

    public class UpdateException : Exception
    {
        public UpdateException(UpdateFailureKind failureKind, string message, Exception? innerException = null)
            : base(message, innerException)
        {
            FailureKind = failureKind;
        }

        public UpdateFailureKind FailureKind { get; }
    }

    public enum UpdateOperatingSystem
    {
        Windows,
        Linux,
        MacOS,
        Unsupported
    }

    public enum LinuxPackageFormat
    {
        Unknown,
        Deb,
        Rpm
    }

    public sealed class UpdatePlatform
    {
        public UpdateOperatingSystem OperatingSystem { get; init; }
        public Architecture Architecture { get; init; } = RuntimeInformation.ProcessArchitecture;
        public LinuxPackageFormat LinuxPackageFormat { get; init; }

        public bool SupportsAutomaticUpdates
            => OperatingSystem is UpdateOperatingSystem.Windows ||
               (OperatingSystem is UpdateOperatingSystem.Linux && LinuxPackageFormat is not LinuxPackageFormat.Unknown);

        public string DisplayName
        {
            get
            {
                var architecture = Architecture.ToString().ToLowerInvariant();
                return OperatingSystem switch
                {
                    UpdateOperatingSystem.Windows => $"Windows {architecture}",
                    UpdateOperatingSystem.Linux when LinuxPackageFormat is LinuxPackageFormat.Deb => $"Linux DEB {architecture}",
                    UpdateOperatingSystem.Linux when LinuxPackageFormat is LinuxPackageFormat.Rpm => $"Linux RPM {architecture}",
                    UpdateOperatingSystem.Linux => $"Linux {architecture}",
                    UpdateOperatingSystem.MacOS => $"macOS {architecture}",
                    _ => $"{RuntimeInformation.OSDescription} {architecture}"
                };
            }
        }

        public string ManualUpdateInstructions => OperatingSystem switch
        {
            UpdateOperatingSystem.MacOS =>
                "Automatic macOS updates are disabled because this installer path cannot be reliably tested. Download the desired release from GitHub, verify the release asset digest shown on GitHub, back up your configuration, then replace the application bundle manually.",
            UpdateOperatingSystem.Linux when LinuxPackageFormat is LinuxPackageFormat.Unknown =>
                "Automatic Linux updates need a known package family. Download the .deb or .rpm package that matches your distribution from GitHub, verify the release asset digest shown on GitHub, then install it with your package manager.",
            _ =>
                "Download the matching release asset from GitHub, verify the release asset digest shown on GitHub, then run the installer manually."
        };

        public static UpdatePlatform Detect()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows };
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.MacOS };
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Linux, LinuxPackageFormat = DetectLinuxPackageFormat() };
            }

            return new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Unsupported };
        }

        private static LinuxPackageFormat DetectLinuxPackageFormat()
        {
            try
            {
                const string OsReleasePath = "/etc/os-release";
                if (!File.Exists(OsReleasePath))
                {
                    Logger.Log(LogLevel.Debug, "Unable to detect Linux package format because /etc/os-release was not found.");
                    return LinuxPackageFormat.Unknown;
                }

                var values = File.ReadAllLines(OsReleasePath)
                    .Select(line => line.Split('=', 2))
                    .Where(parts => parts.Length == 2)
                    .ToDictionary(parts => parts[0], parts => parts[1].Trim('"').ToLowerInvariant());

                var distribution = string.Join(' ', values.GetValueOrDefault("ID"), values.GetValueOrDefault("ID_LIKE"));
                if (ContainsAny(distribution, "debian", "ubuntu", "linuxmint", "pop"))
                {
                    return LinuxPackageFormat.Deb;
                }

                if (ContainsAny(distribution, "rhel", "fedora", "centos", "suse", "opensuse", "rocky", "almalinux"))
                {
                    return LinuxPackageFormat.Rpm;
                }

                Logger.Log(LogLevel.Debug, $"Linux package format was not recognized from /etc/os-release: {distribution}");
                return LinuxPackageFormat.Unknown;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, "Failed to detect Linux package format.", ex);
                return LinuxPackageFormat.Unknown;
            }
        }

        private static bool ContainsAny(string value, params string[] candidates)
        {
            return candidates.Any(candidate => value.Contains(candidate, StringComparison.OrdinalIgnoreCase));
        }
    }

    public sealed class UpdateServiceOptions
    {
        public string ApiBaseUrl { get; set; } = "https://api.github.com";
        public string RepositoryOwner { get; set; } = "ColDog-Studios";
        public string RepositoryName { get; set; } = "ColDog-Locker";
        public string CurrentVersion { get; set; } = AppInfo.SemanticVersion;
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
        public long MaxDownloadBytes { get; set; } = 1024L * 1024L * 1024L;

        public IReadOnlyCollection<string> AllowedDownloadHosts { get; set; } =
        [
            "github.com",
            "objects.githubusercontent.com",
            "github-releases.githubusercontent.com",
            "release-assets.githubusercontent.com"
        ];

        public Func<UpdatePlatform> PlatformDetector { get; set; } = UpdatePlatform.Detect;

        public Func<string> DownloadDirectoryProvider { get; set; } =
            () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        public bool AllowLoopbackHttpDownloadsForTesting { get; set; }
    }

    public static class UpdateService
    {
        private static readonly Lazy<GitHubUpdateService> _defaultService = new(GitHubUpdateService.CreateDefault);

        public static Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
        {
            return _defaultService.Value.CheckForUpdatesAsync(cancellationToken);
        }

        public static async Task<string> DownloadUpdateAsync(UpdateCheckResult updateInfo)
        {
            var result = await _defaultService.Value.DownloadUpdateAsync(updateInfo);
            return result.FilePath;
        }

        public static async Task<string> DownloadUpdateAsync(UpdateCheckResult updateInfo, CancellationToken cancellationToken)
        {
            var result = await _defaultService.Value.DownloadUpdateAsync(updateInfo, cancellationToken);
            return result.FilePath;
        }

        internal static UpdateServiceOptions CreateDefaultOptions()
        {
            var options = new UpdateServiceOptions();
            if (!IsEnabled(Environment.GetEnvironmentVariable("CDLOCKER_E2E_ENABLE_UPDATE_OVERRIDES")))
            {
                return options;
            }

            var apiBaseUrl = Environment.GetEnvironmentVariable("CDLOCKER_E2E_UPDATE_API_BASE_URL");
            if (!string.IsNullOrWhiteSpace(apiBaseUrl))
            {
                options.ApiBaseUrl = apiBaseUrl;
            }

            var currentVersion = Environment.GetEnvironmentVariable("CDLOCKER_E2E_UPDATE_CURRENT_VERSION");
            if (!string.IsNullOrWhiteSpace(currentVersion))
            {
                options.CurrentVersion = currentVersion;
            }

            var downloadDirectory = Environment.GetEnvironmentVariable("CDLOCKER_E2E_UPDATE_DOWNLOAD_DIR");
            if (!string.IsNullOrWhiteSpace(downloadDirectory))
            {
                options.DownloadDirectoryProvider = () => downloadDirectory;
            }

            var platform = CreateE2EPlatform(Environment.GetEnvironmentVariable("CDLOCKER_E2E_UPDATE_PLATFORM"));
            if (platform != null)
            {
                options.PlatformDetector = () => platform;
            }

            if (IsEnabled(Environment.GetEnvironmentVariable("CDLOCKER_E2E_UPDATE_ALLOW_LOOPBACK_HTTP")))
            {
                options.AllowLoopbackHttpDownloadsForTesting = true;
            }

            return options;
        }

        private static UpdatePlatform? CreateE2EPlatform(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            var normalized = value.Trim().ToLowerInvariant();
            var parts = normalized.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 0)
            {
                return null;
            }

            var architecture = parts.Length > 1 ? ParseArchitecture(parts[^1]) : RuntimeInformation.ProcessArchitecture;
            return parts[0] switch
            {
                "windows" or "win" => new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Windows, Architecture = architecture },
                "macos" or "osx" => new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.MacOS, Architecture = architecture },
                "linux" when parts.Contains("deb") => new UpdatePlatform
                {
                    OperatingSystem = UpdateOperatingSystem.Linux, LinuxPackageFormat = LinuxPackageFormat.Deb, Architecture = architecture
                },
                "linux" when parts.Contains("rpm") => new UpdatePlatform
                {
                    OperatingSystem = UpdateOperatingSystem.Linux, LinuxPackageFormat = LinuxPackageFormat.Rpm, Architecture = architecture
                },
                "linux" => new UpdatePlatform { OperatingSystem = UpdateOperatingSystem.Linux, Architecture = architecture },
                _ => null
            };
        }

        private static Architecture ParseArchitecture(string value)
        {
            return value switch
            {
                "x64" or "amd64" => Architecture.X64,
                "arm64" or "aarch64" => Architecture.Arm64,
                "x86" or "i386" => Architecture.X86,
                "arm" or "armv7" or "arm32" => Architecture.Arm,
                _ => RuntimeInformation.ProcessArchitecture
            };
        }

        private static bool IsEnabled(string? value)
        {
            return value is not null &&
                   (value.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                    value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                    value.Equals("yes", StringComparison.OrdinalIgnoreCase));
        }
    }

    public sealed class GitHubUpdateService : IUpdateService, IDisposable
    {
        private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true };
        private readonly Func<UpdateChannel> _channelProvider;
        private readonly bool _disposeHttpClient;

        private readonly HttpClient _httpClient;
        private readonly UpdateServiceOptions _options;

        public GitHubUpdateService(
            HttpClient httpClient,
            UpdateServiceOptions? options = null,
            Func<UpdateChannel>? channelProvider = null,
            bool disposeHttpClient = false)
        {
            _httpClient = httpClient;
            _options = options ?? new UpdateServiceOptions();
            _channelProvider = channelProvider ?? (() => SettingsManager.Settings.UpdateChannel);
            _disposeHttpClient = disposeHttpClient;

            ConfigureGitHubHeaders(_httpClient);
        }

        public void Dispose()
        {
            if (_disposeHttpClient)
            {
                _httpClient.Dispose();
            }
        }

        public async Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
        {
            var currentVersionText = NormalizeVersion(_options.CurrentVersion);
            var platform = _options.PlatformDetector();
            Logger.Log(LogLevel.Info, $"Starting update check for {platform.DisplayName}");
            Logger.Log(LogLevel.Debug, $"Current application version: {currentVersionText}");

            if (!platform.SupportsAutomaticUpdates)
            {
                Logger.Log(LogLevel.Info, $"Automatic updates are disabled for {platform.DisplayName}.");
            }

            try
            {
                var release = await FetchReleaseAsync(cancellationToken);
                if (release == null)
                {
                    Logger.Log(LogLevel.Warning, "No GitHub releases were returned for the selected update channel.");
                    return CreateNoReleaseResult(
                        platform,
                        currentVersionText,
                        "ColDog Locker is up to date. No published releases were found for the selected update channel.");
                }

                var latestVersionText = NormalizeVersion(release.TagName);
                if (!SemanticVersion.TryParse(currentVersionText, out var currentVersion))
                {
                    Logger.Log(LogLevel.Error, $"Current application version is not valid semantic version: {currentVersionText}");
                    throw new UpdateException(UpdateFailureKind.InvalidVersion, $"The current application version is invalid: {currentVersionText}");
                }

                if (!SemanticVersion.TryParse(latestVersionText, out var latestVersion))
                {
                    Logger.Log(LogLevel.Error, $"Release tag is not valid semantic version: {release.TagName}");
                    throw new UpdateException(UpdateFailureKind.InvalidVersion, $"The latest release version is invalid: {release.TagName}");
                }

                if (latestVersion <= currentVersion)
                {
                    Logger.Log(LogLevel.Info, $"Application is up to date: {currentVersionText}");
                    return CreateResult(false, false, platform, release, currentVersionText, latestVersionText,
                        "ColDog Locker is up to date.");
                }

                if (!platform.SupportsAutomaticUpdates)
                {
                    return CreateResult(true, false, platform, release, currentVersionText, latestVersionText,
                        $"A newer version is available, but automatic updates are not available for {platform.DisplayName}.",
                        platform.ManualUpdateInstructions);
                }

                var selectedAsset = SelectAsset(release.Assets, platform);
                if (selectedAsset == null)
                {
                    Logger.Log(LogLevel.Warning, $"No release asset matched platform {platform.DisplayName} for release {release.TagName}.");
                    return CreateResult(true, false, platform, release, currentVersionText, latestVersionText,
                        $"A newer version is available, but no installer package matched {platform.DisplayName}.",
                        platform.ManualUpdateInstructions);
                }

                if (string.IsNullOrWhiteSpace(selectedAsset.Digest))
                {
                    Logger.Log(LogLevel.Warning, $"Release asset '{selectedAsset.Name}' does not include a GitHub digest.");
                    return CreateResult(true, false, platform, release, currentVersionText, latestVersionText,
                        "A newer version is available, but the release asset does not include a digest for verification.",
                        platform.ManualUpdateInstructions);
                }

                Logger.Log(LogLevel.Info, $"Update available: {currentVersionText} -> {latestVersionText}");
                Logger.Log(LogLevel.Debug, $"Selected update asset '{selectedAsset.Name}' with digest '{selectedAsset.Digest}'.");

                return CreateResult(true, true, platform, release, currentVersionText, latestVersionText,
                    "A newer version is available.", selectedAsset: selectedAsset);
            }
            catch (UpdateException)
            {
                throw;
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                Logger.Log(LogLevel.Warning, "Update check timed out.", ex);
                throw new UpdateException(UpdateFailureKind.Timeout, "The update check timed out. Please try again later.", ex);
            }
            catch (HttpRequestException ex)
            {
                Logger.Log(LogLevel.Error, "Update check failed due to a network or GitHub API error.", ex);
                throw new UpdateException(UpdateFailureKind.Network,
                    "Unable to contact GitHub for update information. Please check your network connection and try again.", ex);
            }
            catch (JsonException ex)
            {
                Logger.Log(LogLevel.Error, "GitHub release response could not be parsed.", ex);
                throw new UpdateException(UpdateFailureKind.Unknown, "GitHub returned update information in an unexpected format.", ex);
            }
        }

        public async Task<UpdateDownloadResult> DownloadUpdateAsync(
            UpdateCheckResult updateInfo,
            CancellationToken cancellationToken = default)
        {
            if (!updateInfo.UpdateAvailable)
            {
                throw new UpdateException(UpdateFailureKind.MissingAsset, "No update is available to download.");
            }

            if (!updateInfo.CanDownload)
            {
                throw new UpdateException(UpdateFailureKind.UnsupportedPlatform,
                    updateInfo.UserMessage ?? "This update cannot be downloaded automatically on the current platform.");
            }

            if (string.IsNullOrWhiteSpace(updateInfo.DownloadUrl) || string.IsNullOrWhiteSpace(updateInfo.InstallerFileName))
            {
                throw new UpdateException(UpdateFailureKind.MissingAsset, "The selected release does not include a downloadable installer asset.");
            }

            var expectedHash = ParseSha256Digest(updateInfo.AssetDigest);
            var downloadUri = ValidateDownloadUri(updateInfo.DownloadUrl);
            var targetPath = GetDownloadPath(updateInfo.InstallerFileName);
            Logger.Log(LogLevel.Info, $"Downloading update asset '{updateInfo.InstallerFileName}'.");
            Logger.Log(LogLevel.Debug, $"Downloading update from '{downloadUri}' to '{targetPath}'.");

            var result = await DownloadAndVerifyUpdateAsync(
                downloadUri,
                targetPath,
                expectedHash,
                updateInfo.InstallerFileName,
                cancellationToken);

            Logger.Log(LogLevel.Info, $"Successfully downloaded and verified update: {targetPath}");
            return result;
        }

        public static GitHubUpdateService CreateDefault()
        {
            var options = UpdateService.CreateDefaultOptions();
            var client = new HttpClient { Timeout = options.Timeout };
            return new GitHubUpdateService(client, options, disposeHttpClient: true);
        }

        private async Task<GitHubReleaseDto?> FetchReleaseAsync(CancellationToken cancellationToken)
        {
            var channel = _channelProvider();
            Logger.Log(LogLevel.Info, $"Checking for updates on {channel} channel.");

            if (channel == UpdateChannel.Stable)
            {
                var uri = BuildApiUri("releases/latest");
                Logger.Log(LogLevel.Debug, $"Requesting GitHub release endpoint: {uri}");
                return await SendJsonRequestAsync<GitHubReleaseDto>(uri, cancellationToken);
            }

            var releasesUri = BuildApiUri("releases");
            Logger.Log(LogLevel.Debug, $"Requesting GitHub releases endpoint: {releasesUri}");
            var releases = await SendJsonRequestAsync<List<GitHubReleaseDto>>(releasesUri, cancellationToken);
            return releases?
                .Where(release => !release.Draft)
                .Select(release =>
                {
                    var parsed = SemanticVersion.TryParse(NormalizeVersion(release.TagName), out var version);
                    return new { Release = release, Parsed = parsed, Version = version };
                })
                .Where(candidate => candidate.Parsed)
                .OrderByDescending(candidate => candidate.Version)
                .FirstOrDefault()
                ?.Release;
        }

        private async Task<T?> SendJsonRequestAsync<T>(string uri, CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = await _httpClient.SendAsync(request, cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                Logger.Log(LogLevel.Warning, $"GitHub endpoint returned 404: {uri}");
                return default;
            }

            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            Logger.Log(LogLevel.Debug, $"Received {json.Length} characters from GitHub release API.");
            return JsonSerializer.Deserialize<T>(json, _jsonOptions);
        }

        private string BuildApiUri(string endpoint)
        {
            return $"{_options.ApiBaseUrl.TrimEnd('/')}/repos/{_options.RepositoryOwner}/{_options.RepositoryName}/{endpoint}";
        }

        private static void ConfigureGitHubHeaders(HttpClient httpClient)
        {
            if (!httpClient.DefaultRequestHeaders.UserAgent.Any())
            {
                httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("ColDog-Locker-Updater", "1.0"));
            }

            if (!httpClient.DefaultRequestHeaders.Accept.Any())
            {
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            }

            if (!httpClient.DefaultRequestHeaders.Contains("X-GitHub-Api-Version"))
            {
                httpClient.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
            }
        }

        private static UpdateCheckResult CreateResult(
            bool updateAvailable,
            bool canDownload,
            UpdatePlatform platform,
            GitHubReleaseDto release,
            string currentVersion,
            string latestVersion,
            string userMessage,
            string? manualInstructions = null,
            GitHubAsset? selectedAsset = null)
        {
            return new UpdateCheckResult
            {
                UpdateAvailable = updateAvailable,
                CanDownload = canDownload,
                IsSupportedPlatform = platform.SupportsAutomaticUpdates,
                CurrentVersion = currentVersion,
                LatestVersion = latestVersion,
                PlatformName = platform.DisplayName,
                DownloadUrl = selectedAsset?.BrowserDownloadUrl,
                InstallerFileName = selectedAsset?.Name,
                AssetDigest = selectedAsset?.Digest,
                ReleaseName = release.Name,
                ReleaseUrl = release.HtmlUrl,
                ReleaseNotesMarkdown = release.Body,
                UserMessage = userMessage,
                ManualUpdateInstructions = manualInstructions
            };
        }

        private static UpdateCheckResult CreateNoReleaseResult(
            UpdatePlatform platform,
            string currentVersion,
            string userMessage)
        {
            return new UpdateCheckResult
            {
                UpdateAvailable = false,
                CanDownload = false,
                IsSupportedPlatform = platform.SupportsAutomaticUpdates,
                CurrentVersion = currentVersion,
                LatestVersion = currentVersion,
                PlatformName = platform.DisplayName,
                UserMessage = userMessage
            };
        }

        private static GitHubAsset? SelectAsset(IEnumerable<GitHubAsset> assets, UpdatePlatform platform)
        {
            var candidates = assets
                .Where(asset => !string.IsNullOrWhiteSpace(asset.BrowserDownloadUrl))
                .Select(asset => new { Asset = asset, Score = ScoreAsset(asset, platform) })
                .Where(candidate => candidate.Score >= 0)
                .OrderByDescending(candidate => candidate.Score)
                .ThenBy(candidate => candidate.Asset.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return candidates.FirstOrDefault()?.Asset;
        }

        private static int ScoreAsset(GitHubAsset asset, UpdatePlatform platform)
        {
            var name = asset.Name.ToLowerInvariant();
            if (name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".sig", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".asc", StringComparison.OrdinalIgnoreCase))
            {
                return -1;
            }

            var extensionScore = platform.OperatingSystem switch
            {
                UpdateOperatingSystem.Windows when name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) => 70,
                UpdateOperatingSystem.Windows when name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) => 60,
                UpdateOperatingSystem.Linux when platform.LinuxPackageFormat is LinuxPackageFormat.Deb &&
                                                 name.EndsWith(".deb", StringComparison.OrdinalIgnoreCase) => 60,
                UpdateOperatingSystem.Linux when platform.LinuxPackageFormat is LinuxPackageFormat.Rpm &&
                                                 name.EndsWith(".rpm", StringComparison.OrdinalIgnoreCase) => 60,
                _ => -1
            };

            if (extensionScore < 0)
            {
                return -1;
            }

            var score = extensionScore;
            if (MatchesArchitecture(name, platform.Architecture))
            {
                score += 20;
            }
            else if (ContainsArchitectureToken(name))
            {
                return -1;
            }

            if (platform.OperatingSystem is UpdateOperatingSystem.Windows && ContainsAny(name, "win", "windows"))
            {
                score += 5;
            }

            if (platform.OperatingSystem is UpdateOperatingSystem.Linux && ContainsAny(name, "linux"))
            {
                score += 5;
            }

            return score;
        }

        private static bool MatchesArchitecture(string assetName, Architecture architecture)
        {
            return architecture switch
            {
                Architecture.X64 => ContainsAny(assetName, "x64", "amd64"),
                Architecture.Arm64 => ContainsAny(assetName, "arm64", "aarch64"),
                Architecture.X86 => ContainsAny(assetName, "x86", "i386", "win32"),
                Architecture.Arm => ContainsAny(assetName, "armv7", "arm32"),
                _ => false
            };
        }

        private static bool ContainsArchitectureToken(string assetName)
        {
            return ContainsAny(assetName, "x64", "amd64", "arm64", "aarch64", "x86", "i386", "win32", "armv7", "arm32");
        }

        private static bool ContainsAny(string value, params string[] candidates)
        {
            return candidates.Any(candidate => value.Contains(candidate, StringComparison.OrdinalIgnoreCase));
        }

        private static string NormalizeVersion(string version)
        {
            var normalized = version.Trim();
            if (normalized.StartsWith('v') || normalized.StartsWith('V'))
            {
                normalized = normalized[1..];
            }

            var buildMetadataIndex = normalized.IndexOf('+');
            return buildMetadataIndex >= 0 ? normalized[..buildMetadataIndex] : normalized;
        }

        private static string ParseSha256Digest(string? digest)
        {
            if (string.IsNullOrWhiteSpace(digest))
            {
                Logger.Log(LogLevel.Warning, "Cannot verify update because the selected release asset has no digest.");
                throw new UpdateException(UpdateFailureKind.MissingDigest,
                    "The selected release asset does not include a GitHub digest for verification.");
            }

            var parts = digest.Split(':', 2);
            if (parts.Length != 2 ||
                !parts[0].Equals("sha256", StringComparison.OrdinalIgnoreCase) ||
                parts[1].Length != 64 ||
                parts[1].Any(static c => !Uri.IsHexDigit(c)))
            {
                Logger.Log(LogLevel.Warning, $"Unsupported release asset digest format: {digest}");
                throw new UpdateException(UpdateFailureKind.MissingDigest,
                    "The selected release asset digest is missing or is not a SHA-256 digest.");
            }

            return parts[1].ToLowerInvariant();
        }

        private string GetDownloadPath(string installerFileName)
        {
            var safeFileName = Path.GetFileName(installerFileName);
            return Path.Combine(_options.DownloadDirectoryProvider(), safeFileName);
        }

        private Uri ValidateDownloadUri(string downloadUrl)
        {
            if (!Uri.TryCreate(downloadUrl, UriKind.Absolute, out var uri) ||
                !IsAllowedDownloadScheme(uri) ||
                !IsAllowedDownloadHost(uri.Host))
            {
                Logger.Log(LogLevel.Warning, $"Rejected unsafe update download URL: {downloadUrl}");
                throw new UpdateException(UpdateFailureKind.InvalidDownloadUrl,
                    "The selected update asset has an unsafe download URL. The file was not downloaded.");
            }

            return uri;
        }

        private void ValidateFinalDownloadUri(Uri uri)
        {
            if (!IsAllowedDownloadScheme(uri) || !IsAllowedDownloadHost(uri.Host))
            {
                Logger.Log(LogLevel.Warning, $"Rejected unsafe update redirect URL: {uri}");
                throw new UpdateException(UpdateFailureKind.InvalidDownloadUrl,
                    "The update download redirected to an unsafe URL. The file was not saved.");
            }
        }

        private bool IsAllowedDownloadHost(string host)
        {
            if (_options.AllowLoopbackHttpDownloadsForTesting && IsLoopbackHost(host))
            {
                return true;
            }

            return _options.AllowedDownloadHosts.Any(allowedHost =>
                host.Equals(allowedHost, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsAllowedDownloadScheme(Uri uri)
        {
            return uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                   (_options.AllowLoopbackHttpDownloadsForTesting &&
                    uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                    IsLoopbackHost(uri.Host));
        }

        private static bool IsLoopbackHost(string host)
        {
            return host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                   IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);
        }

        private async Task<UpdateDownloadResult> DownloadAndVerifyUpdateAsync(
            Uri downloadUri,
            string targetPath,
            string expectedHash,
            string installerFileName,
            CancellationToken cancellationToken)
        {
            var targetDirectory = Path.GetDirectoryName(targetPath) ?? Directory.GetCurrentDirectory();
            var tempPath = Path.Combine(targetDirectory, $".{Path.GetFileName(targetPath)}.{Guid.NewGuid():N}.tmp");

            try
            {
                Directory.CreateDirectory(targetDirectory);

                using var request = new HttpRequestMessage(HttpMethod.Get, downloadUri);
                using var response = await _httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);
                response.EnsureSuccessStatusCode();

                ValidateFinalDownloadUri(response.RequestMessage?.RequestUri ?? downloadUri);

                if (response.Content.Headers.ContentLength is { } contentLength)
                {
                    EnsureDownloadSizeAllowed(contentLength, installerFileName);
                }

                long bytesDownloaded = 0;
                string actualHash;

                await using (var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken))
                await using (var targetStream = new FileStream(
                                 tempPath,
                                 FileMode.CreateNew,
                                 FileAccess.Write,
                                 FileShare.None,
                                 1024 * 128,
                                 FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    AppFilePermissions.ApplyPrivateFile(tempPath);

                    using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var buffer = new byte[1024 * 128];

                    while (true)
                    {
                        var bytesRead = await responseStream.ReadAsync(buffer, cancellationToken);
                        if (bytesRead == 0)
                        {
                            break;
                        }

                        bytesDownloaded += bytesRead;
                        EnsureDownloadSizeAllowed(bytesDownloaded, installerFileName);
                        hasher.AppendData(buffer, 0, bytesRead);
                        await targetStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                    }

                    await targetStream.FlushAsync(cancellationToken);
                    actualHash = Convert.ToHexStringLower(hasher.GetHashAndReset());
                }

                if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    Logger.Log(LogLevel.Error, $"Update digest mismatch for '{installerFileName}'. Expected {expectedHash}, got {actualHash}.");
                    throw new UpdateException(UpdateFailureKind.DigestMismatch,
                        "The downloaded update did not match GitHub's release digest. The file was not saved.");
                }

                if (File.Exists(targetPath))
                {
                    File.Replace(tempPath, targetPath, null);
                }
                else
                {
                    File.Move(tempPath, targetPath);
                }

                AppFilePermissions.ApplyPrivateFile(targetPath);

                return new UpdateDownloadResult { FilePath = targetPath, Sha256 = actualHash, BytesDownloaded = bytesDownloaded };
            }
            catch (UpdateException)
            {
                TryDeleteTempFile(tempPath);
                throw;
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                TryDeleteTempFile(tempPath);
                Logger.Log(LogLevel.Warning, $"Download timed out for update asset '{installerFileName}'.", ex);
                throw new UpdateException(UpdateFailureKind.Timeout, "The update download timed out. Please try again later.", ex);
            }
            catch (HttpRequestException ex)
            {
                TryDeleteTempFile(tempPath);
                Logger.Log(LogLevel.Error, $"Failed to download update asset '{installerFileName}'.", ex);
                throw new UpdateException(UpdateFailureKind.Network, "The update download failed. Please check your network connection and try again.", ex);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException or OperationCanceledException)
            {
                TryDeleteTempFile(tempPath);
                Logger.Log(LogLevel.Error, $"Failed to write update asset to '{targetPath}'.", ex);
                throw new UpdateException(UpdateFailureKind.FileSystem, "The update was verified but could not be saved to disk.", ex);
            }
        }

        private void EnsureDownloadSizeAllowed(long bytes, string installerFileName)
        {
            if (bytes <= _options.MaxDownloadBytes)
            {
                return;
            }

            Logger.Log(LogLevel.Warning, $"Rejected update asset '{installerFileName}' because it exceeds the configured maximum size.");
            throw new UpdateException(UpdateFailureKind.DownloadTooLarge,
                "The update download is larger than the configured safety limit. The file was not saved.");
        }

        private static void TryDeleteTempFile(string tempPath)
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Failed to clean up temporary update file '{tempPath}'.", ex);
            }
        }
    }
}

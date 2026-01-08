using System.Security.Cryptography;
using System.Text.Json;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Application.Services
{
    public class UpdateCheckResult
    {
        public bool UpdateAvailable { get; set; }
        public string CurrentVersion { get; set; } = string.Empty;
        public string LatestVersion { get; set; } = string.Empty;
        public string? DownloadUrl { get; set; }
        public string? InstallerFileName { get; set; }
        public string? HashUrl { get; set; }
    }

    public static class UpdateManager
    {
        // Delegate for showing menu title (to avoid dependency on TUI)
        public static Action<string>? ShowMenuTitle { get; set; }

        // Check for updates and return result information
        public static async Task<UpdateCheckResult> CheckForUpdatesAsync()
        {
            // Show Update Menu
            ShowMenuTitle?.Invoke("Main Menu > Check for Updates");

            // Log the start of the update check
            Logger.AddEntry("Starting update check.", LogLevel.Info);

            // Create an HttpClient instance
            using HttpClient client = new();
            client.DefaultRequestHeaders.Add("User-Agent", "request");

            // Fetch the latest release information based on configured channel
            var releaseInfo = await FetchLatestReleaseAsync(client) 
                ?? throw new Exception("No releases found. This may be because the repository has no published releases yet, or there is a network connectivity issue.");

            // Extract the latest version from the release information
            var latestVersion = releaseInfo.TagName;
            var currentVersion = BuildInfo.Version;

            // Compare the latest version with the current version
            if (new Version(latestVersion) > new Version(currentVersion))
            {
                // Find the installer and hash assets
                string? downloadUrl = null;
                string? hashUrl = null;
                string? installerFileName = null;

                foreach (var asset in releaseInfo.Assets)
                {
                    if (asset.Name.EndsWith(".exe") || asset.Name.EndsWith(".msi"))
                    {
                        downloadUrl = asset.BrowserDownloadUrl;
                        installerFileName = asset.Name;
                    }
                    else if (asset.Name.EndsWith(".sha256"))
                    {
                        hashUrl = asset.BrowserDownloadUrl;
                    }
                }

                Logger.AddEntry($"Update available: {currentVersion} -> {latestVersion}", LogLevel.Info);

                return new UpdateCheckResult
                {
                    UpdateAvailable = true,
                    CurrentVersion = currentVersion,
                    LatestVersion = latestVersion,
                    DownloadUrl = downloadUrl,
                    InstallerFileName = installerFileName,
                    HashUrl = hashUrl
                };
            }
            else
            {
                Logger.AddEntry($"Application is up to date: {currentVersion}", LogLevel.Success);

                return new UpdateCheckResult
                {
                    UpdateAvailable = false,
                    CurrentVersion = currentVersion,
                    LatestVersion = latestVersion
                };
            }
        }

        // Download and install update
        public static async Task<string> DownloadUpdateAsync(UpdateCheckResult updateInfo)
        {
            if (!updateInfo.UpdateAvailable)
            {
                throw new InvalidOperationException("No update available to download.");
            }

            if (string.IsNullOrEmpty(updateInfo.DownloadUrl))
            {
                throw new Exception("Installer download URL not found in release assets.");
            }

            if (string.IsNullOrEmpty(updateInfo.HashUrl))
            {
                throw new Exception("Hash file not found in release assets.");
            }

            if (string.IsNullOrEmpty(updateInfo.InstallerFileName))
            {
                throw new Exception("Installer file name not found.");
            }

            using HttpClient client = new();
            client.DefaultRequestHeaders.Add("User-Agent", "request");

            // Download the hash file
            var hashContent = await client.GetStringAsync(updateInfo.HashUrl);
            var expectedHash = hashContent.Split(' ')[0];

            // Download the installer
            var downloadDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            var fileName = Path.Combine(downloadDirectory, updateInfo.InstallerFileName);

            Logger.AddEntry($"Downloading update to: {fileName}", LogLevel.Info);

            var fileBytes = await client.GetByteArrayAsync(updateInfo.DownloadUrl);
            await File.WriteAllBytesAsync(fileName, fileBytes);

            // Verify the hash
            var fileHashBytes = SHA256.HashData(fileBytes);
            var fileHash = Convert.ToHexStringLower(fileHashBytes);

            // Delete the file if the hash does not match
            if (fileHash != expectedHash)
            {
                File.Delete(fileName);
                throw new Exception("Downloaded file hash does not match the expected hash. The file has been deleted for security reasons.");
            }

            Logger.AddEntry($"Successfully downloaded and verified update: {fileName}", LogLevel.Success);
            return fileName;
        }

        // Fetch the latest release based on the configured update channel
        private static async Task<GitHubRelease?> FetchLatestReleaseAsync(HttpClient client)
        {
            var channel = Infrastructure.Configuration.SettingsManager.Settings.UpdateChannel;

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            if (channel == Infrastructure.Configuration.UpdateChannel.Stable)
            {
                // Use /releases/latest for stable releases only
                var uri = "https://api.github.com/repos/ColDog-Studios/ColDog-Locker/releases/latest";
                Logger.AddEntry("Checking for updates on Stable channel.", LogLevel.Info);
                var json = await client.GetStringAsync(uri);
                return JsonSerializer.Deserialize<GitHubRelease>(json, options);
            }
            else
            {
                // Use /releases and get the first item (most recent, including prereleases)
                var uri = "https://api.github.com/repos/ColDog-Studios/ColDog-Locker/releases";
                Logger.AddEntry("Checking for updates on Prerelease channel.", LogLevel.Info);
                var json = await client.GetStringAsync(uri);
                var releases = JsonSerializer.Deserialize<List<GitHubRelease>>(json, options);

                if (releases == null || releases.Count == 0)
                {
                    return null;
                }

                // Return the first release (most recent)
                return releases[0];
            }
        }
    }
}

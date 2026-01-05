using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
using Newtonsoft.Json;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace ColDogStudios.ColDogLocker.Application.Services
{
    public static class UpdateManager
    {

        // Delegate for showing menu title (to avoid dependency on TUI)
        public static Action<string>? ShowMenuTitle { get; set; }

        // Check for updates and prompt the user to download if a new version is available
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "Dynamic types are required for GitHub API response parsing")]
        public static async Task CheckForUpdatesAsync(bool hideUpToDateMessage)
        {
            // Show Update Menu
            ShowMenuTitle?.Invoke("Main Menu > Check for Updates");

            // Log the start of the update check
            Logger.AddEntry("Starting update check.", LogLevel.Info);

            try
            {
                // Create an HttpClient instance
                using HttpClient client = new();
                client.DefaultRequestHeaders.Add("User-Agent", "request");

                // Fetch the latest release information based on configured channel
                dynamic? releaseInfo = await FetchLatestReleaseAsync(client);

                if (releaseInfo == null)
                {
                    throw new Exception("Failed to retrieve release information.");
                }

                // Extract the latest version from the release information
                string latestVersion = releaseInfo.tag_name;

                // Display the menu title
                ShowMenuTitle?.Invoke("Main Menu > Check for Updates");

                // Compare the latest version with the current version
                if (new Version(latestVersion) > new Version(BuildInfo.Version))
                {
                    // Prompt the user to download the latest version
                    string message = $"A newer version is available:\n\n" +
                                     $"Current Version: {BuildInfo.Version}\n" +
                                     $"Latest Version: {latestVersion}\n\n" +
                                     "Do you want to download the latest version? (y/N): ";

                    Console.WriteLine(message);
                    var result = Console.ReadLine()?.ToLower();

                    if (result == "y")
                    {
                        // Find the installer and hash assets
                        string? downloadUrl = null;
                        string? hashUrl = null;
                        string? installerFileName = null;

                        foreach (var asset in releaseInfo.assets)
                        {
                            if (asset.name.EndsWith(".exe") || asset.name.EndsWith(".msi"))
                            {
                                downloadUrl = asset.browser_download_url;
                                installerFileName = asset.name;
                            }
                            else if (asset.name.EndsWith(".sha256"))
                            {
                                hashUrl = asset.browser_download_url;
                            }
                        }

                        // Verify that the installer and hash assets were found
                        if (downloadUrl == null)
                        {
                            throw new Exception("Installer asset not found.");
                        }
                        else if (hashUrl == null)
                        {
                            throw new Exception("Hash asset not found.");
                        }
                        else if (installerFileName == null)
                        {
                            throw new Exception("Installer file name not found.");
                        }

                        // Download the hash file
                        string hashContent = await client.GetStringAsync(hashUrl);
                        string expectedHash = hashContent.Split(' ')[0];

                        // Download the installer
                        string downloadDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                        string fileName = Path.Combine(downloadDirectory, installerFileName);

                        byte[] fileBytes = await client.GetByteArrayAsync(downloadUrl);
                        await File.WriteAllBytesAsync(fileName, fileBytes);

                        // Verify the hash
                        byte[] fileHashBytes = SHA256.HashData(fileBytes);
                        string fileHash = Convert.ToHexStringLower(fileHashBytes);

                        // Delete the file if the hash does not match
                        if (fileHash != expectedHash)
                        {
                            File.Delete(fileName);
                            throw new Exception("Downloaded file hash does not match the expected hash.");
                        }

                        // Log the successful download
                        Logger.AddEntry($"Downloaded the latest version to: {fileName}", LogLevel.Success);
                        Console.WriteLine($"Downloaded the latest version to: {fileName}.\nPlease run the installer to update ColDog Locker.");
                        Console.ReadLine();
                    }
                    else
                    {
                        Logger.AddEntry("User chose not to download the latest version.", LogLevel.Info);
                    }
                }
                else
                {
                    // Log and optionally display a message if the application is up to date
                    string message = $"ColDog Locker is up to date:\n\n" +
                                     $"Current Version: {BuildInfo.Version}\n" +
                                     $"Latest Version: {latestVersion}";

                    Logger.AddEntry($"Successfully checked for updates: {message}", LogLevel.Success);

                    // Hide the message if no updates are available on startup
                    if (!hideUpToDateMessage)
                    {
                        Console.WriteLine(message);
                        Console.ReadLine();
                    }
                }
            }
            catch (Exception ex)
            {
                // Log and display any errors that occur during the update check
                Logger.AddEntry($"An error occurred while checking for updates: {ex.Message}", LogLevel.Error);
                Console.WriteLine($"An error occurred while checking for updates: {ex.Message}");
                Console.ReadLine();
            }
        }

        // Fetch the latest release based on the configured update channel
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JsonConvert is needed for GitHub API deserialization")]
        private static async Task<dynamic?> FetchLatestReleaseAsync(HttpClient client)
        {
            var channel = Infrastructure.Configuration.SettingsManager.Settings.UpdateChannel;

            if (channel == Infrastructure.Configuration.UpdateChannel.Stable)
            {
                // Use /releases/latest for stable releases only
                string uri = "https://api.github.com/repos/ColDog-Studios/ColDog-Locker/releases/latest";
                Logger.AddEntry("Checking for updates on Stable channel.", LogLevel.Info);
                string json = await client.GetStringAsync(uri);
                return JsonConvert.DeserializeObject(json);
            }
            else
            {
                // Use /releases and get the first item (most recent, including prereleases)
                string uri = "https://api.github.com/repos/ColDog-Studios/ColDog-Locker/releases";
                Logger.AddEntry("Checking for updates on Prerelease channel.", LogLevel.Info);
                string json = await client.GetStringAsync(uri);
                dynamic[]? releases = JsonConvert.DeserializeObject<dynamic[]>(json);
                
                if (releases == null || releases.Length == 0)
                {
                    return null;
                }

                // Return the first release (most recent)
                return releases[0];
            }
        }
    }
}

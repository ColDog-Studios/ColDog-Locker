using System.Text.Json.Serialization;

namespace ColDogStudios.ColDogLocker.Services.Updates
{
    public class GitHubReleaseDto
    {
        [JsonPropertyName("tag_name")] public string TagName { get; set; } = string.Empty;

        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;

        [JsonPropertyName("body")] public string Body { get; set; } = string.Empty;

        [JsonPropertyName("html_url")] public string HtmlUrl { get; set; } = string.Empty;

        [JsonPropertyName("draft")] public bool Draft { get; set; }

        [JsonPropertyName("prerelease")] public bool Prerelease { get; set; }

        [JsonPropertyName("assets")] public List<GitHubAsset> Assets { get; set; } = [];
    }

    public class GitHubAsset
    {
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;

        [JsonPropertyName("browser_download_url")]
        public string BrowserDownloadUrl { get; set; } = string.Empty;

        [JsonPropertyName("digest")] public string? Digest { get; set; }

        [JsonPropertyName("size")] public long Size { get; set; }

        [JsonPropertyName("content_type")] public string ContentType { get; set; } = string.Empty;
    }
}

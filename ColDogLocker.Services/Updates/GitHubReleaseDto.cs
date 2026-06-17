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

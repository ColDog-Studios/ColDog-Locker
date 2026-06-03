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

using System.Text.Json;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Services.Tests.Updates
{
    public class GitHubReleaseDtoTests
    {
        [Fact]
        public void DefaultValues_ShouldBeNonNullAndEmpty()
        {
            var release = new GitHubReleaseDto();
            var asset = new GitHubAsset();

            Assert.Equal(string.Empty, release.TagName);
            Assert.Equal(string.Empty, release.Name);
            Assert.Equal(string.Empty, release.Body);
            Assert.Equal(string.Empty, release.HtmlUrl);
            Assert.False(release.Draft);
            Assert.False(release.Prerelease);
            Assert.NotNull(release.Assets);
            Assert.Empty(release.Assets);
            Assert.Equal(string.Empty, asset.Name);
            Assert.Equal(string.Empty, asset.BrowserDownloadUrl);
            Assert.Null(asset.Digest);
            Assert.Equal(0, asset.Size);
            Assert.Equal(string.Empty, asset.ContentType);
        }

        [Fact]
        public void Deserialize_ShouldMapGitHubJsonPropertyNames()
        {
            const string json = """
                {
                  "tag_name": "v1.2.3",
                  "name": "Release 1.2.3",
                  "body": "Release notes",
                  "html_url": "https://github.example/releases/v1.2.3",
                  "draft": false,
                  "prerelease": true,
                  "assets": [
                    {
                      "name": "cdlocker-linux-x64.tar.gz",
                      "browser_download_url": "https://github.example/download",
                      "digest": "sha256:abcdef",
                      "size": 4096,
                      "content_type": "application/gzip"
                    }
                  ]
                }
                """;

            var release = JsonSerializer.Deserialize<GitHubReleaseDto>(json);

            Assert.NotNull(release);
            Assert.Equal("v1.2.3", release.TagName);
            Assert.Equal("Release 1.2.3", release.Name);
            Assert.Equal("Release notes", release.Body);
            Assert.Equal("https://github.example/releases/v1.2.3", release.HtmlUrl);
            Assert.False(release.Draft);
            Assert.True(release.Prerelease);

            var asset = Assert.Single(release.Assets);
            Assert.Equal("cdlocker-linux-x64.tar.gz", asset.Name);
            Assert.Equal("https://github.example/download", asset.BrowserDownloadUrl);
            Assert.Equal("sha256:abcdef", asset.Digest);
            Assert.Equal(4096, asset.Size);
            Assert.Equal("application/gzip", asset.ContentType);
        }

        [Fact]
        public void Deserialize_ShouldAllowMissingNullableDigest()
        {
            const string json = """
                {
                  "assets": [
                    {
                      "name": "cdlocker.exe",
                      "browser_download_url": "https://github.example/download",
                      "size": 1024,
                      "content_type": "application/octet-stream"
                    }
                  ]
                }
                """;

            var release = JsonSerializer.Deserialize<GitHubReleaseDto>(json);

            Assert.NotNull(release);
            var asset = Assert.Single(release.Assets);
            Assert.Null(asset.Digest);
        }
    }
}

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

namespace ColDogStudios.ColDogLocker.Core.Environment
{
    /// <summary>Uses the same validated inventory that ships with the installers.</summary>
    public static class ThirdPartyAcknowledgements
    {
        public static string Text { get; } = Load();

        private static string Load()
        {
            using var stream = typeof(ThirdPartyAcknowledgements).Assembly.GetManifestResourceStream("ThirdPartyComponents.json")
                               ?? throw new InvalidOperationException("The third-party component inventory is missing.");
            using var document = JsonDocument.Parse(stream);
            var entries = document.RootElement.GetProperty("components").EnumerateArray()
                .Where(component => component.GetProperty("scope").GetString() != "build")
                .Select(component => $"{component.GetProperty("name").GetString()} {component.GetProperty("version").GetString()} — {component.GetProperty("license").GetString()}")
                .Append(".NET — MIT; bundled runtime notices are included with the package")
                .Append("Inter font — OFL-1.1; The Inter Project Authors")
                .Append("Material Design icon data — Apache-2.0; Material Design Icons contributors")
                .OrderBy(entry => entry, StringComparer.OrdinalIgnoreCase);
            return string.Join("\n\n", entries) + "\n\nSee THIRD-PARTY-NOTICES.md and DOTNET-THIRD-PARTY-NOTICES.txt in the installation directory for copyright and license notices.";
        }
    }
}

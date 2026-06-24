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

namespace ColDogStudios.ColDogLocker.Core.Versioning
{
    public class SemanticVersion : IComparable<SemanticVersion>, IEquatable<SemanticVersion>
    {
        private readonly string[]? _preReleaseParts; // Cache parsed prerelease identifiers

        /// <summary>
        ///     Initializes a new instance of the SemanticVersion class by parsing a version string.
        /// </summary>
        /// <param name="version">The version string to parse (e.g., "1.2.3-alpha")</param>
        /// <exception cref="FormatException">Thrown if the version string is invalid or in an incorrect format.</exception>
        public SemanticVersion(string version)
        {
            if (string.IsNullOrWhiteSpace(version))
            {
                throw new FormatException("Version cannot be null or empty.");
            }

            if (!TryParse(version, out var parsed))
            {
                throw new FormatException($"Invalid semantic version format: {version}");
            }

            Major = parsed.Major;
            Minor = parsed.Minor;
            Patch = parsed.Patch;
            PreRelease = parsed.PreRelease;
            _preReleaseParts = parsed._preReleaseParts;
        }

        /// <summary>
        ///     Private constructor used by TryParse to create validated SemanticVersion instances.
        /// </summary>
        private SemanticVersion(int major, int minor, int patch, string? preRelease, string[]? preReleaseParts)
        {
            Major = major;
            Minor = minor;
            Patch = patch;
            PreRelease = preRelease;
            _preReleaseParts = preReleaseParts;
        }

        public int Major { get; }
        public int Minor { get; }
        public int Patch { get; }
        public string? PreRelease { get; }

        /// <summary>
        ///     Compares this instance to another SemanticVersion instance. Returns a positive number if this instance is greater,
        ///     negative if less, and zero if equal.
        /// </summary>
        /// <param name="other">The SemanticVersion instance to compare against.</param>
        /// <returns>A positive number if this instance is greater; negative if less; zero if equal.</returns>
        public int CompareTo(SemanticVersion? other)
        {
            if (other is null)
            {
                return 1;
            }

            // Compare major.minor.patch
            if (Major != other.Major)
            {
                return Major.CompareTo(other.Major);
            }

            if (Minor != other.Minor)
            {
                return Minor.CompareTo(other.Minor);
            }

            if (Patch != other.Patch)
            {
                return Patch.CompareTo(other.Patch);
            }

            // Handle prerelease: stable > prerelease
            if (PreRelease == null && other.PreRelease != null)
            {
                return 1;
            }

            if (PreRelease != null && other.PreRelease == null)
            {
                return -1;
            }

            if (PreRelease == null && other.PreRelease == null)
            {
                return 0;
            }

            // Compare prerelease identifiers per semver spec
            var thisParts = _preReleaseParts!;
            var otherParts = other._preReleaseParts!;

            var minLength = Math.Min(thisParts.Length, otherParts.Length);
            for (var i = 0; i < minLength; i++)
            {
                var thisIsNumeric = int.TryParse(thisParts[i], out var thisNum);
                var otherIsNumeric = int.TryParse(otherParts[i], out var otherNum);

                // Numeric identifiers are compared as integers
                if (thisIsNumeric && otherIsNumeric)
                {
                    var numCompare = thisNum.CompareTo(otherNum);
                    if (numCompare != 0)
                    {
                        return numCompare;
                    }
                }
                // Numeric < Non-numeric
                else if (thisIsNumeric)
                {
                    return -1;
                }
                else if (otherIsNumeric)
                {
                    return 1;
                }
                // Both non-numeric, compare lexically
                else
                {
                    var lexCompare = string.Compare(thisParts[i], otherParts[i], StringComparison.Ordinal);
                    if (lexCompare != 0)
                    {
                        return lexCompare;
                    }
                }
            }

            // Longer prerelease list > shorter (if all preceding are equal)
            return thisParts.Length.CompareTo(otherParts.Length);
        }

        public bool Equals(SemanticVersion? other)
        {
            return other is not null && CompareTo(other) == 0;
        }

        /// <summary>
        ///     Tries to parse a version string into a SemanticVersion instance. Returns true if successful, false otherwise.
        /// </summary>
        /// <param name="version">The version string to parse.</param>
        /// <param name="result">The resulting SemanticVersion instance if parsing succeeds; null otherwise.</param>
        /// <returns>True if parsing succeeds; false otherwise.</returns>
        public static bool TryParse(string version, out SemanticVersion result)
        {
            result = null!;

            if (string.IsNullOrWhiteSpace(version))
            {
                return false;
            }

            try
            {
                var versionWithoutBuildMetadata = version.Split('+', 2)[0];
                var mainAndPre = versionWithoutBuildMetadata.Split('-', 2);
                var mainParts = mainAndPre[0].Split('.');

                if (mainParts.Length != 3)
                {
                    return false;
                }

                if (!int.TryParse(mainParts[0], out var major) ||
                    !int.TryParse(mainParts[1], out var minor) ||
                    !int.TryParse(mainParts[2], out var patch) ||
                    major < 0 || minor < 0 || patch < 0)
                {
                    return false;
                }

                var preRelease = mainAndPre.Length > 1 ? mainAndPre[1] : null;

                // Validate prerelease format if present
                if (preRelease != null && string.IsNullOrWhiteSpace(preRelease))
                {
                    return false;
                }

                var preReleaseParts = preRelease?.Split('.');
                if (preReleaseParts?.Any(part => part.Length > 1 && part[0] == '0' && char.IsDigit(part[1])) == true)
                {
                    return false;
                }

                result = new SemanticVersion(major, minor, patch, preRelease, preReleaseParts);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public override bool Equals(object? obj)
        {
            return obj is SemanticVersion other && Equals(other);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Major, Minor, Patch, PreRelease);
        }

        public override string ToString()
        {
            return PreRelease != null ? $"{Major}.{Minor}.{Patch}-{PreRelease}" : $"{Major}.{Minor}.{Patch}";
        }

        public static bool operator >(SemanticVersion? v1, SemanticVersion? v2)
        {
            return v1 is not null && v1.CompareTo(v2) > 0;
        }

        public static bool operator <(SemanticVersion? v1, SemanticVersion? v2)
        {
            return v2 is not null && (v1 is null || v1.CompareTo(v2) < 0);
        }

        public static bool operator >=(SemanticVersion? v1, SemanticVersion? v2)
        {
            return v1 is null ? v2 is null : v1.CompareTo(v2) >= 0;
        }

        public static bool operator <=(SemanticVersion? v1, SemanticVersion? v2)
        {
            return v1 is null || v1.CompareTo(v2) <= 0;
        }

        public static bool operator ==(SemanticVersion? v1, SemanticVersion? v2)
        {
            return ReferenceEquals(v1, v2) || (v1 is not null && v2 is not null && v1.Equals(v2));
        }

        public static bool operator !=(SemanticVersion? v1, SemanticVersion? v2)
        {
            return !(v1 == v2);
        }
    }
}

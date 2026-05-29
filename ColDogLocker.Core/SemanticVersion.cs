/*
** SemanticVersion.cs
** Copyright (C) 2026 ColDog Studios
*/

namespace ColDogStudios.ColDogLocker.Core
{
    public class SemanticVersion : IComparable<SemanticVersion>, IEquatable<SemanticVersion>
    {
        public int Major { get; set; }
        public int Minor { get; set; }
        public int Patch { get; set; }
        public string? PreRelease { get; set; }
        private string[]? _preReleaseParts; // Cache parsed prerelease identifiers

        /// <summary>
        ///     Initializes a new instance of the SemanticVersion class by parsing a version string.
        /// </summary>
        /// <param name="version"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="FormatException"></exception>
        public SemanticVersion(string version)
        {
            if (string.IsNullOrWhiteSpace(version))
            {
                throw new ArgumentException("Version cannot be null or empty.", nameof(version));
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
        ///     Tries to parse a version string into a SemanticVersion instance. Returns true if successful, false otherwise.
        /// </summary>
        /// <param name="version"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static bool TryParse(string version, out SemanticVersion result)
        {
            result = null!;

            if (string.IsNullOrWhiteSpace(version))
            {
                return false;
            }

            try
            {
                var mainAndPre = version.Split('-', 2);
                var mainParts = mainAndPre[0].Split('.');

                if (mainParts.Length != 3)
                {
                    return false;
                }

                if (!int.TryParse(mainParts[0], out int major) ||
                    !int.TryParse(mainParts[1], out int minor) ||
                    !int.TryParse(mainParts[2], out int patch) ||
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

                var instance = new SemanticVersion
                {
                    Major = major,
                    Minor = minor,
                    Patch = patch,
                    PreRelease = preRelease,
                    _preReleaseParts = preRelease?.Split('.') // Cache split parts
                };

                result = instance;
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        ///    Compares this instance to another SemanticVersion instance. Returns a positive number if this instance is greater, negative if less, and zero if equal.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public int CompareTo(SemanticVersion? other)
        {
            if (other == null)
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

            int minLength = Math.Min(thisParts.Length, otherParts.Length);
            for (int i = 0; i < minLength; i++)
            {
                bool thisIsNumeric = int.TryParse(thisParts[i], out int thisNum);
                bool otherIsNumeric = int.TryParse(otherParts[i], out int otherNum);

                // Numeric identifiers are compared as integers
                if (thisIsNumeric && otherIsNumeric)
                {
                    int numCompare = thisNum.CompareTo(otherNum);
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
                    int lexCompare = string.Compare(thisParts[i], otherParts[i], StringComparison.Ordinal);
                    if (lexCompare != 0)
                    {
                        return lexCompare;
                    }
                }
            }

            // Longer prerelease list > shorter (if all preceding are equal)
            return thisParts.Length.CompareTo(otherParts.Length);
        }

        public bool Equals(SemanticVersion? other) => other != null && CompareTo(other) == 0;
        public override bool Equals(object? obj) => obj is SemanticVersion other && Equals(other);
        public override int GetHashCode() => HashCode.Combine(Major, Minor, Patch, PreRelease);

        public override string ToString()
        {
            return PreRelease != null ? $"{Major}.{Minor}.{Patch}-{PreRelease}" : $"{Major}.{Minor}.{Patch}";
        }

        public static bool operator >(SemanticVersion v1, SemanticVersion v2) => v1.CompareTo(v2) > 0;
        public static bool operator <(SemanticVersion v1, SemanticVersion v2) => v1.CompareTo(v2) < 0;
        public static bool operator >=(SemanticVersion v1, SemanticVersion v2) => v1.CompareTo(v2) >= 0;
        public static bool operator <=(SemanticVersion v1, SemanticVersion v2) => v1.CompareTo(v2) <= 0;
        public static bool operator ==(SemanticVersion v1, SemanticVersion v2) => v1.Equals(v2);
        public static bool operator !=(SemanticVersion v1, SemanticVersion v2) => !v1.Equals(v2);

        // Private constructor for TryParse
        private SemanticVersion() { }
    }
}
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

using System.Text.RegularExpressions;

namespace ColDogStudios.ColDogLocker.Core.Validation
{
    public class PasswordRequirement
    {
        public string Description { get; set; } = string.Empty;
        public bool IsMet { get; set; }
    }

    public partial class PasswordFilter
    {
        private static readonly string[] _commonWords =
        [
            "password",
            "admin",
            "locker",
            "root",
            "secret",
            "welcome",
            "letmein",
            "monkey",
            "football",
            "baseball",
            "basketball",
            "master",
            "user",
            "test",
            "guest"
        ];

        [GeneratedRegex(
            "(?:0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210|qwer|wert|erty|rtyu|tyui|yuio|uiop|poiu|oiuy|iuyt|uytr|ytre|trew|rewq|asdf|sdfg|dfgh|fghj|ghjk|hjkl|lkjh|kjhg|jhgf|hgfd|gfds|fdsa|zxcv|xcvb|cvbn|vbnm|mnbv|nbvc|bvcx|vcxz|qazwsx|xswzaq|1q2w3e|1qaz2wsx)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
        private static partial Regex CommonPatternRegex();

        private static readonly List<Func<string, bool>> _securityRules =
        [
            password => password.Length >= 12,
            password => password.Any(char.IsUpper),
            password => password.Any(char.IsLower),
            password => password.Any(char.IsDigit),
            password => password.Any(ch => !char.IsLetterOrDigit(ch))
        ];

        private static readonly List<string> _securityMessages =
        [
            "At least 12 characters",
            "At least one uppercase letter",
            "At least one lowercase letter",
            "At least one digit",
            "At least one special character"
        ];

        /// <summary>
        ///     Gets a list of all password requirements with their current status.
        ///     Useful for displaying dynamic password requirement indicators in UI.
        /// </summary>
        public static List<PasswordRequirement>
            Validate(string password)
        {
            var requirements = new List<PasswordRequirement>();

            if (string.IsNullOrEmpty(password))
            {
                password = string.Empty;
            }

            // Check each security rule
            for (var i = 0; i < _securityRules.Count; i++)
            {
                requirements.Add(new PasswordRequirement { Description = _securityMessages[i], IsMet = _securityRules[i](password) });
            }

            // Check common words
            var hasCommonWord = false;
            foreach (var commonWord in _commonWords)
            {
                if (password.Contains(commonWord, StringComparison.OrdinalIgnoreCase))
                {
                    hasCommonWord = true;
                    break;
                }
            }

            hasCommonWord |= CommonPatternRegex().IsMatch(password);

            requirements.Add(new PasswordRequirement { Description = "No common words", IsMet = !hasCommonWord });

            return requirements;
        }

        /// <summary>
        ///     Validates a password against all security and common word checks.
        ///     Returns null if valid, otherwise returns the first validation error message.
        /// </summary>
        public static string? ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return "Password cannot be null or empty.";
            }

            // Check security rules
            for (var i = 0; i < _securityRules.Count; i++)
            {
                if (!_securityRules[i](password))
                {
                    return _securityMessages[i];
                }
            }

            // Check common words
            foreach (var commonWord in _commonWords)
            {
                if (password.Contains(commonWord, StringComparison.OrdinalIgnoreCase))
                {
                    return $"'{commonWord}' is considered a common word. Please enter a new password.";
                }
            }


            var commonPattern = CommonPatternRegex().Match(password);
            if (commonPattern.Success)
            {
                return $"'{commonPattern.Value}' is considered a common word pattern. Please enter a new password.";
            }

            return null; // Valid password
        }
    }
}

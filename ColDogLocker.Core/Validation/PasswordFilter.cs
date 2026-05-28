namespace ColDogStudios.ColDogLocker.Core.Validation
{
    public class PasswordRequirement
    {
        public string Description { get; set; } = string.Empty;
        public bool IsMet { get; set; }
    }

    public class PasswordFilter
    {
        // TODO: Probably change this to use a short list and use pattern matching to catch more variations
        private static readonly string[] _commonWords =
        [
            "password",
            "admin",
            "locker",
            "root",
            "secret",
            "123456",
            "qwerty",
            "letmein",
            "monkey",
            "abc123",
            "football",
            "baseball",
            "basketball",
            "master",
            "123456789",
            "12345678",
            "12345",
            "1234",
            "1234567",
            "1234567890",
            "user",
            "test",
            "guest",
            "adfghjk",
            "zxcvbnm",
            "asdfghjkl",
            "qazwsx",
            "1q2w3e4r",
            "1qaz2wsx"
        ];

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
            GetPasswordRequirements(string password) // TODO: change function name to Validate so calling is PasswordFilter.Validate(password)
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

            return null; // Valid password
        }
    }
}

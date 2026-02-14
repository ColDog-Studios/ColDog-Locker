namespace ColDogStudios.ColDogLocker.Application.Validation
{
    public class PasswordFilter
    {
        private static readonly List<Func<string, bool>> _securityRules =
        [
            password => password.Length >= 10,
            password => password.Any(char.IsUpper),
            password => password.Any(char.IsLower),
            password => password.Any(char.IsDigit),
            password => password.Any(ch => !char.IsLetterOrDigit(ch))
        ];

        private static readonly List<string> _securityMessages =
        [
            "Password must be at least 10 characters long.",
            "Password must contain at least one uppercase letter.",
            "Password must contain at least one lowercase letter.",
            "Password must contain at least one digit.",
            "Password must contain at least one special character."
        ];

        public static void SecurityCheck(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.");
            }

            for (var i = 0; i < _securityRules.Count; i++)
            {
                if (!_securityRules[i](password))
                {
                    throw new Exception(_securityMessages[i]);
                }
            }
        }

        public static void IllegalWordCheck(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.");
            }

            // List of illegal words
            string[] illegalWords =
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
                "iloveyou",
                "welcome"
            ];

            // Check if password contains any illegal words (case-insensitive)
            foreach (var illegalWord in illegalWords)
            {
                if (password.Contains(illegalWord, StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception($"'{illegalWord}' is considered a common word. Please enter a new password.");
                }
            }
        }
    }
}

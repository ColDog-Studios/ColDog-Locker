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

using System.Security.Cryptography;
using System.Text;

namespace ColDogStudios.ColDogLocker.Services.Security
{
    public static class EncryptionHelper
    {
        private const int SaltSize = 16;
        private const int KeySize = 32;
        private const int PasswordVerifierIterations = 600000;
        private const string PasswordVerifierPrefix = "$cdl-pbkdf2-sha256$v1$";
        private static readonly UTF8Encoding _passwordEncoding = new(false, true);

        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var passwordBytes = _passwordEncoding.GetBytes(password);
            try
            {
                var verifier = Rfc2898DeriveBytes.Pbkdf2(
                    passwordBytes,
                    salt,
                    PasswordVerifierIterations,
                    HashAlgorithmName.SHA256,
                    KeySize);
                try
                {
                    return $"{PasswordVerifierPrefix}{PasswordVerifierIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(verifier)}";
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(verifier);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        public static bool VerifyPassword(string password, string hash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            {
                return false;
            }

            var parts = hash.Split('$');
            if (parts.Length != 6 || !hash.StartsWith(PasswordVerifierPrefix, StringComparison.Ordinal) ||
                parts[3] != PasswordVerifierIterations.ToString(System.Globalization.CultureInfo.InvariantCulture))
            {
                throw new InvalidDataException("Unsupported password verifier format.");
            }

            byte[] salt;
            byte[] expected;
            try
            {
                salt = Convert.FromBase64String(parts[4]);
                expected = Convert.FromBase64String(parts[5]);
            }
            catch (FormatException ex)
            {
                throw new InvalidDataException("Password verifier contains invalid base64 data.", ex);
            }

            if (salt.Length != SaltSize || expected.Length != KeySize)
            {
                throw new InvalidDataException("Invalid password verifier length.");
            }

            var passwordBytes = _passwordEncoding.GetBytes(password);
            try
            {
                var actual = Rfc2898DeriveBytes.Pbkdf2(
                    passwordBytes,
                    salt,
                    PasswordVerifierIterations,
                    HashAlgorithmName.SHA256,
                    KeySize);
                try
                {
                    return CryptographicOperations.FixedTimeEquals(actual, expected);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(actual);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
                CryptographicOperations.ZeroMemory(salt);
                CryptographicOperations.ZeroMemory(expected);
            }
        }
    }
}

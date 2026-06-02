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

namespace ColDogStudios.ColDogLocker.Services.Security
{
    public static class EncryptionHelper
    {
        private const int BufferSize = 81920; // 80KB buffer
        private const int SaltSize = 16; // 16 bytes for salt

        // Encrypt all files and subdirectories in a directory
        public static void EncryptDirectory(string directory, string password)
        {
            // Encrypt each file in the directory
            foreach (var file in Directory.GetFiles(directory))
            {
                EncryptFile(file, password);
            }

            // Recursively encrypt each subdirectory
            foreach (var subDirectory in Directory.GetDirectories(directory))
            {
                EncryptDirectory(subDirectory, password);
            }
        }

        // Encrypt a single file
        public static void EncryptFile(string inputFile, string password)
        {
            if (string.IsNullOrEmpty(inputFile))
            {
                throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFile));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException($"Input file not found: {inputFile}");
            }

            // Create AES encryption object
            using var aes = Aes.Create();

            // Generate a random salt for this file
            var salt = new byte[SaltSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            // Generate key and IV from password using the random salt
            var keyAndIv = Rfc2898DeriveBytes.Pbkdf2(password, salt, 10000, HashAlgorithmName.SHA256, 48);
            aes.Key = keyAndIv[..32];
            aes.IV = keyAndIv[32..];

            // Open input file and create encrypted output file
            using FileStream fsIn = new(inputFile, FileMode.Open);
            using FileStream fsCrypt = new(inputFile + ".enc", FileMode.Create);
            // Write the salt at the beginning of the encrypted file
            fsCrypt.Write(salt, 0, salt.Length);

            using CryptoStream cs = new(fsCrypt, aes.CreateEncryptor(), CryptoStreamMode.Write);
            var buffer = new byte[BufferSize];
            int read;

            // Read from input file and write encrypted data to output file
            while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
            {
                cs.Write(buffer, 0, read);
            }

            // Replace original file with encrypted file
            File.Delete(inputFile);
            File.Move(inputFile + ".enc", inputFile);
        }

        // Decrypt all files and subdirectories in a directory
        public static void DecryptDirectory(string directory, string password)
        {
            // Decrypt each file in the directory
            foreach (var file in Directory.GetFiles(directory))
            {
                DecryptFile(file, password);
            }

            // Recursively decrypt each subdirectory
            foreach (var subDirectory in Directory.GetDirectories(directory))
            {
                DecryptDirectory(subDirectory, password);
            }
        }

        // Decrypt a single file
        public static void DecryptFile(string inputFile, string password)
        {
            if (string.IsNullOrEmpty(inputFile))
            {
                throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFile));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException($"Input file not found: {inputFile}");
            }

            // Create AES decryption object
            using var aes = Aes.Create();

            // Open encrypted input file and read the salt
            using FileStream fsCrypt = new(inputFile, FileMode.Open);
            // Verify file is large enough to contain salt
            if (fsCrypt.Length < SaltSize)
            {
                throw new InvalidDataException("File is too small to contain encryption data.");
            }

            // Read the salt from the beginning of the file
            var salt = new byte[SaltSize];
            var bytesRead = fsCrypt.Read(salt, 0, salt.Length);
            if (bytesRead != SaltSize)
            {
                throw new InvalidDataException("Unable to read salt from encrypted file.");
            }

            // Generate key and IV from password using the stored salt
            var keyAndIv = Rfc2898DeriveBytes.Pbkdf2(password, salt, 10000, HashAlgorithmName.SHA256, 48);
            aes.Key = keyAndIv[..32];
            aes.IV = keyAndIv[32..];

            using CryptoStream cs = new(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using FileStream fsOut = new(inputFile + ".dec", FileMode.Create);
            var buffer = new byte[BufferSize];
            int read;

            // Read from encrypted file and write decrypted data to output file
            while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
            {
                fsOut.Write(buffer, 0, read);
            }

            // Replace encrypted file with decrypted file
            File.Delete(inputFile);
            File.Move(inputFile + ".dec", inputFile);
        }

        // Improved password hashing using bcrypt
        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

            // Cost factor of 14 provides enhanced security vs performance trade-off
            return BCrypt.Net.BCrypt.HashPassword(password, 14); // 12-13 recommended
        }

        // Method to verify password against hash
        public static bool VerifyPassword(string password, string hash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            {
                return false;
            }

            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
    }
}

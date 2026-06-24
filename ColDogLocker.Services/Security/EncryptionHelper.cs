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

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Services.Security
{
    public static class EncryptionHelper
    {
        private const int BufferSize = 81920; // 80KB buffer
        private const int SaltSize = 16; // 16 bytes for salt
        private const int NoncePrefixSize = 8;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;
        private const int Pbkdf2Iterations = 210000;
        private static readonly byte[] _magic = Encoding.ASCII.GetBytes("CDLENC");

        // Encrypt all files and subdirectories in a directory
        public static void EncryptDirectory(string directory, string password)
        {
            var encryptedFiles = new List<string>();
            var encryptedDirectories = new List<string>();

            try
            {
                // Encrypt each file in the directory
                foreach (var file in Directory.GetFiles(directory))
                {
                    EncryptFile(file, password);
                    encryptedFiles.Add(file);
                }

                // Recursively encrypt each subdirectory
                foreach (var subDirectory in Directory.GetDirectories(directory))
                {
                    EncryptDirectory(subDirectory, password);
                    encryptedDirectories.Add(subDirectory);
                }
            }
            catch
            {
                RollBackEncryptedFiles(encryptedFiles, encryptedDirectories, password);
                throw;
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

            // Generate a random salt for this file
            var salt = new byte[SaltSize];
            var noncePrefix = new byte[NoncePrefixSize];
            RandomNumberGenerator.Fill(salt);
            RandomNumberGenerator.Fill(noncePrefix);

            // Generate key from password using the random salt
            var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);

            var encryptedFile = CreateTempPath(inputFile, ".enc");

            try
            {
                // Open input file and create encrypted output file
                using (FileStream fsIn = new(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (FileStream fsCrypt = new(encryptedFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    WriteHeader(fsCrypt, salt, noncePrefix, fsIn.Length);

                    using var aes = new AesGcm(key, TagSize);
                    var plainBuffer = new byte[BufferSize];
                    var cipherBuffer = new byte[BufferSize];
                    var tag = new byte[TagSize];
                    var chunkIndex = 0;
                    int read;

                    while ((read = fsIn.Read(plainBuffer, 0, plainBuffer.Length)) > 0)
                    {
                        var nonce = CreateNonce(noncePrefix, chunkIndex);
                        var aad = CreateAad(fsIn.Length, chunkIndex, read);
                        aes.Encrypt(nonce, plainBuffer.AsSpan(0, read), cipherBuffer.AsSpan(0, read), tag, aad);
                        WriteChunk(fsCrypt, read, tag, cipherBuffer.AsSpan(0, read));
                        chunkIndex++;
                    }
                }

                ReplaceFile(encryptedFile, inputFile);
            }
            catch
            {
                TryDeleteFile(encryptedFile);
                throw;
            }
        }

        // Decrypt all files and subdirectories in a directory
        public static void DecryptDirectory(string directory, string password)
        {
            var decryptedFiles = new List<string>();
            var decryptedDirectories = new List<string>();

            try
            {
                // Decrypt each file in the directory
                foreach (var file in Directory.GetFiles(directory))
                {
                    DecryptFile(file, password);
                    decryptedFiles.Add(file);
                }

                // Recursively decrypt each subdirectory
                foreach (var subDirectory in Directory.GetDirectories(directory))
                {
                    DecryptDirectory(subDirectory, password);
                    decryptedDirectories.Add(subDirectory);
                }
            }
            catch
            {
                RollBackDecryptedFiles(decryptedFiles, decryptedDirectories, password);
                throw;
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

            var decryptedFile = CreateTempPath(inputFile, ".dec");

            try
            {
                // Open encrypted input file and read the authenticated header
                using (FileStream fsCrypt = new(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (FileStream fsOut = new(decryptedFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var header = ReadHeader(fsCrypt);
                    var key = Rfc2898DeriveBytes.Pbkdf2(password, header.Salt, header.Iterations, HashAlgorithmName.SHA256, KeySize);

                    using var aes = new AesGcm(key, TagSize);
                    var tag = new byte[TagSize];
                    var cipherBuffer = new byte[BufferSize];
                    var plainBuffer = new byte[BufferSize];
                    var chunkIndex = 0;
                    long bytesWritten = 0;

                    while (fsCrypt.Position < fsCrypt.Length)
                    {
                        var chunkLength = ReadChunkLength(fsCrypt);
                        if (chunkLength <= 0 || chunkLength > BufferSize)
                        {
                            throw new InvalidDataException("Encrypted file contains an invalid chunk length.");
                        }

                        if (bytesWritten + chunkLength > header.OriginalLength)
                        {
                            throw new InvalidDataException("Encrypted file contains more data than expected.");
                        }

                        ReadExactly(fsCrypt, tag);
                        ReadExactly(fsCrypt, cipherBuffer.AsSpan(0, chunkLength));

                        var nonce = CreateNonce(header.NoncePrefix, chunkIndex);
                        var aad = CreateAad(header.OriginalLength, chunkIndex, chunkLength);
                        aes.Decrypt(nonce, cipherBuffer.AsSpan(0, chunkLength), tag, plainBuffer.AsSpan(0, chunkLength), aad);
                        fsOut.Write(plainBuffer, 0, chunkLength);

                        bytesWritten += chunkLength;
                        chunkIndex++;
                    }

                    if (bytesWritten != header.OriginalLength)
                    {
                        throw new InvalidDataException("Encrypted file ended before all expected data was read.");
                    }
                }

                ReplaceFile(decryptedFile, inputFile);
            }
            catch
            {
                TryDeleteFile(decryptedFile);
                throw;
            }
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

        private static void WriteHeader(Stream stream, byte[] salt, byte[] noncePrefix, long originalLength)
        {
            stream.Write(_magic);
            stream.Write(salt);
            stream.Write(noncePrefix);

            Span<byte> numberBuffer = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(numberBuffer, originalLength);
            stream.Write(numberBuffer);

            numberBuffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(numberBuffer, Pbkdf2Iterations);
            stream.Write(numberBuffer);
        }

        private static EncryptedFileHeader ReadHeader(Stream stream)
        {
            var magic = new byte[_magic.Length];
            ReadExactly(stream, magic);
            if (!magic.SequenceEqual(_magic))
            {
                throw new InvalidDataException("File is not a supported ColDog Locker encrypted file.");
            }

            var salt = new byte[SaltSize];
            var noncePrefix = new byte[NoncePrefixSize];
            ReadExactly(stream, salt);
            ReadExactly(stream, noncePrefix);

            Span<byte> numberBuffer = stackalloc byte[8];
            ReadExactly(stream, numberBuffer);
            var originalLength = BinaryPrimitives.ReadInt64LittleEndian(numberBuffer);
            if (originalLength < 0)
            {
                throw new InvalidDataException("Encrypted file contains an invalid original length.");
            }

            numberBuffer = stackalloc byte[4];
            ReadExactly(stream, numberBuffer);
            var iterations = BinaryPrimitives.ReadInt32LittleEndian(numberBuffer);
            if (iterations <= 0)
            {
                throw new InvalidDataException("Encrypted file contains an invalid key derivation setting.");
            }

            return new EncryptedFileHeader(salt, noncePrefix, originalLength, iterations);
        }

        private static void WriteChunk(Stream stream, int plaintextLength, byte[] tag, ReadOnlySpan<byte> ciphertext)
        {
            Span<byte> lengthBuffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(lengthBuffer, plaintextLength);
            stream.Write(lengthBuffer);
            stream.Write(tag);
            stream.Write(ciphertext);
        }

        private static int ReadChunkLength(Stream stream)
        {
            Span<byte> lengthBuffer = stackalloc byte[4];
            ReadExactly(stream, lengthBuffer);
            return BinaryPrimitives.ReadInt32LittleEndian(lengthBuffer);
        }

        private static byte[] CreateNonce(byte[] noncePrefix, int chunkIndex)
        {
            var nonce = new byte[NonceSize];
            noncePrefix.CopyTo(nonce, 0);
            BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(NoncePrefixSize), chunkIndex);
            return nonce;
        }

        private static byte[] CreateAad(long originalLength, int chunkIndex, int plaintextLength)
        {
            var aad = new byte[_magic.Length + 8 + 4 + 4];
            _magic.CopyTo(aad, 0);
            BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(_magic.Length), originalLength);
            BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(_magic.Length + 8), chunkIndex);
            BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(_magic.Length + 12), plaintextLength);
            return aad;
        }

        private static void ReadExactly(Stream stream, Span<byte> buffer)
        {
            var totalRead = 0;
            while (totalRead < buffer.Length)
            {
                var read = stream.Read(buffer[totalRead..]);
                if (read == 0)
                {
                    throw new EndOfStreamException("Encrypted file ended unexpectedly.");
                }

                totalRead += read;
            }
        }

        private static string CreateTempPath(string inputFile, string suffix)
        {
            var directory = Path.GetDirectoryName(inputFile) ?? Directory.GetCurrentDirectory();
            var fileName = Path.GetFileName(inputFile);
            return Path.Join(directory, $".{fileName}.{Guid.NewGuid():N}{suffix}.tmp");
        }

        private static void ReplaceFile(string sourceFile, string destinationFile)
        {
            try
            {
                File.Replace(sourceFile, destinationFile, null, true);
            }
            catch (PlatformNotSupportedException)
            {
                File.Move(sourceFile, destinationFile, true);
            }
        }

        private static void TryDeleteFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // A failed temp-file cleanup should not hide the original encryption error.
            }
        }

        private static void RollBackEncryptedFiles(
            IReadOnlyList<string> encryptedFiles,
            IReadOnlyList<string> encryptedDirectories,
            string password)
        {
            foreach (var directory in encryptedDirectories.Reverse())
            {
                TryDecryptDirectory(directory, password);
            }

            foreach (var file in encryptedFiles.Reverse())
            {
                TryDecryptFile(file, password);
            }
        }

        private static void RollBackDecryptedFiles(
            IReadOnlyList<string> decryptedFiles,
            IReadOnlyList<string> decryptedDirectories,
            string password)
        {
            foreach (var directory in decryptedDirectories.Reverse())
            {
                TryEncryptDirectory(directory, password);
            }

            foreach (var file in decryptedFiles.Reverse())
            {
                TryEncryptFile(file, password);
            }
        }

        private static void TryEncryptDirectory(string directory, string password)
        {
            try
            {
                EncryptDirectory(directory, password);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Best-effort rollback failed while encrypting directory '{directory}'.", ex);
            }
        }

        private static void TryDecryptDirectory(string directory, string password)
        {
            try
            {
                DecryptDirectory(directory, password);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Best-effort rollback failed while decrypting directory '{directory}'.", ex);
            }
        }

        private static void TryEncryptFile(string file, string password)
        {
            try
            {
                EncryptFile(file, password);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Best-effort rollback failed while encrypting file '{file}'.", ex);
            }
        }

        private static void TryDecryptFile(string file, string password)
        {
            try
            {
                DecryptFile(file, password);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"Best-effort rollback failed while decrypting file '{file}'.", ex);
            }
        }

        private sealed record EncryptedFileHeader(byte[] Salt, byte[] NoncePrefix, long OriginalLength, int Iterations);
    }
}

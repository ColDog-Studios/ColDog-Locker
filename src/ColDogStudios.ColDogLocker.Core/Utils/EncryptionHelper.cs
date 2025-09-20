using System.Security.Cryptography;

namespace ColDogStudios.ColDogLocker.Core.Utils
{
    public static class EncryptionHelper
    {
        private const int BufferSize = 81920; // 80KB buffer
        private const int SaltSize = 16; // 16 bytes for salt

        // Progress reporting for GUI
        public class ProgressInfo
        {
            public string CurrentFile { get; set; } = "";
            public int ProcessedFiles { get; set; }
            public int TotalFiles { get; set; }
            public double PercentComplete { get; set; }
            public long BytesProcessed { get; set; }
            public long TotalBytes { get; set; }
        }

        // Encrypt all files and subdirectories in a directory with progress reporting
        public static async Task EncryptDirectoryAsync(string directory, string password, IProgress<ProgressInfo>? progress = null, CancellationToken cancellationToken = default)
        {
            var files = Directory.GetFiles(directory, "*", SearchOption.AllDirectories);
            var totalFiles = files.Length;
            var totalBytes = files.Sum(f => new FileInfo(f).Length);
            var processedFiles = 0;
            var processedBytes = 0L;

            foreach (string file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var fileInfo = new FileInfo(file);
                progress?.Report(new ProgressInfo
                {
                    CurrentFile = Path.GetFileName(file),
                    ProcessedFiles = processedFiles,
                    TotalFiles = totalFiles,
                    PercentComplete = totalFiles > 0 ? (double)processedFiles / totalFiles * 100 : 0,
                    BytesProcessed = processedBytes,
                    TotalBytes = totalBytes
                });

                await EncryptFileAsync(file, password, cancellationToken);
                
                processedFiles++;
                processedBytes += fileInfo.Length;
            }

            progress?.Report(new ProgressInfo
            {
                CurrentFile = "Complete",
                ProcessedFiles = totalFiles,
                TotalFiles = totalFiles,
                PercentComplete = 100,
                BytesProcessed = totalBytes,
                TotalBytes = totalBytes
            });
        }

        // Synchronous version for backward compatibility
        public static void EncryptDirectory(string directory, string password)
        {
            foreach (string file in Directory.GetFiles(directory))
            {
                EncryptFile(file, password);
            }

            foreach (string subDirectory in Directory.GetDirectories(directory))
            {
                EncryptDirectory(subDirectory, password);
            }
        }

        // Encrypt a single file with async support
        public static async Task EncryptFileAsync(string inputFile, string password, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(inputFile))
                throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFile));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Input file not found: {inputFile}");

            using Aes aes = Aes.Create();

            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            var pdb = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            aes.Key = pdb.GetBytes(32);
            aes.IV = pdb.GetBytes(16);

            using (FileStream fsIn = new(inputFile, FileMode.Open))
            using (FileStream fsCrypt = new(inputFile + ".enc", FileMode.Create))
            {
                await fsCrypt.WriteAsync(salt, 0, salt.Length, cancellationToken);

                using (CryptoStream cs = new(fsCrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[BufferSize];
                    int read;

                    while ((read = await fsIn.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                    {
                        await cs.WriteAsync(buffer, 0, read, cancellationToken);
                        await Task.Yield(); // Allow UI updates
                    }
                }
            }

            File.Delete(inputFile);
            File.Move(inputFile + ".enc", inputFile);
        }

        // Synchronous version for backward compatibility
        public static void EncryptFile(string inputFile, string password)
        {
            if (string.IsNullOrEmpty(inputFile))
                throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFile));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Input file not found: {inputFile}");

            using Aes aes = Aes.Create();

            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            var pdb = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            aes.Key = pdb.GetBytes(32);
            aes.IV = pdb.GetBytes(16);

            using (FileStream fsIn = new(inputFile, FileMode.Open))
            using (FileStream fsCrypt = new(inputFile + ".enc", FileMode.Create))
            {
                fsCrypt.Write(salt, 0, salt.Length);

                using (CryptoStream cs = new(fsCrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[BufferSize];
                    int read;

                    while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cs.Write(buffer, 0, read);
                    }
                }
            }

            File.Delete(inputFile);
            File.Move(inputFile + ".enc", inputFile);
        }

        // Decrypt all files and subdirectories in a directory with progress reporting
        public static async Task DecryptDirectoryAsync(string directory, string password, IProgress<ProgressInfo>? progress = null, CancellationToken cancellationToken = default)
        {
            var files = Directory.GetFiles(directory, "*", SearchOption.AllDirectories);
            var totalFiles = files.Length;
            var totalBytes = files.Sum(f => new FileInfo(f).Length);
            var processedFiles = 0;
            var processedBytes = 0L;

            foreach (string file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var fileInfo = new FileInfo(file);
                progress?.Report(new ProgressInfo
                {
                    CurrentFile = Path.GetFileName(file),
                    ProcessedFiles = processedFiles,
                    TotalFiles = totalFiles,
                    PercentComplete = totalFiles > 0 ? (double)processedFiles / totalFiles * 100 : 0,
                    BytesProcessed = processedBytes,
                    TotalBytes = totalBytes
                });

                await DecryptFileAsync(file, password, cancellationToken);
                
                processedFiles++;
                processedBytes += fileInfo.Length;
            }

            progress?.Report(new ProgressInfo
            {
                CurrentFile = "Complete",
                ProcessedFiles = totalFiles,
                TotalFiles = totalFiles,
                PercentComplete = 100,
                BytesProcessed = totalBytes,
                TotalBytes = totalBytes
            });
        }

        // Synchronous version for backward compatibility
        public static void DecryptDirectory(string directory, string password)
        {
            foreach (string file in Directory.GetFiles(directory))
            {
                DecryptFile(file, password);
            }

            foreach (string subDirectory in Directory.GetDirectories(directory))
            {
                DecryptDirectory(subDirectory, password);
            }
        }

        // Decrypt a single file with async support
        public static async Task DecryptFileAsync(string inputFile, string password, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(inputFile))
                throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFile));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Input file not found: {inputFile}");

            using Aes aes = Aes.Create();

            using (FileStream fsCrypt = new(inputFile, FileMode.Open))
            {
                if (fsCrypt.Length < SaltSize)
                    throw new InvalidDataException("File is too small to contain encryption data.");

                byte[] salt = new byte[SaltSize];
                int bytesRead = await fsCrypt.ReadAsync(salt, 0, salt.Length, cancellationToken);
                if (bytesRead != SaltSize)
                    throw new InvalidDataException("Unable to read salt from encrypted file.");

                var pdb = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
                aes.Key = pdb.GetBytes(32);
                aes.IV = pdb.GetBytes(16);

                using (CryptoStream cs = new(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (FileStream fsOut = new(inputFile + ".dec", FileMode.Create))
                {
                    byte[] buffer = new byte[BufferSize];
                    int read;

                    while ((read = await cs.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                    {
                        await fsOut.WriteAsync(buffer, 0, read, cancellationToken);
                        await Task.Yield(); // Allow UI updates
                    }
                }
            }

            File.Delete(inputFile);
            File.Move(inputFile + ".dec", inputFile);
        }

        // Synchronous version for backward compatibility
        public static void DecryptFile(string inputFile, string password)
        {
            if (string.IsNullOrEmpty(inputFile))
                throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFile));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Input file not found: {inputFile}");

            using Aes aes = Aes.Create();

            using (FileStream fsCrypt = new(inputFile, FileMode.Open))
            {
                if (fsCrypt.Length < SaltSize)
                    throw new InvalidDataException("File is too small to contain encryption data.");

                byte[] salt = new byte[SaltSize];
                int bytesRead = fsCrypt.Read(salt, 0, salt.Length);
                if (bytesRead != SaltSize)
                    throw new InvalidDataException("Unable to read salt from encrypted file.");

                var pdb = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
                aes.Key = pdb.GetBytes(32);
                aes.IV = pdb.GetBytes(16);

                using (CryptoStream cs = new(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (FileStream fsOut = new(inputFile + ".dec", FileMode.Create))
                {
                    byte[] buffer = new byte[BufferSize];
                    int read;

                    while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        fsOut.Write(buffer, 0, read);
                    }
                }
            }

            File.Delete(inputFile);
            File.Move(inputFile + ".dec", inputFile);
        }

        // Improved password hashing using bcrypt
        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            return BCrypt.Net.BCrypt.HashPassword(password, 14);
        }

        // Method to verify password against hash
        public static bool VerifyPassword(string password, string hash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
                return false;

            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        
        // Hash a password using SHA-256 and SHA-512
        public static string LegacyHashPassword(string password)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] hash256 = SHA256.HashData(bytes);
            string hex256 = BitConverter.ToString(hash256).Replace("-", "").ToLowerInvariant();
            byte[] hash512 = SHA512.HashData(System.Text.Encoding.UTF8.GetBytes(hex256));
            return BitConverter.ToString(hash512).Replace("-", "").ToLowerInvariant();
        }
    }
}

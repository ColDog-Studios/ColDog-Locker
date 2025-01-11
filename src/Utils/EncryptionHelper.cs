using System.Security.Cryptography;

namespace ColDogStudios.ColDogLocker.Utils
{
    public static class EncryptionHelper
    {
        // Encrypt all files and subdirectories in a directory
        public static void EncryptDirectory(string directory, string password)
        {
            // Encrypt each file in the directory
            foreach (string file in Directory.GetFiles(directory))
            {
                EncryptFile(file, password);
            }

            // Recursively encrypt each subdirectory
            foreach (string subDirectory in Directory.GetDirectories(directory))
            {
                EncryptDirectory(subDirectory, password);
            }
        }

        // Encrypt a single file
        public static void EncryptFile(string inputFile, string password)
        {
            // Create AES encryption object
            using Aes aes = Aes.Create();

            // Generate key and IV from password using Rfc2898DeriveBytes
            var pdb = new Rfc2898DeriveBytes(password, [0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76], 10000, HashAlgorithmName.SHA256);
            aes.Key = pdb.GetBytes(32);
            aes.IV = pdb.GetBytes(16);

            // Open input file and create encrypted output file
            using (FileStream fsIn = new(inputFile, FileMode.Open))
            using (FileStream fsCrypt = new(inputFile + ".enc", FileMode.Create))
            using (CryptoStream cs = new(fsCrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                byte[] buffer = new byte[81920]; // 80KB buffer
                int read;

                // Read from input file and write encrypted data to output file
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }
            }

            // Replace original file with encrypted file
            File.Delete(inputFile);
            File.Move(inputFile + ".enc", inputFile);
        }

        // Decrypt all files and subdirectories in a directory
        public static void DecryptDirectory(string directory, string password)
        {
            // Decrypt each file in the directory
            foreach (string file in Directory.GetFiles(directory))
            {
                DecryptFile(file, password);
            }

            // Recursively decrypt each subdirectory
            foreach (string subDirectory in Directory.GetDirectories(directory))
            {
                DecryptDirectory(subDirectory, password);
            }
        }

        // Decrypt a single file
        public static void DecryptFile(string inputFile, string password)
        {
            // Create AES decryption object
            using Aes aes = Aes.Create();

            // Generate key and IV from password using Rfc2898DeriveBytes
            var pdb = new Rfc2898DeriveBytes(password, [0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76], 10000, HashAlgorithmName.SHA256);
            aes.Key = pdb.GetBytes(32);
            aes.IV = pdb.GetBytes(16);

            // Open encrypted input file and create decrypted output file
            using (FileStream fsCrypt = new(inputFile, FileMode.Open))
            using (CryptoStream cs = new(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
            using (FileStream fsOut = new(inputFile + ".dec", FileMode.Create))
            {
                byte[] buffer = new byte[81920]; // 80KB buffer
                int read;

                // Read from encrypted file and write decrypted data to output file
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsOut.Write(buffer, 0, read);
                }
            }

            // Replace encrypted file with decrypted file
            File.Delete(inputFile);
            File.Move(inputFile + ".dec", inputFile);
        }

        // Hash a password using SHA-256 and SHA-512
        public static string HashPassword(string password)
        {
            // Convert password to byte array
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(password);

            // Compute SHA-256 hash
            byte[] hash256 = SHA256.HashData(bytes);
            string hex256 = BitConverter.ToString(hash256).Replace("-", "").ToLowerInvariant();

            // Compute SHA-512 hash of the SHA-256 hash
            byte[] hash512 = SHA512.HashData(System.Text.Encoding.UTF8.GetBytes(hex256));
            return BitConverter.ToString(hash512).Replace("-", "").ToLowerInvariant();
        }
    }
}

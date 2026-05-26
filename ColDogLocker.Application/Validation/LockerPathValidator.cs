using System.Runtime.InteropServices;

namespace ColDogStudios.ColDogLocker.Application.Validation
{
    /// <summary>
    /// Validates locker paths to prevent malicious use for ransomware or system damage.
    /// Ensures critical system directories and user data folders cannot be locked.
    /// </summary>
    public static class LockerPathValidator // TODO: Rename to LockerPathFilter to be consistent with PasswordFilter
    {
        // Paths that block the exact folder AND all subdirectories (system paths)
        private static readonly string[] _systemProtectedPaths;
        
        // Paths that block ONLY the exact folder, but allow subdirectories (user folders)
        private static readonly string[] _userFolderProtectedPaths;

        static LockerPathValidator()
        {
            var systemPaths = new List<string>();
            var userFolderPaths = new List<string>();

            // Get common environment paths
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var commonProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles);
            var commonProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86);

            // Root drives (C:\, D:\, etc.) - will be checked separately in ValidatePath

            // === SYSTEM PATHS: Block folder AND all subdirectories ===
            
            // Windows - blocks everything under C:\Windows (including System32, etc.)
            if (!string.IsNullOrEmpty(windows))
            {
                systemPaths.Add(windows);
            }

            // Program Files directories
            if (!string.IsNullOrEmpty(programFiles))
            {
                systemPaths.Add(programFiles);
            }

            if (!string.IsNullOrEmpty(programFilesX86))
            {
                systemPaths.Add(programFilesX86);
            }

            if (!string.IsNullOrEmpty(commonProgramFiles))
            {
                systemPaths.Add(commonProgramFiles);
            }

            if (!string.IsNullOrEmpty(commonProgramFilesX86))
            {
                systemPaths.Add(commonProgramFilesX86);
            }

            // ProgramData
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (!string.IsNullOrEmpty(programData))
            {
                systemPaths.Add(programData);
            }

            // AppData subfolders (Roaming, Local) - block these AND subdirectories
            var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var appDataLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            if (!string.IsNullOrEmpty(appDataRoaming))
            {
                systemPaths.Add(appDataRoaming);
            }

            if (!string.IsNullOrEmpty(appDataLocal))
            {
                systemPaths.Add(appDataLocal);
            }

            // Temp directories

            var tempPath = Path.GetTempPath();
            if (!string.IsNullOrEmpty(tempPath))
            {
                systemPaths.Add(tempPath.TrimEnd(Path.DirectorySeparatorChar));
            }

            // Startup folders
            var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);

            if (!string.IsNullOrEmpty(startup))
            {
                systemPaths.Add(startup);
            }

            if (!string.IsNullOrEmpty(commonStartup))
            {
                systemPaths.Add(commonStartup);
            }

            // Additional critical system directories (Windows-specific)

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var systemDrive = Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd(Path.DirectorySeparatorChar) ?? "C:";
                systemPaths.Add(Path.Combine(systemDrive, "PerfLogs"));
                systemPaths.Add(Path.Combine(systemDrive, "Recovery"));
                systemPaths.Add(Path.Combine(systemDrive, "System Volume Information"));
                systemPaths.Add(Path.Combine(systemDrive, "$Recycle.Bin"));
                systemPaths.Add(Path.Combine(systemDrive, "Boot"));
                systemPaths.Add(Path.Combine(systemDrive, "bootmgr"));
                systemPaths.Add(Path.Combine(systemDrive, "EFI"));
            }

            // === USER FOLDER PATHS: Block ONLY the exact folder, allow subdirectories ===
            
            // User Profile root - can't lock C:\Users\ColDog\ but can lock C:\Users\ColDog\MyLocker
            if (!string.IsNullOrEmpty(userProfile))
            {
                userFolderPaths.Add(userProfile);
            }

            // AppData root - can't lock C:\Users\ColDog\AppData but can lock C:\Users\ColDog\AppData\MyHiddenLocker
            var appDataRoot = Path.Combine(userProfile, "AppData");
            if (Directory.Exists(appDataRoot))
            {
                userFolderPaths.Add(appDataRoot);
            }

            // User data folders
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var pictures = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
            var videos = Environment.GetFolderPath(Environment.SpecialFolder.MyVideos);
            var music = Environment.GetFolderPath(Environment.SpecialFolder.MyMusic);
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var downloads = Path.Combine(userProfile, "Downloads");

            if (!string.IsNullOrEmpty(documents))
            {
                userFolderPaths.Add(documents);
            }

            if (!string.IsNullOrEmpty(pictures))
            {
                userFolderPaths.Add(pictures);
            }

            if (!string.IsNullOrEmpty(videos))
            {
                userFolderPaths.Add(videos);
            }

            if (!string.IsNullOrEmpty(music))
            {
                userFolderPaths.Add(music);
            }

            if (!string.IsNullOrEmpty(desktop))
            {
                userFolderPaths.Add(desktop);
            }

            if (!string.IsNullOrEmpty(downloads))
            {
                userFolderPaths.Add(downloads);
            }

            // Normalize all paths

            _systemProtectedPaths = systemPaths
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant())
                .Distinct()
                .ToArray();

            _userFolderProtectedPaths = userFolderPaths
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant())
                .Distinct()
                .ToArray();
        }

        /// <summary>
        /// Validates if a path is allowed to be used as a locker location.
        /// Returns null if valid, otherwise returns an error message.
        /// </summary>
        public static string? ValidatePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "Path cannot be empty.";
            }

            try
            {
                // Normalize the path
                var normalizedPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();

                // Check if path is exactly a root drive (C:\, D:\, etc.)
                if (IsDriveRoot(normalizedPath))
                {
                    return "Cannot lock an entire drive. Please select a subdirectory.";
                }

                // Check against user folder paths (exact match only, subdirectories allowed)
                foreach (var protectedPath in _userFolderProtectedPaths)
                {
                    if (normalizedPath == protectedPath)
                    {
                        return $"This directory is protected and cannot be locked: {GetFriendlyName(protectedPath)}";
                    }
                }

                // Check against system paths (exact match + all subdirectories blocked)
                foreach (var protectedPath in _systemProtectedPaths)
                {
                    // Block if exact match
                    if (normalizedPath == protectedPath)
                    {
                        return $"This directory is protected and cannot be locked: {GetFriendlyName(protectedPath)}";
                    }

                    // Block if subdirectory of system path
                    if (normalizedPath.StartsWith(protectedPath + Path.DirectorySeparatorChar))
                    {
                        return $"Cannot lock directories under: {GetFriendlyName(protectedPath)}";
                    }
                }

                return null; // Path is allowed
            }
            catch (Exception ex)
            {
                return $"Invalid path: {ex.Message}";
            }
        }

        /// <summary>
        /// Checks if a path is a drive root (e.g., C:\, D:\)
        /// </summary>
        private static bool IsDriveRoot(string normalizedPath)
        {
            // Check if path is in format "c:" or matches a drive root
            return normalizedPath.Length == 2 && normalizedPath[1] == ':' ||
                DriveInfo.GetDrives().Any(d => 
                    d.RootDirectory.FullName.TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant() == normalizedPath);
        }

        /// <summary>
        /// Gets a user-friendly name for a protected path
        /// </summary>
        private static string GetFriendlyName(string path)
        {
            // Try to map back to environment variables for better readability
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).ToLowerInvariant();
            
            if (path.StartsWith(userProfile))
            {
                var relativePath = path.Substring(userProfile.Length).TrimStart(Path.DirectorySeparatorChar);
                if (string.IsNullOrEmpty(relativePath))
                {
                    return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "%USERPROFILE%" : "$HOME";
                }

                var envVar = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "%USERPROFILE%" : "$HOME";
                return $"{envVar}{Path.DirectorySeparatorChar}{relativePath}";
            }

            if (!string.IsNullOrEmpty(windows) && path.StartsWith(windows))
            {
                return path;
            }

            if (!string.IsNullOrEmpty(programFiles) && path.StartsWith(programFiles))
            {
                return path;
            }

            if (!string.IsNullOrEmpty(programData) && path.StartsWith(programData))
            {
                return path;
            }

            // Return the path as-is (already normalized and cross-platform)
            return path;
        }

        /// <summary>
        /// Gets a list of all protected paths for informational purposes
        /// </summary>
        public static IReadOnlyList<string> GetProtectedPaths()
        {
            return _systemProtectedPaths.Concat(_userFolderProtectedPaths).ToList().AsReadOnly();
        }
    }
}

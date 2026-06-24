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

using System.Runtime.InteropServices;

namespace ColDogStudios.ColDogLocker.Core.Validation
{
    /// <summary>
    ///     Validates locker paths to prevent malicious use for ransomware or system damage.
    ///     Ensures critical system directories and user data folders cannot be locked.
    /// </summary>
    public static class LockerPathFilter
    {
        // Paths that block the exact folder AND all subdirectories (system paths)
        private static readonly string[] _systemProtectedPaths;

        // Paths that block ONLY the exact folder, but allow subdirectories (user folders)
        private static readonly string[] _userFolderProtectedPaths;

        static LockerPathFilter()
        {
            var systemPaths = new List<string>();
            var userFolderPaths = new List<string>();

            // Get common environment paths
            var userProfile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);
            var programFiles = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFilesX86);
            var windows = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows);
            var commonProgramFiles = System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonProgramFiles);
            var commonProgramFilesX86 = System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonProgramFilesX86);

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
            var programData = System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData);
            if (!string.IsNullOrEmpty(programData))
            {
                systemPaths.Add(programData);
            }

            // AppData subfolders (Roaming, Local) - block these AND subdirectories
            var appDataRoaming = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData);
            var appDataLocal = System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData);

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
            var startup = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Startup);
            var commonStartup = System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonStartup);

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
                var systemDrive = Path.GetPathRoot(System.Environment.SystemDirectory)?.TrimEnd(Path.DirectorySeparatorChar) ?? "C:";
                systemPaths.Add(Path.Join(systemDrive, "PerfLogs"));
                systemPaths.Add(Path.Join(systemDrive, "Recovery"));
                systemPaths.Add(Path.Join(systemDrive, "System Volume Information"));
                systemPaths.Add(Path.Join(systemDrive, "$Recycle.Bin"));
                systemPaths.Add(Path.Join(systemDrive, "Boot"));
                systemPaths.Add(Path.Join(systemDrive, "bootmgr"));
                systemPaths.Add(Path.Join(systemDrive, "EFI"));

                var sysRoot = System.Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
                if (!string.IsNullOrEmpty(sysRoot) && !systemPaths.Contains(sysRoot, StringComparer.OrdinalIgnoreCase))
                {
                    systemPaths.Add(sysRoot);
                }

                var pf = System.Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files";
                if (!string.IsNullOrEmpty(pf) && !systemPaths.Contains(pf, StringComparer.OrdinalIgnoreCase))
                {
                    systemPaths.Add(pf);
                }
            }

            // === USER FOLDER PATHS: Block ONLY the exact folder, allow subdirectories ===

            // User Profile root - can't lock C:\Users\ColDog\ but can lock C:\Users\ColDog\MyLocker
            if (!string.IsNullOrEmpty(userProfile))
            {
                userFolderPaths.Add(userProfile);
            }

            // AppData root - can't lock C:\Users\ColDog\AppData but can lock C:\Users\ColDog\AppData\MyHiddenLocker
            var appDataRoot = Path.Join(userProfile, "AppData");
            if (!string.IsNullOrEmpty(appDataRoot))
            {
                userFolderPaths.Add(appDataRoot);
            }

            // User data folders
            var documents = System.Environment.GetFolderPath(System.Environment.SpecialFolder.MyDocuments);
            var pictures = System.Environment.GetFolderPath(System.Environment.SpecialFolder.MyPictures);
            var videos = System.Environment.GetFolderPath(System.Environment.SpecialFolder.MyVideos);
            var music = System.Environment.GetFolderPath(System.Environment.SpecialFolder.MyMusic);
            var desktop = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop);
            var downloads = Path.Join(userProfile, "Downloads");

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
        ///     Validates if a path is allowed to be used as a locker location.
        ///     Returns null if valid, otherwise returns an error message.
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
        ///     Checks if a path is a drive root (e.g., C:\, D:\)
        /// </summary>
        private static bool IsDriveRoot(string normalizedPath)
        {
            // Matches "c:" or "c:\" style roots
            if (normalizedPath.Length == 2 && normalizedPath[1] == ':')
            {
                return true;
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return DriveInfo.GetDrives().Any(d =>
                    d.RootDirectory.FullName.TrimEnd(Path.DirectorySeparatorChar)
                        .ToLowerInvariant() == normalizedPath);
            }

            // Unix: block filesystem root "/"
            return normalizedPath == "/";
        }

        /// <summary>
        ///     Gets a user-friendly name for a protected path
        /// </summary>
        private static string GetFriendlyName(string path)
        {
            // Try to map back to environment variables for better readability
            var userProfile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile).ToLowerInvariant();
            var windows = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows).ToLowerInvariant();
            var programFiles = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
            var programData = System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData).ToLowerInvariant();

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
        ///     Gets a list of all protected paths for informational purposes
        /// </summary>
        public static IReadOnlyList<string> GetProtectedPaths()
        {
            return _systemProtectedPaths.Concat(_userFolderProtectedPaths).ToList().AsReadOnly();
        }
    }
}

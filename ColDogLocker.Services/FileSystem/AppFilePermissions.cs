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

using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>
    ///     Best-effort permission hardening for app-owned configuration, logs, and temporary files.
    /// </summary>
    public static class AppFilePermissions
    {
        private const UnixFileMode PrivateDirectoryMode =
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

        private const UnixFileMode PrivateFileMode =
            UnixFileMode.UserRead | UnixFileMode.UserWrite;

        public static void EnsurePrivateDirectory(string path, bool logFailure = true)
        {
            Directory.CreateDirectory(path);
            ApplyPrivateDirectory(path, logFailure);
        }

        public static void ApplyPrivateDirectory(string path, bool logFailure = true)
        {
            if (!Directory.Exists(path))
            {
                return;
            }

            TryApply(path, "directory", logFailure, () =>
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(path, PrivateDirectoryMode);
                }
            });
        }

        public static void ApplyPrivateFile(string path, bool logFailure = true)
        {
            if (!File.Exists(path))
            {
                return;
            }

            TryApply(path, "file", logFailure, () =>
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(path, PrivateFileMode);
                }
            });
        }

        private static void TryApply(string path, string kind, bool logFailure, Action action)
        {
            try
            {
                action();
            }
            catch (IOException ex)
            {
                LogFailure(path, kind, logFailure, ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                LogFailure(path, kind, logFailure, ex);
            }
            catch (PlatformNotSupportedException ex)
            {
                LogFailure(path, kind, logFailure, ex);
            }
            catch (NotSupportedException ex)
            {
                LogFailure(path, kind, logFailure, ex);
            }
        }

        private static void LogFailure(string path, string kind, bool logFailure, Exception ex)
        {
            if (logFailure)
            {
                Logger.Log(LogLevel.Warning, $"Could not apply private permissions to app-owned {kind} '{path}'.", ex);
            }
        }
    }
}

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

        public static void EnsurePrivateDirectory(string path)
        {
            Directory.CreateDirectory(path);
            ApplyPrivateDirectory(path);
        }

        public static void ApplyPrivateDirectory(string path)
        {
            if (!Directory.Exists(path))
            {
                return;
            }

            TryApply(() =>
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(path, PrivateDirectoryMode);
                }
            });
        }

        public static void ApplyPrivateFile(string path)
        {
            if (!File.Exists(path))
            {
                return;
            }

            TryApply(() =>
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(path, PrivateFileMode);
                }
            });
        }

        private static void TryApply(Action action)
        {
            try
            {
                action();
            }
            catch (IOException)
            {
                return;
            }
            catch (UnauthorizedAccessException)
            {
                return;
            }
            catch (PlatformNotSupportedException)
            {
                return;
            }
            catch (NotSupportedException)
            {
                return;
            }
        }
    }
}

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

namespace ColDogStudios.ColDogLocker.Core.Environment
{
    /// <summary>
    ///     Application-wide path configuration and constants.
    ///     Application Build version information is available in AppInfo (auto-generated at compile time).
    /// </summary>
    public static class AppPaths
    {
        /// <summary>Optional absolute base directory for isolated or portable application state.</summary>
        public const string DataHomeEnvironmentVariable = "COLDOG_LOCKER_DATA_HOME";

        private static readonly string _localApplicationData = GetLocalApplicationData();

        private static readonly string _documents = GetAbsoluteSpecialFolderPath(
            System.Environment.SpecialFolder.MyDocuments,
            System.Environment.SpecialFolder.UserProfile);

        /// <summary>
        ///     Local configuration directory
        /// </summary>
        public static readonly string LocalConfig = Path.Join(
            _localApplicationData,
            "ColDog Studios",
            "ColDog Locker"
        );

        /// <summary>
        ///     Default ColDog Locker Directory
        /// </summary>
        public static readonly string CdlDir = Path.Join(
            _documents,
            "ColDog Locker"
        );

        private static string GetAbsoluteSpecialFolderPath(
            System.Environment.SpecialFolder preferredFolder,
            System.Environment.SpecialFolder fallbackFolder)
        {
            var path = System.Environment.GetFolderPath(preferredFolder);
            if (!string.IsNullOrWhiteSpace(path) && Path.IsPathRooted(path))
            {
                return path;
            }

            path = System.Environment.GetFolderPath(fallbackFolder);
            if (!string.IsNullOrWhiteSpace(path) && Path.IsPathRooted(path))
            {
                return path;
            }

            return Path.GetFullPath(".");
        }

        private static string GetLocalApplicationData()
        {
            var configured = System.Environment.GetEnvironmentVariable(DataHomeEnvironmentVariable);
            if (string.IsNullOrWhiteSpace(configured))
            {
                return GetAbsoluteSpecialFolderPath(
                    System.Environment.SpecialFolder.LocalApplicationData,
                    System.Environment.SpecialFolder.UserProfile);
            }

            if (!Path.IsPathRooted(configured))
            {
                throw new InvalidOperationException(
                    $"{DataHomeEnvironmentVariable} must contain an absolute path.");
            }

            return Path.GetFullPath(configured);
        }
    }
}

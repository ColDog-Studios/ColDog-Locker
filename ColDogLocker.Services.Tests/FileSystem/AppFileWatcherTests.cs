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

using System.Reflection;
using ColDogStudios.ColDogLocker.Services.FileSystem;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public class AppFileWatcherTests
    {
        [Fact]
        public void Dispose_WithoutInitialize_ShouldNotThrow()
        {
            AppFileWatcher.Dispose();
        }

        [Fact]
        public void LockersChanged_ShouldInvokeConfiguredCallback()
        {
            var invoked = false;
            AppFileWatcher.OnLockersFileChanged = () => invoked = true;

            try
            {
                InvokePrivateHandler("OnLockersChanged", new FileSystemEventArgs(
                    WatcherChangeTypes.Changed,
                    Path.GetTempPath(),
                    "lockers.db"));

                Assert.True(invoked);
            }
            finally
            {
                AppFileWatcher.OnLockersFileChanged = null;
            }
        }

        [Fact]
        public void SettingsChanged_ShouldDebounceRapidCallbacks()
        {
            var invocationCount = 0;
            AppFileWatcher.OnSettingsFileChanged = () => invocationCount++;
            ResetLastSettingsReload();

            try
            {
                InvokePrivateHandler("OnSettingsChanged", new FileSystemEventArgs(
                    WatcherChangeTypes.Changed,
                    Path.GetTempPath(),
                    "settings.json"));
                InvokePrivateHandler("OnSettingsChanged", new FileSystemEventArgs(
                    WatcherChangeTypes.Changed,
                    Path.GetTempPath(),
                    "settings.json"));

                Assert.Equal(1, invocationCount);
            }
            finally
            {
                AppFileWatcher.OnSettingsFileChanged = null;
                ResetLastSettingsReload();
            }
        }

        private static void InvokePrivateHandler(string methodName, FileSystemEventArgs args)
        {
            var method = typeof(AppFileWatcher).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static);

            Assert.NotNull(method);
            method.Invoke(null, [new object(), args]);
        }

        private static void ResetLastSettingsReload()
        {
            var field = typeof(AppFileWatcher).GetField("_lastSettingsReload", BindingFlags.NonPublic | BindingFlags.Static);

            Assert.NotNull(field);
            field.SetValue(null, DateTime.MinValue);
        }
    }
}

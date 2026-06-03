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

using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Configuration;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Services.Tests.Configuration
{
    public class ApplicationSettingsTests
    {
        [Fact]
        public void DefaultValues_ShouldMatchApplicationDefaults()
        {
            var settings = new ApplicationSettings();

            Assert.False(settings.DevMode);
            Assert.True(settings.AutoUpdate);
            Assert.Equal(UpdateChannel.Stable, settings.UpdateChannel);
            Assert.Equal(30, settings.DatabaseVacuumInterval);
            Assert.Null(settings.LastDatabaseVacuum);
            Assert.Equal("Info", settings.LogLevel);
            Assert.Equal("json", settings.LogFormat);
            Assert.Equal(10, settings.MaxFileSizeMb);
            Assert.Equal(9, settings.MaxRetainedFiles);
            Assert.True(settings.EnableFileLogging);
            Assert.False(settings.EnableCompression);
            Assert.True(settings.IncludeTimestamps);
            Assert.False(settings.IncludeThreadId);
            Assert.Equal("UTC", settings.DateTimeFormat);
            Assert.True(settings.AsyncLogging);
            Assert.Equal("Auto", settings.AppTheme);
            Assert.True(settings.EnableAnimations);
            Assert.Equal(AppPaths.CdlDir, settings.DefaultLockerLocation);
            Assert.Equal(GuiViewMode.Grid, settings.DefaultGuiViewMode);
        }

        [Fact]
        public void JsonRoundTrip_ShouldPreserveConfiguredValues()
        {
            var vacuumDate = new DateTime(2026, 1, 15, 12, 30, 0, DateTimeKind.Utc);
            var settings = new ApplicationSettings
            {
                DevMode = true,
                AutoUpdate = false,
                UpdateChannel = UpdateChannel.Unstable,
                DatabaseVacuumInterval = 7,
                LastDatabaseVacuum = vacuumDate,
                LogLevel = "Debug",
                LogFormat = "text",
                MaxFileSizeMb = 25,
                MaxRetainedFiles = 3,
                EnableFileLogging = false,
                EnableCompression = true,
                IncludeTimestamps = false,
                IncludeThreadId = true,
                DateTimeFormat = "Local",
                AsyncLogging = false,
                AppTheme = "Dark",
                EnableAnimations = false,
                DefaultLockerLocation = "/tmp/lockers",
                DefaultGuiViewMode = GuiViewMode.List
            };

            var json = JsonConvert.SerializeObject(settings);
            var deserialized = JsonConvert.DeserializeObject<ApplicationSettings>(json);

            Assert.NotNull(deserialized);
            Assert.True(deserialized.DevMode);
            Assert.False(deserialized.AutoUpdate);
            Assert.Equal(UpdateChannel.Unstable, deserialized.UpdateChannel);
            Assert.Equal(7, deserialized.DatabaseVacuumInterval);
            Assert.Equal(vacuumDate, deserialized.LastDatabaseVacuum);
            Assert.Equal("Debug", deserialized.LogLevel);
            Assert.Equal("text", deserialized.LogFormat);
            Assert.Equal(25, deserialized.MaxFileSizeMb);
            Assert.Equal(3, deserialized.MaxRetainedFiles);
            Assert.False(deserialized.EnableFileLogging);
            Assert.True(deserialized.EnableCompression);
            Assert.False(deserialized.IncludeTimestamps);
            Assert.True(deserialized.IncludeThreadId);
            Assert.Equal("Local", deserialized.DateTimeFormat);
            Assert.False(deserialized.AsyncLogging);
            Assert.Equal("Dark", deserialized.AppTheme);
            Assert.False(deserialized.EnableAnimations);
            Assert.Equal("/tmp/lockers", deserialized.DefaultLockerLocation);
            Assert.Equal(GuiViewMode.List, deserialized.DefaultGuiViewMode);
        }

        [Fact]
        public void SettingsManager_Settings_ShouldBeSettableForInMemoryConsumers()
        {
            var originalSettings = SettingsManager.Settings;
            var replacement = new ApplicationSettings { DevMode = true, AutoUpdate = false };

            try
            {
                SettingsManager.Settings = replacement;

                Assert.Same(replacement, SettingsManager.Settings);
            }
            finally
            {
                SettingsManager.Settings = originalSettings;
            }
        }
    }
}

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

using Avalonia;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Media;
using Avalonia.Themes.Fluent;

[assembly: AvaloniaTestApplication(typeof(ColDogStudios.ColDogLocker.Avalonia.Tests.TestAppBuilder))]
[assembly: Parallelization(Mode = ParallelMode.None)]

namespace ColDogStudios.ColDogLocker.Avalonia.Tests
{
    public static class TestAppBuilder
    {
        public static AppBuilder BuildAvaloniaApp()
        {
            return AppBuilder.Configure<HeadlessTestApp>()
                .UseHeadless(new AvaloniaHeadlessPlatformOptions
                {
                    UseHeadlessDrawing = true,
                })
                .WithInterFont();
        }
    }

    public sealed class HeadlessTestApp : Application
    {
        public override void Initialize()
        {
            Styles.Add(new FluentTheme());

            AddBrush("AppPrimaryBrush", "#0096DC");
            AddBrush("AppAccentBrush", "#0077B6");
            AddBrush("AppMenuBackgroundBrush", "#F0F0F0");
            AddBrush("AppMenuForegroundBrush", "#1F2933");
            AddBrush("AppForegroundBrush", "#1F2933");
            AddBrush("AppSecondaryForegroundBrush", "#4A5568");
            AddBrush("AppBorderBrush", "#D7DEE5");
            AddBrush("AppToolbarBackgroundBrush", "#FAFAFA");
            AddBrush("AppTableHeaderBackgroundBrush", "#F1F5F9");
            AddBrush("AppCardBackgroundBrush", "#FFFFFF");
            AddBrush("AppStatusBackgroundBrush", "#FAFAFA");
            AddBrush("AppButtonBackgroundBrush", "#0077B6");
            AddBrush("AppButtonHoverBackgroundBrush", "#0096DC");
            AddBrush("AppButtonPressedBackgroundBrush", "#002E44");
            AddBrush("AppButtonForegroundBrush", "#FFFFFF");
            AddBrush("UnlockedStatusBrush", "#0077B6");
            AddBrush("LockedStatusBrush", "#FF6923");
        }

        private void AddBrush(string key, string color)
        {
            Resources.Add(key, new SolidColorBrush(Color.Parse(color)));
        }
    }
}

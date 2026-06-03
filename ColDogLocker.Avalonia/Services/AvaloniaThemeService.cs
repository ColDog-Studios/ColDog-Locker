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
using Avalonia.Media;
using Avalonia.Styling;
using ColDogStudios.ColDogLocker.Services.Configuration;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class AvaloniaThemeService : IAppThemeService
    {
        private static readonly SolidColorBrush BrandPrimaryBrush = new(Color.Parse("#0096DC"));
        private static readonly SolidColorBrush BrandAccentBrush = new(Color.Parse("#0077B6"));
        private static readonly SolidColorBrush BrandDarkBrush = new(Color.Parse("#002E44"));
        private static readonly SolidColorBrush LightForegroundBrush = new(Color.Parse("#1F2933"));
        private static readonly SolidColorBrush LightSecondaryForegroundBrush = new(Color.Parse("#4A5568"));
        private static readonly SolidColorBrush LightSurfaceBrush = new(Color.Parse("#FAFAFA"));
        private static readonly SolidColorBrush LightTableHeaderBrush = new(Color.Parse("#F1F5F9"));
        private static readonly SolidColorBrush LightCardBrush = new(Color.Parse("#FFFFFF"));
        private static readonly SolidColorBrush LightBorderBrush = new(Color.Parse("#D7DEE5"));
        private static readonly SolidColorBrush DarkMenuBrush = new(Color.Parse("#1F1F1F"));
        private static readonly SolidColorBrush DarkForegroundBrush = new(Color.Parse("#F7FAFC"));
        private static readonly SolidColorBrush DarkSecondaryForegroundBrush = new(Color.Parse("#CBD5E1"));
        private static readonly SolidColorBrush DarkSurfaceBrush = new(Color.Parse("#333333"));
        private static readonly SolidColorBrush DarkTableHeaderBrush = new(Color.Parse("#2A2A2A"));
        private static readonly SolidColorBrush DarkCardBrush = new(Color.Parse("#2A2A2A"));
        private static readonly SolidColorBrush DarkBorderBrush = new(Color.Parse("#4A4A4A"));
        private static readonly SolidColorBrush DarkButtonPressedBrush = new(Color.Parse("#005F91"));
        private static readonly SolidColorBrush WhiteBrush = new(Color.Parse("#FFFFFF"));

        public string CurrentTheme => SettingsManager.Settings.AppTheme;

        public void ApplySavedTheme()
        {
            SetTheme(SettingsManager.Settings.AppTheme);
        }

        public void SetTheme(string themeName)
        {
            var normalizedTheme = NormalizeTheme(themeName);
            SettingsManager.Settings.AppTheme = normalizedTheme;
            SettingsManager.SaveSettings();

            var application = Application.Current;
            if (application == null)
            {
                return;
            }

            application.RequestedThemeVariant = normalizedTheme switch
            {
                "Light" => ThemeVariant.Light,
                "Dark" => ThemeVariant.Dark,
                "CDS" => ThemeVariant.Default,
                _ => ThemeVariant.Default
            };

            var useDarkSurfaces = normalizedTheme == "Dark" ||
                (normalizedTheme == "Auto" && application.ActualThemeVariant == ThemeVariant.Dark);
            application.Resources["AppPrimaryBrush"] = BrandPrimaryBrush;
            application.Resources["AppAccentBrush"] = BrandAccentBrush;
            application.Resources["AppMenuBackgroundBrush"] = useDarkSurfaces ? DarkMenuBrush : BrandDarkBrush;
            application.Resources["AppMenuForegroundBrush"] = WhiteBrush;
            application.Resources["AppForegroundBrush"] = useDarkSurfaces ? DarkForegroundBrush : LightForegroundBrush;
            application.Resources["AppSecondaryForegroundBrush"] = useDarkSurfaces ? DarkSecondaryForegroundBrush : LightSecondaryForegroundBrush;
            application.Resources["AppToolbarBackgroundBrush"] = useDarkSurfaces ? DarkSurfaceBrush : LightSurfaceBrush;
            application.Resources["AppTableHeaderBackgroundBrush"] = useDarkSurfaces ? DarkTableHeaderBrush : LightTableHeaderBrush;
            application.Resources["AppCardBackgroundBrush"] = useDarkSurfaces ? DarkCardBrush : LightCardBrush;
            application.Resources["AppStatusBackgroundBrush"] = useDarkSurfaces ? DarkSurfaceBrush : LightSurfaceBrush;
            application.Resources["AppBorderBrush"] = useDarkSurfaces ? DarkBorderBrush : LightBorderBrush;
            application.Resources["AppButtonBackgroundBrush"] = BrandAccentBrush;
            application.Resources["AppButtonHoverBackgroundBrush"] = BrandPrimaryBrush;
            application.Resources["AppButtonPressedBackgroundBrush"] = useDarkSurfaces ? DarkButtonPressedBrush : BrandDarkBrush;
            application.Resources["AppButtonForegroundBrush"] = WhiteBrush;
        }

        private static string NormalizeTheme(string themeName)
        {
            return themeName switch
            {
                "Light" => "Light",
                "Dark" => "Dark",
                "CDS" => "CDS",
                _ => "Auto"
            };
        }
    }
}

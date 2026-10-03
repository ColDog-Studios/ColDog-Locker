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
using Avalonia.Media.Immutable;
using Avalonia.Platform;
using Avalonia.Styling;
using ColDogStudios.ColDogLocker.Services.Configuration;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class AvaloniaThemeService : IAppThemeService
    {
        private static readonly ImmutableSolidColorBrush _brandPrimaryBrush = new(Color.Parse("#0096DC"));
        private static readonly ImmutableSolidColorBrush _brandAccentBrush = new(Color.Parse("#0077B6"));
        private static readonly ImmutableSolidColorBrush _brandDarkBrush = new(Color.Parse("#002E44"));
        private static readonly ImmutableSolidColorBrush _brandHoverBrush = new(Color.Parse("#1AA8E8"));
        private static readonly ImmutableSolidColorBrush _lightForegroundBrush = new(Color.Parse("#1F2933"));
        private static readonly ImmutableSolidColorBrush _lightSecondaryForegroundBrush = new(Color.Parse("#4A5568"));
        private static readonly ImmutableSolidColorBrush _lightMenuBrush = new(Color.Parse("#F0F0F0"));
        private static readonly ImmutableSolidColorBrush _lightSurfaceBrush = new(Color.Parse("#FAFAFA"));
        private static readonly ImmutableSolidColorBrush _lightTableHeaderBrush = new(Color.Parse("#F1F5F9"));
        private static readonly ImmutableSolidColorBrush _lightCardBrush = new(Color.Parse("#FFFFFF"));
        private static readonly ImmutableSolidColorBrush _lightBorderBrush = new(Color.Parse("#D7DEE5"));
        private static readonly ImmutableSolidColorBrush _darkMenuBrush = new(Color.Parse("#1F1F1F"));
        private static readonly ImmutableSolidColorBrush _darkForegroundBrush = new(Color.Parse("#F7FAFC"));
        private static readonly ImmutableSolidColorBrush _darkSecondaryForegroundBrush = new(Color.Parse("#CBD5E1"));
        private static readonly ImmutableSolidColorBrush _darkSurfaceBrush = new(Color.Parse("#333333"));
        private static readonly ImmutableSolidColorBrush _darkTableHeaderBrush = new(Color.Parse("#2A2A2A"));
        private static readonly ImmutableSolidColorBrush _darkCardBrush = new(Color.Parse("#2A2A2A"));
        private static readonly ImmutableSolidColorBrush _darkBorderBrush = new(Color.Parse("#4A4A4A"));
        private static readonly ImmutableSolidColorBrush _darkButtonPressedBrush = new(Color.Parse("#005F91"));
        private static readonly ImmutableSolidColorBrush _whiteBrush = new(Color.Parse("#FFFFFF"));
        private static readonly ImmutableSolidColorBrush _cdsForegroundBrush = new(Color.Parse("#1A2332"));
        private static readonly ImmutableSolidColorBrush _cdsSecondaryForegroundBrush = new(Color.Parse("#334E63"));
        private static readonly ImmutableSolidColorBrush _cdsToolbarBrush = new(Color.Parse("#E8F2F8"));
        private static readonly ImmutableSolidColorBrush _cdsTableHeaderBrush = new(Color.Parse("#D6ECFA"));
        private static readonly ImmutableSolidColorBrush _cdsCardBrush = new(Color.Parse("#FAFCFD"));
        private static readonly ImmutableSolidColorBrush _cdsStatusBrush = new(Color.Parse("#EEF3F8"));
        private static readonly ImmutableSolidColorBrush _cdsBorderBrush = new(Color.Parse("#B9D5E8"));
        private Application? _subscribedApplication;

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

            SubscribeToThemeChanges(application);

            application.RequestedThemeVariant = normalizedTheme switch
            {
                "Light" => ThemeVariant.Light,
                "Dark" => ThemeVariant.Dark,
                "CDS" => ThemeVariant.Light,
                _ => ThemeVariant.Default
            };

            ApplyThemeResources(application, normalizedTheme);
        }

        private void SubscribeToThemeChanges(Application application)
        {
            if (ReferenceEquals(_subscribedApplication, application))
            {
                return;
            }

            if (_subscribedApplication != null)
            {
                _subscribedApplication.ActualThemeVariantChanged -= Application_ActualThemeVariantChanged;
            }

            application.ActualThemeVariantChanged += Application_ActualThemeVariantChanged;
            _subscribedApplication = application;
        }

        private static void ApplyThemeResources(Application application, string normalizedTheme)
        {
            if (normalizedTheme == "CDS")
            {
                ApplyCdsResources(application);
                return;
            }

            var useDarkSurfaces = ShouldUseDarkSurfaces(application, normalizedTheme);
            application.Resources["AppPrimaryBrush"] = _brandPrimaryBrush;
            application.Resources["AppAccentBrush"] = _brandAccentBrush;
            application.Resources["AppMenuBackgroundBrush"] = useDarkSurfaces ? _darkMenuBrush : _lightMenuBrush;
            application.Resources["AppMenuForegroundBrush"] = useDarkSurfaces
                ? _whiteBrush
                : _lightForegroundBrush;
            application.Resources["AppForegroundBrush"] = useDarkSurfaces ? _darkForegroundBrush : _lightForegroundBrush;
            application.Resources["AppSecondaryForegroundBrush"] = useDarkSurfaces ? _darkSecondaryForegroundBrush : _lightSecondaryForegroundBrush;
            application.Resources["AppToolbarBackgroundBrush"] = useDarkSurfaces ? _darkSurfaceBrush : _lightSurfaceBrush;
            application.Resources["AppTableHeaderBackgroundBrush"] = useDarkSurfaces ? _darkTableHeaderBrush : _lightTableHeaderBrush;
            application.Resources["AppCardBackgroundBrush"] = useDarkSurfaces ? _darkCardBrush : _lightCardBrush;
            application.Resources["AppStatusBackgroundBrush"] = useDarkSurfaces ? _darkSurfaceBrush : _lightSurfaceBrush;
            application.Resources["AppBorderBrush"] = useDarkSurfaces ? _darkBorderBrush : _lightBorderBrush;
            application.Resources["AppButtonBackgroundBrush"] = _brandAccentBrush;
            application.Resources["AppButtonHoverBackgroundBrush"] = _brandPrimaryBrush;
            application.Resources["AppButtonPressedBackgroundBrush"] = useDarkSurfaces ? _darkButtonPressedBrush : _brandDarkBrush;
            application.Resources["AppButtonForegroundBrush"] = _whiteBrush;
        }

        private static void ApplyCdsResources(Application application)
        {
            application.Resources["AppPrimaryBrush"] = _brandPrimaryBrush;
            application.Resources["AppAccentBrush"] = _brandAccentBrush;
            application.Resources["AppMenuBackgroundBrush"] = _brandDarkBrush;
            application.Resources["AppMenuForegroundBrush"] = _whiteBrush;
            application.Resources["AppForegroundBrush"] = _cdsForegroundBrush;
            application.Resources["AppSecondaryForegroundBrush"] = _cdsSecondaryForegroundBrush;
            application.Resources["AppToolbarBackgroundBrush"] = _cdsToolbarBrush;
            application.Resources["AppTableHeaderBackgroundBrush"] = _cdsTableHeaderBrush;
            application.Resources["AppCardBackgroundBrush"] = _cdsCardBrush;
            application.Resources["AppStatusBackgroundBrush"] = _cdsStatusBrush;
            application.Resources["AppBorderBrush"] = _cdsBorderBrush;
            application.Resources["AppButtonBackgroundBrush"] = _brandPrimaryBrush;
            application.Resources["AppButtonHoverBackgroundBrush"] = _brandHoverBrush;
            application.Resources["AppButtonPressedBackgroundBrush"] = _brandAccentBrush;
            application.Resources["AppButtonForegroundBrush"] = _whiteBrush;
        }

        private void Application_ActualThemeVariantChanged(object? sender, EventArgs e)
        {
            var application = Application.Current;
            if (application == null)
            {
                return;
            }

            ApplyThemeResources(application, NormalizeTheme(SettingsManager.Settings.AppTheme));
        }

        private static bool ShouldUseDarkSurfaces(Application application, string normalizedTheme)
        {
            if (normalizedTheme == "Dark")
            {
                return true;
            }

            if (normalizedTheme != "Auto")
            {
                return false;
            }

            return application.PlatformSettings?.GetColorValues().ThemeVariant switch
            {
                PlatformThemeVariant.Dark => true,
                PlatformThemeVariant.Light => false,
                _ => application.ActualThemeVariant == ThemeVariant.Dark
            };
        }

        private static string NormalizeTheme(string themeName)
        {
            return themeName switch
            {
                "Light" => "Light",
                "Dark" => "Dark",
                "ColDog Studios" => "CDS",
                "CDS" => "CDS",
                _ => "Auto"
            };
        }
    }
}

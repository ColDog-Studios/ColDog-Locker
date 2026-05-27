using System.Windows;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using Microsoft.Win32;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Services
{
    /// <summary>
    ///     Service for managing application theme
    /// </summary>
    public class ThemeService : IThemeService
    {
        private const string ThemeSettingKey = "AppTheme";

        public AppTheme CurrentTheme { get; private set; } = AppTheme.ColDogStudios;

        public Task SetThemeAsync(AppTheme theme)
        {
            CurrentTheme = theme;

            // Save to application settings
            SettingsManager.Settings.AppTheme = theme.ToString();
            SettingsManager.SaveSettings();

            // Apply theme to application
            ApplyTheme(theme);

            return Task.CompletedTask;
        }

        public Task LoadThemeAsync()
        {
            // Load from application settings
            var savedTheme = SettingsManager.Settings.AppTheme;

            if (!string.IsNullOrEmpty(savedTheme) && Enum.TryParse<AppTheme>(savedTheme, out var theme))
            {
                CurrentTheme = theme;
            }
            else
            {
                // Default to ColDogStudios theme
                CurrentTheme = AppTheme.ColDogStudios;
            }

            ApplyTheme(CurrentTheme);

            return Task.CompletedTask;
        }

        private static AppTheme DetectWindowsTheme()
        {
            try
            {
                // Check Windows Registry for light/dark theme preference
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                var value = key?.GetValue("AppsUseLightTheme");

                if (value is int themeValue)
                {
                    return themeValue == 1 ? AppTheme.Light : AppTheme.Dark;
                }
            }
            catch
            {
                // If detection fails, default to Light theme
            }

            return AppTheme.Light;
        }

        private void ApplyTheme(AppTheme theme)
        {
            var app = System.Windows.Application.Current;
            if (app == null)
            {
                return;
            }

            // If Auto theme, detect Windows theme
            var effectiveTheme = theme;
            if (theme == AppTheme.Auto)
            {
                effectiveTheme = DetectWindowsTheme();
            }

            // Clear existing theme dictionaries (but keep Base.xaml)
            var themeDictionaries = app.Resources.MergedDictionaries
                .Where(d => d.Source != null &&
                            d.Source.OriginalString.Contains("Themes/") &&
                            !d.Source.OriginalString.Contains("Base.xaml"))
                .ToList();

            foreach (var dict in themeDictionaries)
            {
                app.Resources.MergedDictionaries.Remove(dict);
            }

            // Ensure Base.xaml is loaded
            var hasBase = app.Resources.MergedDictionaries.Any(d =>
                d.Source != null && d.Source.OriginalString.Contains("Base.xaml"));

            if (!hasBase)
            {
                app.Resources.MergedDictionaries.Insert(0,
                    new ResourceDictionary { Source = new Uri("Themes/Base.xaml", UriKind.Relative) });
            }

            // Add new theme dictionary
            var themeUri = effectiveTheme switch
            {
                AppTheme.Light => new Uri("Themes/LightTheme.xaml", UriKind.Relative),
                AppTheme.Dark => new Uri("Themes/DarkTheme.xaml", UriKind.Relative),
                AppTheme.ColDogStudios => new Uri("Themes/ColDogStudiosTheme.xaml", UriKind.Relative),
                _ => new Uri("Themes/ColDogStudiosTheme.xaml", UriKind.Relative)
            };

            app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });
        }
    }
}

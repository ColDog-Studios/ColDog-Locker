using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using Application = System.Windows.Application;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Services;

/// <summary>
/// Service for managing application theme
/// </summary>
public class ThemeService : IThemeService
{
    private const string ThemeSettingKey = "AppTheme";
    private AppTheme _currentTheme = AppTheme.ColDogStudios;

    public AppTheme CurrentTheme => _currentTheme;

    public Task SetThemeAsync(AppTheme theme)
    {
        _currentTheme = theme;
        
        // Save to application settings
        Properties.Settings.Default.AppTheme = theme.ToString();
        Properties.Settings.Default.Save();
        
        // Apply theme to application
        ApplyTheme(theme);
        
        return Task.CompletedTask;
    }

    public Task LoadThemeAsync()
    {
        // Load from application settings
        var savedTheme = Properties.Settings.Default.AppTheme;
        
        if (!string.IsNullOrEmpty(savedTheme) && Enum.TryParse<AppTheme>(savedTheme, out var theme))
        {
            _currentTheme = theme;
        }
        else
        {
            // Default to ColDogStudios theme
            _currentTheme = AppTheme.ColDogStudios;
        }
        
        ApplyTheme(_currentTheme);
        
        return Task.CompletedTask;
    }

    private AppTheme DetectWindowsTheme()
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
        if (app == null) return;

        // If Auto theme, detect Windows theme
        var effectiveTheme = theme;
        if (theme == AppTheme.Auto)
        {
            effectiveTheme = DetectWindowsTheme();
        }

        // Clear existing theme dictionaries
        var themeDictionaries = app.Resources.MergedDictionaries
            .Where(d => d.Source != null && d.Source.OriginalString.Contains("Themes/"))
            .ToList();

        foreach (var dict in themeDictionaries)
        {
            app.Resources.MergedDictionaries.Remove(dict);
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

using System.Threading.Tasks;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Services;

/// <summary>
/// Available application themes
/// </summary>
public enum AppTheme
{
    Auto,
    Light,
    Dark,
    ColDogStudios
}

/// <summary>
/// Service for managing application theme
/// </summary>
public interface IThemeService
{
    /// <summary>
    /// Gets the current theme
    /// </summary>
    AppTheme CurrentTheme { get; }

    /// <summary>
    /// Sets the application theme
    /// </summary>
    /// <param name="theme">The theme to set</param>
    Task SetThemeAsync(AppTheme theme);

    /// <summary>
    /// Loads the saved theme from settings
    /// </summary>
    Task LoadThemeAsync();
}

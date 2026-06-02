namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public interface IAppThemeService
    {
        string CurrentTheme { get; }
        void ApplySavedTheme();
        void SetTheme(string themeName);
    }
}

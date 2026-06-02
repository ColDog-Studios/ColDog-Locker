using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class AvaloniaUserDialogService : IUserDialogService
    {
        private readonly IAppThemeService _themeService;

        public AvaloniaUserDialogService(IAppThemeService themeService)
        {
            _themeService = themeService;
        }

        public Task ShowMessageAsync(string title, string message)
        {
            return ShowDialogAsync(new MessageDialog(title, message, MessageDialogKind.Information));
        }

        public Task ShowErrorAsync(string title, string message, Exception? exception = null)
        {
            return ShowDialogAsync(new MessageDialog(title, exception == null ? message : $"{message}\n\n{exception}", MessageDialogKind.Error));
        }

        public Task ShowWarningAsync(string title, string message)
        {
            return ShowDialogAsync(new MessageDialog(title, message, MessageDialogKind.Warning));
        }

        public Task<bool> ConfirmAsync(string title, string message)
        {
            return ShowDialogAsync<bool>(new MessageDialog(title, message, MessageDialogKind.Confirmation));
        }

        public Task<string?> PromptPasswordAsync(string title)
        {
            return ShowDialogAsync<string>(new PasswordDialog(title));
        }

        public Task<NewLockerRequest?> ShowNewLockerAsync()
        {
            return ShowDialogAsync<NewLockerRequest>(new NewLockerDialog());
        }

        public Task ShowLockerPropertiesAsync(LockerModel locker)
        {
            return ShowDialogAsync(new LockerPropertiesDialog(locker));
        }

        public async Task ShowSettingsAsync()
        {
            var theme = await ShowDialogAsync<string>(new SettingsDialog(_themeService));
            if (!string.IsNullOrWhiteSpace(theme))
            {
                _themeService.SetTheme(theme);
            }
        }

        public Task ShowAboutAsync()
        {
            return ShowDialogAsync(new AboutDialog());
        }

        public Task ShowDevInfoAsync()
        {
            var message =
                $"Version: {AppInfo.SemanticVersion}\n" +
                $"Config: {AppPaths.LocalConfig}\n" +
                $"Base directory: {AppContext.BaseDirectory}\n" +
                $".NET: {Environment.Version}\n" +
                $"OS: {Environment.OSVersion}";
            return ShowDialogAsync(new MessageDialog("Developer Info", message, MessageDialogKind.Information));
        }

        private static Window Owner
        {
            get
            {
                if (global::Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop &&
                    desktop.MainWindow is { } mainWindow)
                {
                    return mainWindow;
                }

                throw new InvalidOperationException("No Avalonia main window is available for dialog ownership.");
            }
        }

        private static async Task ShowDialogAsync(Window dialog)
        {
            await dialog.ShowDialog<object?>(Owner);
        }

        private static Task<T?> ShowDialogAsync<T>(Window dialog)
        {
            return dialog.ShowDialog<T?>(Owner);
        }
    }
}

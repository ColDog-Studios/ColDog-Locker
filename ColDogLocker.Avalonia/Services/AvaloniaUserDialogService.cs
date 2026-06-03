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

using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class AvaloniaUserDialogService : IUserDialogService
    {
        private readonly IAppThemeService _themeService;
        private readonly IPlatformService _platformService;
        private readonly UpdateWorkflow _updateWorkflow;

        public AvaloniaUserDialogService(
            IAppThemeService themeService,
            IPlatformService platformService,
            UpdateWorkflow updateWorkflow)
        {
            _themeService = themeService;
            _platformService = platformService;
            _updateWorkflow = updateWorkflow;
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
            var theme = await ShowDialogAsync<string>(new SettingsDialog(_themeService, _platformService));
            if (!string.IsNullOrWhiteSpace(theme))
            {
                _themeService.SetTheme(theme);
            }
        }

        public Task ShowAboutAsync()
        {
            return ShowDialogAsync(new AboutDialog(_platformService, _updateWorkflow));
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

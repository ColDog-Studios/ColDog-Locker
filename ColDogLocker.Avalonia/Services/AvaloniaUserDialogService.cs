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
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class AvaloniaUserDialogService : IUserDialogService
    {
        private readonly IPlatformService _platformService;
        private readonly IAppThemeService _themeService;
        private readonly AvaloniaUpdateDialogHost _updateDialogHost;
        private readonly UpdateWorkflow _updateWorkflow;

        public AvaloniaUserDialogService(
            IAppThemeService themeService,
            IPlatformService platformService,
            AvaloniaUpdateDialogHost updateDialogHost,
            UpdateWorkflow updateWorkflow)
        {
            _themeService = themeService;
            _platformService = platformService;
            _updateDialogHost = updateDialogHost;
            _updateWorkflow = updateWorkflow;
        }

        private static Window Owner
        {
            get
            {
                if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop &&
                    desktop.MainWindow is { } mainWindow)
                {
                    return mainWindow;
                }

                throw new InvalidOperationException("No Avalonia main window is available for dialog ownership.");
            }
        }

        public Task ShowMessageAsync(string title, string message)
        {
            return ShowDialogAsync(new MessageDialog(title, message, MessageDialogKind.Information));
        }

        public Task ShowErrorAsync(string title, string message, Exception? exception = null)
        {
            Window dialog = exception == null
                ? new MessageDialog(title, message, MessageDialogKind.Error)
                : new ErrorDialog(title, message, exception, _platformService);

            return ShowDialogAsync(dialog);
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
            var theme = await ShowDialogAsync<string>(
                new SettingsDialog(_themeService, _platformService, _updateWorkflow, _updateDialogHost));
            if (!string.IsNullOrWhiteSpace(theme))
            {
                _themeService.SetTheme(theme);
            }
        }

        public Task ShowAboutAsync()
        {
            return ShowDialogAsync(new AboutDialog(_platformService));
        }

        public Task ShowDevInfoAsync()
        {
            return ShowDialogAsync(new DevDialog(_platformService));
        }

        public async Task ShowProgressTestAsync()
        {
            var dialog = new ProgressDialog("Test Progress Dialog");
            dialog.SetIndeterminate("Preparing progress dialog test...");

            var progressTask = RunProgressTestAsync(dialog);
            await ShowDialogAsync(dialog);
            await progressTask;
        }

        private static async Task RunProgressTestAsync(ProgressDialog dialog)
        {
            await Task.Delay(650);

            const int total = 5;
            for (var current = 1; current <= total; current++)
            {
                dialog.UpdateProgress(current, total, $"Processing test item {current} of {total}...");
                await Task.Delay(550);
            }

            dialog.Complete("Progress dialog test complete.");
            await Task.Delay(900);
            dialog.Close();
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

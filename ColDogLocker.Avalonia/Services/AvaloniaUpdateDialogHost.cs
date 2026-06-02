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

using ColDogStudios.ColDogLocker.Services.Updates;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class AvaloniaUpdateDialogHost : IUpdateDialogHost
    {
        public Task ShowMessageAsync(UpdateDialogMessage message, CancellationToken cancellationToken = default)
        {
            return ShowDialogAsync(new MessageDialog(message.Title, message.Message, MessageDialogKind.Information));
        }

        public Task<bool> ConfirmDownloadAsync(UpdateDialogMessage prompt, CancellationToken cancellationToken = default)
        {
            return ShowDialogAsync<bool>(new MessageDialog(prompt.Title, prompt.Message, MessageDialogKind.Confirmation));
        }

        public Task ShowErrorAsync(UpdateDialogError error, CancellationToken cancellationToken = default)
        {
            var message = error.Exception == null
                ? error.Message
                : $"{error.Message}\n\n{error.Exception}";
            return ShowDialogAsync(new MessageDialog(error.Title, message, MessageDialogKind.Error));
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

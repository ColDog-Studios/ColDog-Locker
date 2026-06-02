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

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class AvaloniaUpdateDialogHost : IUpdateDialogHost
    {
        private readonly IUserDialogService _dialogs;

        public AvaloniaUpdateDialogHost(IUserDialogService dialogs)
        {
            _dialogs = dialogs;
        }

        public Task ShowMessageAsync(UpdateDialogMessage message, CancellationToken cancellationToken = default)
        {
            return _dialogs.ShowMessageAsync(message.Title, message.Message);
        }

        public Task<bool> ConfirmDownloadAsync(UpdateDialogMessage prompt, CancellationToken cancellationToken = default)
        {
            return _dialogs.ConfirmAsync(prompt.Title, prompt.Message);
        }

        public Task ShowErrorAsync(UpdateDialogError error, CancellationToken cancellationToken = default)
        {
            return _dialogs.ShowErrorAsync(error.Title, error.Message, error.Exception);
        }
    }
}

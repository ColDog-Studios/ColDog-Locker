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

using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public interface IUserDialogService
    {
        Task ShowMessageAsync(string title, string message);
        Task ShowErrorAsync(string title, string message, Exception? exception = null);
        Task ShowWarningAsync(string title, string message);
        Task<bool> ConfirmAsync(string title, string message);
        Task<string?> PromptPasswordAsync(string title);
        Task<NewLockerRequest?> ShowNewLockerAsync();
        Task ShowLockerPropertiesAsync(LockerModel locker);
        Task ShowSettingsAsync();
        Task ShowAboutAsync();
        Task ShowDevInfoAsync();
        Task ShowProgressTestAsync();
    }
}

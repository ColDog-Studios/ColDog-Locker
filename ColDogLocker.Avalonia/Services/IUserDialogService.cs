using ColDogStudios.ColDogLocker.Avalonia.Models;
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
    }
}

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

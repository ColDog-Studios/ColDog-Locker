using System.Windows;
using ColDogStudios.ColDogLocker.Gui.WPF.Dialogs;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Services
{
    internal static class WpfUpdateWorkflow
    {
        public static async Task RunAsync(Window owner)
        {
            using var updateService = GitHubUpdateService.CreateDefault();
            var workflow = new UpdateWorkflow(updateService, new WpfUpdateDialogHost(owner));
            await workflow.RunAsync();
        }
    }

    internal sealed class WpfUpdateDialogHost : IUpdateDialogHost
    {
        private readonly Window _owner;

        public WpfUpdateDialogHost(Window owner)
        {
            _owner = owner;
        }

        public Task ShowMessageAsync(UpdateDialogMessage message, CancellationToken cancellationToken = default)
        {
            MessageDialog.ShowInformation(message.Message, message.Title, _owner);
            return Task.CompletedTask;
        }

        public Task<bool> ConfirmDownloadAsync(UpdateDialogMessage prompt, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(MessageDialog.ShowQuestion(prompt.Message, prompt.Title, _owner));
        }

        public Task ShowErrorAsync(UpdateDialogError error, CancellationToken cancellationToken = default)
        {
            ErrorDialog.Show(error.Message, error.Exception, error.Title, _owner);
            return Task.CompletedTask;
        }
    }
}

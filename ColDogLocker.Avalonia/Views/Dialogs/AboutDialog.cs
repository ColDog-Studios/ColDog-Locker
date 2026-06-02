using Avalonia.Controls;
using ColDogStudios.ColDogLocker.Core.Environment;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class AboutDialog : Window
    {
        public AboutDialog()
        {
            Title = "About ColDog Locker";
            Width = 520;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var closeButton = DialogHelpers.Button("Close");
            closeButton.Click += (_, _) => Close();

            Content = new StackPanel
            {
                Margin = new global::Avalonia.Thickness(18),
                Spacing = 12,
                Children =
                {
                    new TextBlock
                    {
                        Text = "ColDog Locker",
                        FontSize = 22,
                        FontWeight = global::Avalonia.Media.FontWeight.SemiBold
                    },
                    DialogHelpers.Body($"Version {AppInfo.SemanticVersion}\nSecure file locker by ColDog Studios.\n\n.NET {Environment.Version}\n{Environment.OSVersion}"),
                    DialogHelpers.Buttons(closeButton)
                }
            };
        }
    }
}

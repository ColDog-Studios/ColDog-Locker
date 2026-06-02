using Avalonia.Controls;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class PasswordDialog : Window
    {
        public PasswordDialog(string title)
        {
            Title = title;
            Width = 420;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var passwordBox = new TextBox
            {
                PasswordChar = '*',
                PlaceholderText = "Password"
            };

            var okButton = DialogHelpers.Button("OK");
            okButton.IsEnabled = false;
            okButton.Click += (_, _) => Close(passwordBox.Text ?? string.Empty);

            passwordBox.PropertyChanged += (_, args) =>
            {
                if (args.Property == TextBox.TextProperty)
                {
                    okButton.IsEnabled = !string.IsNullOrWhiteSpace(passwordBox.Text);
                }
            };

            var cancelButton = DialogHelpers.Button("Cancel");
            cancelButton.Click += (_, _) => Close(null);

            Content = new StackPanel
            {
                Margin = new global::Avalonia.Thickness(18),
                Spacing = 16,
                Children =
                {
                    DialogHelpers.Field("Password", passwordBox),
                    DialogHelpers.Buttons(cancelButton, okButton)
                }
            };
        }
    }
}

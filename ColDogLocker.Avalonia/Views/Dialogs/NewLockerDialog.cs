using Avalonia.Controls;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Services.Configuration;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class NewLockerDialog : Window
    {
        public NewLockerDialog()
        {
            Title = "New Locker";
            Width = 560;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var nameBox = new TextBox { PlaceholderText = "Locker name" };
            var locationBox = new TextBox { Text = SettingsManager.Settings.DefaultLockerLocation, PlaceholderText = "Folder path" };
            var passwordBox = new TextBox { PasswordChar = '*', PlaceholderText = "Password" };
            var confirmBox = new TextBox { PasswordChar = '*', PlaceholderText = "Confirm password" };
            var errorText = new TextBlock { Foreground = global::Avalonia.Media.Brushes.Firebrick, TextWrapping = global::Avalonia.Media.TextWrapping.Wrap };

            var browseButton = DialogHelpers.Button("Browse");
            browseButton.Click += async (_, _) =>
            {
                var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
                {
                    Title = "Select locker folder",
                    AllowMultiple = false
                });

                if (folders.Count > 0)
                {
                    locationBox.Text = folders[0].TryGetLocalPath() ?? locationBox.Text;
                }
            };

            var createButton = DialogHelpers.Button("Create");
            createButton.Click += (_, _) =>
            {
                var validationError = Validate(nameBox.Text, locationBox.Text, passwordBox.Text, confirmBox.Text);
                if (validationError != null)
                {
                    errorText.Text = validationError;
                    return;
                }

                Close(new NewLockerRequest
                {
                    LockerName = nameBox.Text!.Trim(),
                    Location = locationBox.Text!.Trim(),
                    Password = passwordBox.Text!
                });
            };

            var cancelButton = DialogHelpers.Button("Cancel");
            cancelButton.Click += (_, _) => Close(null);

            var locationPanel = new Grid
            {
                ColumnDefinitions =
                {
                    new ColumnDefinition(GridLength.Star),
                    new ColumnDefinition(GridLength.Auto)
                },
                ColumnSpacing = 8
            };
            locationPanel.Children.Add(locationBox);
            Grid.SetColumn(browseButton, 1);
            locationPanel.Children.Add(browseButton);

            Content = new StackPanel
            {
                Margin = new global::Avalonia.Thickness(18),
                Spacing = 14,
                Children =
                {
                    DialogHelpers.Field("Name", nameBox),
                    DialogHelpers.Field("Location", locationPanel),
                    DialogHelpers.Field("Password", passwordBox),
                    DialogHelpers.Field("Confirm Password", confirmBox),
                    errorText,
                    DialogHelpers.Buttons(cancelButton, createButton)
                }
            };
        }

        private static string? Validate(string? name, string? location, string? password, string? confirmPassword)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return "Locker name is required.";
            }

            if (string.IsNullOrWhiteSpace(location))
            {
                return "Locker location is required.";
            }

            var passwordError = PasswordFilter.ValidatePassword(password ?? string.Empty);
            if (passwordError != null)
            {
                return passwordError;
            }

            if (!string.Equals(password, confirmPassword, StringComparison.Ordinal))
            {
                return "Passwords do not match.";
            }

            return null;
        }
    }
}

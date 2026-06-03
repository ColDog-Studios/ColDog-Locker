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

using Avalonia.Controls;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Services.Configuration;
using System.IO;

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

            var defaultBasePath = GetDefaultBasePath();
            var isCustomPath = false;
            var isUpdatingLocation = false;

            var nameBox = new TextBox { PlaceholderText = "Locker name" };
            var locationBox = new TextBox { PlaceholderText = "Folder path" };
            var passwordBox = new TextBox { PasswordChar = '*', PlaceholderText = "Password" };
            var confirmBox = new TextBox { PasswordChar = '*', PlaceholderText = "Confirm password" };
            var errorText = new TextBlock { Foreground = global::Avalonia.Media.Brushes.Firebrick, TextWrapping = global::Avalonia.Media.TextWrapping.Wrap };

            void SetLocation(string value)
            {
                isUpdatingLocation = true;
                locationBox.Text = value;
                isUpdatingLocation = false;
            }

            void UpdateDefaultLocation()
            {
                if (isCustomPath)
                {
                    return;
                }

                var lockerName = nameBox.Text?.Trim();
                if (!string.IsNullOrWhiteSpace(lockerName))
                {
                    lockerName = Path.GetFileName(lockerName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                }

                SetLocation(string.IsNullOrWhiteSpace(lockerName)
                    ? string.Empty
                    : Path.Combine(defaultBasePath, lockerName));
            }

            nameBox.TextChanged += (_, _) => UpdateDefaultLocation();
            locationBox.TextChanged += (_, _) =>
            {
                if (!isUpdatingLocation && locationBox.IsFocused)
                {
                    isCustomPath = true;
                }
            };

            var browseButton = DialogHelpers.Button("Browse");
            browseButton.Click += async (_, _) =>
            {
                var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
                {
                    Title = "Select folder to lock",
                    AllowMultiple = false
                });

                if (folders.Count > 0)
                {
                    var selectedPath = folders[0].TryGetLocalPath() ?? folders[0].Path.LocalPath;
                    isCustomPath = true;
                    SetLocation(selectedPath);

                    var selectedName = GetFolderName(selectedPath);
                    if (!string.IsNullOrWhiteSpace(selectedName))
                    {
                        nameBox.Text = selectedName;
                    }
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

        private static string GetDefaultBasePath()
        {
            var defaultBasePath = SettingsManager.Settings.DefaultLockerLocation;
            if (string.IsNullOrWhiteSpace(defaultBasePath))
            {
                return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            }

            try
            {
                Directory.CreateDirectory(defaultBasePath);
                return defaultBasePath;
            }
            catch
            {
                return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            }
        }

        private static string GetFolderName(string path)
        {
            var trimmedPath = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return Path.GetFileName(trimmedPath);
        }
    }
}

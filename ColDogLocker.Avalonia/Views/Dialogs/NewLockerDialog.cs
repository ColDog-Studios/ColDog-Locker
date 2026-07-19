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
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Validation;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class NewLockerDialog : Window
    {
        private readonly string _defaultBasePath;
        private bool _isCustomPath;
        private bool _isUpdatingLocation;

        public NewLockerDialog()
        {
            InitializeComponent();

            _defaultBasePath = GetDefaultBasePath();

            NameBox.TextChanged += (_, _) =>
            {
                UpdateDefaultLocation();
                UpdateCreateButtonState();
            };
            LocationBox.TextChanged += (_, _) =>
            {
                if (!_isUpdatingLocation && LocationBox.IsFocused)
                {
                    _isCustomPath = true;
                }

                UpdateCreateButtonState();
            };
            PasswordBox.TextChanged += (_, _) =>
            {
                UpdatePasswordRequirements();
                UpdateCreateButtonState();
            };
            ConfirmBox.TextChanged += (_, _) => UpdateCreateButtonState();
            BrowseButton.Click += BrowseButton_Click;
            CreateButton.Click += CreateButton_Click;
            CancelButton.Click += CancelButton_Click;

            UpdatePasswordRequirements();
            UpdateCreateButtonState();
        }

        private void SetLocation(string value)
        {
            _isUpdatingLocation = true;
            LocationBox.Text = value;
            _isUpdatingLocation = false;
        }

        private void UpdateDefaultLocation()
        {
            if (_isCustomPath)
            {
                return;
            }

            var lockerName = NameBox.Text?.Trim();
            if (!string.IsNullOrWhiteSpace(lockerName))
            {
                lockerName = Path.GetFileName(lockerName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }

            SetLocation(string.IsNullOrWhiteSpace(lockerName)
                ? string.Empty
                : Path.Join(_defaultBasePath, lockerName));
        }

        private async void BrowseButton_Click(object? sender, RoutedEventArgs e)
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Select folder to lock", AllowMultiple = false });

            if (folders.Count <= 0)
            {
                return;
            }

            var selectedPath = folders[0].TryGetLocalPath() ?? folders[0].Path.LocalPath;
            _isCustomPath = true;
            SetLocation(selectedPath);

            var selectedName = GetFolderName(selectedPath);
            if (!string.IsNullOrWhiteSpace(selectedName))
            {
                NameBox.Text = selectedName;
            }

            UpdateCreateButtonState();
        }

        private void CreateButton_Click(object? sender, RoutedEventArgs e)
        {
            var validationError = Validate(NameBox.Text, LocationBox.Text, PasswordBox.Text, ConfirmBox.Text);
            if (validationError != null)
            {
                ErrorText.Text = validationError;
                return;
            }

            Close(new NewLockerRequest { LockerName = NameBox.Text!.Trim(), Location = LocationBox.Text!.Trim(), Password = PasswordBox.Text! });
        }

        private void CancelButton_Click(object? sender, RoutedEventArgs e)
        {
            Close(null);
        }

        private void UpdateCreateButtonState()
        {
            var validationError = Validate(NameBox.Text, LocationBox.Text, PasswordBox.Text, ConfirmBox.Text);
            CreateButton.IsEnabled = validationError == null;
            if (validationError == null || string.IsNullOrWhiteSpace(ErrorText.Text))
            {
                ErrorText.Text = string.Empty;
            }
        }

        private void UpdatePasswordRequirements()
        {
            PasswordRequirementsPanel.Children.Clear();

            foreach (var requirement in PasswordFilter.Validate(PasswordBox.Text ?? string.Empty))
            {
                var brush = requirement.IsMet ? Brushes.ForestGreen : Brushes.Gray;
                var row = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    Spacing = 8,
                    Children =
                    {
                        new TextBlock
                        {
                            Text = requirement.IsMet ? "✓" : "○",
                            Width = 18,
                            FontSize = 14,
                            Foreground = brush,
                            VerticalAlignment = VerticalAlignment.Center
                        },
                        new TextBlock { Text = requirement.Description, FontSize = 12, Foreground = brush, VerticalAlignment = VerticalAlignment.Center }
                    }
                };

                PasswordRequirementsPanel.Children.Add(row);
            }
        }

        private static string? Validate(string? name, string? location, string? password, string? confirmPassword)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return "Locker name is required.";
            }

            var trimmedName = name.Trim();
            if (Path.IsPathRooted(trimmedName) ||
                trimmedName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                trimmedName.Contains(Path.DirectorySeparatorChar) ||
                trimmedName.Contains(Path.AltDirectorySeparatorChar) ||
                trimmedName is "." or "..")
            {
                return "Locker name must be a valid file name, not a path.";
            }

            if (string.IsNullOrWhiteSpace(location))
            {
                return "Locker location is required.";
            }

            var pathValidationError = LockerPathFilter.ValidatePath(location);
            if (pathValidationError != null)
            {
                return pathValidationError;
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
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException or PathTooLongException or ArgumentException or System.Security.SecurityException)
            {
                Logger.Log(LogLevel.Warning, $"Could not create configured default locker directory '{defaultBasePath}'; using Documents instead.", ex);
                return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, $"Could not create configured default locker directory '{defaultBasePath}'; using Documents instead.", ex);
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

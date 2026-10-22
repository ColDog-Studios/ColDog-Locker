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
using ColDogStudios.ColDogLocker.Core.Validation;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class PasswordDialog : Window
    {
        private readonly bool _requireNewPassword;

        public PasswordDialog()
        {
            InitializeComponent();

            Opened += (_, _) => PasswordBox.Focus();
            Closed += (_, _) =>
            {
                PasswordBox.Text = string.Empty;
                ConfirmPasswordBox.Text = string.Empty;
            };
            ShowPasswordCheckBox.IsCheckedChanged += (_, _) =>
            {
                var passwordChar = ShowPasswordCheckBox.IsChecked == true ? '\0' : '*';
                PasswordBox.PasswordChar = passwordChar;
                ConfirmPasswordBox.PasswordChar = passwordChar;
            };
            OkButton.Click += OkButton_Click;
            CancelButton.Click += CancelButton_Click;
            PasswordBox.PropertyChanged += (_, args) =>
            {
                if (args.Property == TextBox.TextProperty)
                {
                    UpdatePasswordState();
                }
            };
            ConfirmPasswordBox.TextChanged += (_, _) => UpdatePasswordState();
        }

        public PasswordDialog(string title, bool requireNewPassword = false)
            : this()
        {
            Title = title;
            _requireNewPassword = requireNewPassword;
            PasswordRequirementsContainer.IsVisible = requireNewPassword;
            ConfirmationPanel.IsVisible = requireNewPassword;
            if (requireNewPassword)
            {
                PasswordLabel.Text = "New password";
                PasswordBox.PlaceholderText = "New password";
                OkButton.Content = "Change Password";
            }

            UpdatePasswordState();
        }

        private void UpdatePasswordState()
        {
            var password = PasswordBox.Text ?? string.Empty;
            if (_requireNewPassword)
            {
                PasswordRequirementsPresenter.Update(PasswordRequirementsPanel, password);
            }

            var matches = password == (ConfirmPasswordBox.Text ?? string.Empty);
            MismatchText.IsVisible = _requireNewPassword && !string.IsNullOrEmpty(ConfirmPasswordBox.Text) && !matches;
            OkButton.IsEnabled = _requireNewPassword
                ? PasswordFilter.ValidatePassword(password) == null && matches
                : !string.IsNullOrWhiteSpace(password);
        }

        private void OkButton_Click(object? sender, RoutedEventArgs e)
        {
            if (OkButton.IsEnabled)
            {
                Close(PasswordBox.Text ?? string.Empty);
            }
        }

        private void CancelButton_Click(object? sender, RoutedEventArgs e)
        {
            Close(null);
        }
    }
}

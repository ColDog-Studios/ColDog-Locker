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

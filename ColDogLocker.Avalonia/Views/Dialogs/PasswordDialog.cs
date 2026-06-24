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

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class PasswordDialog : Window
    {
        public PasswordDialog()
        {
            InitializeComponent();

            OkButton.Click += OkButton_Click;
            CancelButton.Click += CancelButton_Click;
            PasswordBox.PropertyChanged += (_, args) =>
            {
                if (args.Property == TextBox.TextProperty)
                {
                    OkButton.IsEnabled = !string.IsNullOrWhiteSpace(PasswordBox.Text);
                }
            };
        }

        public PasswordDialog(string title)
            : this()
        {
            Title = title;
        }

        private void OkButton_Click(object? sender, RoutedEventArgs e)
        {
            Close(PasswordBox.Text ?? string.Empty);
        }

        private void CancelButton_Click(object? sender, RoutedEventArgs e)
        {
            Close(null);
        }
    }
}

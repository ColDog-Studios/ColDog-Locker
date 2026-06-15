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
using Avalonia.Media;
using Material.Icons;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public enum MessageDialogKind
    {
        Information,
        Error,
        Warning,
        Confirmation
    }

    public sealed partial class MessageDialog : Window
    {
        private MessageDialogKind _kind;

        public MessageDialog()
        {
            InitializeComponent();

            OkButton.Click += OkButton_Click;
            CancelButton.Click += CancelButton_Click;
            Configure("Message", string.Empty, MessageDialogKind.Information);
        }

        public MessageDialog(string title, string message, MessageDialogKind kind)
            : this()
        {
            Configure(title, message, kind);
        }

        private void Configure(string title, string message, MessageDialogKind kind)
        {
            _kind = kind;
            Title = title;
            MessageText.Text = message;
            DialogIcon.Kind = IconKind(kind);
            DialogIcon.Foreground = IconBrush(kind);
            OkButton.Content = kind == MessageDialogKind.Confirmation ? "Yes" : "OK";
            CancelButton.IsVisible = kind == MessageDialogKind.Confirmation;
        }

        private void OkButton_Click(object? sender, global::Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close(_kind != MessageDialogKind.Error);
        }

        private void CancelButton_Click(object? sender, global::Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close(false);
        }

        private static MaterialIconKind IconKind(MessageDialogKind kind)
        {
            return kind switch
            {
                MessageDialogKind.Error => MaterialIconKind.AlertCircleOutline,
                MessageDialogKind.Warning => MaterialIconKind.AlertOutline,
                MessageDialogKind.Confirmation => MaterialIconKind.HelpCircleOutline,
                _ => MaterialIconKind.InformationOutline
            };
        }

        private static IBrush IconBrush(MessageDialogKind kind)
        {
            return new SolidColorBrush(Color.Parse(kind switch
            {
                MessageDialogKind.Error => "#E81123",
                MessageDialogKind.Warning => "#FFA500",
                _ => "#0077B6"
            }));
        }
    }
}

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
            DialogIcon.Data = IconData(kind);
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

        private static Geometry IconData(MessageDialogKind kind)
        {
            return Geometry.Parse(kind switch
            {
                MessageDialogKind.Error => "M12 2C6.48 2 2 6.48 2 12S6.48 22 12 22 22 17.52 22 12 17.52 2 12 2ZM7 7L17 17M17 7L7 17",
                MessageDialogKind.Warning => "M12 3L22 20H2L12 3ZM11 9H13V14H11V9ZM11 16H13V18H11V16Z",
                MessageDialogKind.Confirmation => "M12 2C6.48 2 2 6.48 2 12S6.48 22 12 22 22 17.52 22 12 17.52 2 12 2ZM11 17H13V19H11V17ZM12 5C14.21 5 16 6.79 16 9C16 11.5 13 11.75 13 14H11C11 10.75 14 10.5 14 9C14 7.9 13.1 7 12 7S10 7.9 10 9H8C8 6.79 9.79 5 12 5Z",
                _ => "M12 2C6.48 2 2 6.48 2 12S6.48 22 12 22 22 17.52 22 12 17.52 2 12 2ZM11 10H13V17H11V10ZM11 7H13V9H11V7Z"
            });
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

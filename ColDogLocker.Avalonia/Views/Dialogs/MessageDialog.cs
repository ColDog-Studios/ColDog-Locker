using Avalonia.Controls;
using Avalonia.Layout;
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

    public sealed class MessageDialog : Window
    {
        public MessageDialog(string title, string message, MessageDialogKind kind)
        {
            Title = title;
            Width = 520;
            MinHeight = 180;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var okButton = DialogHelpers.Button(kind == MessageDialogKind.Confirmation ? "Yes" : "OK");
            okButton.Click += (_, _) => Close(kind != MessageDialogKind.Error);

            var panel = new StackPanel
            {
                Margin = new global::Avalonia.Thickness(18),
                Spacing = 18
            };

            var messageContent = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto,*"),
                ColumnSpacing = 12
            };

            var icon = new PathIcon
            {
                Width = 28,
                Height = 28,
                Data = IconData(kind),
                Foreground = IconBrush(kind),
                VerticalAlignment = VerticalAlignment.Top
            };
            messageContent.Children.Add(icon);

            var scrollViewer = new ScrollViewer
            {
                MaxHeight = 360,
                Content = DialogHelpers.Body(message)
            };
            Grid.SetColumn(scrollViewer, 1);
            messageContent.Children.Add(scrollViewer);

            panel.Children.Add(messageContent);

            if (kind == MessageDialogKind.Confirmation)
            {
                var cancelButton = DialogHelpers.Button("No");
                cancelButton.Click += (_, _) => Close(false);
                panel.Children.Add(DialogHelpers.Buttons(cancelButton, okButton));
            }
            else
            {
                panel.Children.Add(DialogHelpers.Buttons(okButton));
            }

            Content = panel;
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

using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs;

public partial class MessageDialog : Window
{
    public enum MessageType
    {
        Information,
        Warning,
        Error,
        Question
    }

    public enum MessageButtons
    {
        OK,
        OKCancel,
        YesNo,
        YesNoCancel
    }

    public enum MessageResult
    {
        None,
        OK,
        Cancel,
        Yes,
        No
    }

    public MessageResult Result { get; private set; } = MessageResult.None;

    public MessageDialog(string message, string title = "Message", MessageType type = MessageType.Information, MessageButtons buttons = MessageButtons.OK)
    {
        InitializeComponent();
        
        Title = title;
        MessageText.Text = message;
        
        SetupIcon(type);
        SetupButtons(buttons);
    }

    private void SetupIcon(MessageType type)
    {
        switch (type)
        {
            case MessageType.Information:
                IconText.Text = "\uE946"; // Info icon
                IconText.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#0078D4"));
                break;
            case MessageType.Warning:
                IconText.Text = "\uE7BA"; // Warning icon
                IconText.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FFA500"));
                break;
            case MessageType.Error:
                IconText.Text = "\uE783"; // Error icon
                IconText.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#E81123"));
                break;
            case MessageType.Question:
                IconText.Text = "\uE897"; // Help icon
                IconText.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#0078D4"));
                break;
        }
    }

    private void SetupButtons(MessageButtons buttons)
    {
        ButtonPanel.Children.Clear();

        switch (buttons)
        {
            case MessageButtons.OK:
                AddButton("OK", MessageResult.OK, isDefault: true);
                break;
            case MessageButtons.OKCancel:
                AddButton("Cancel", MessageResult.Cancel, isCancel: true);
                AddButton("OK", MessageResult.OK, isDefault: true);
                break;
            case MessageButtons.YesNo:
                AddButton("No", MessageResult.No);
                AddButton("Yes", MessageResult.Yes, isDefault: true);
                break;
            case MessageButtons.YesNoCancel:
                AddButton("Cancel", MessageResult.Cancel, isCancel: true);
                AddButton("No", MessageResult.No);
                AddButton("Yes", MessageResult.Yes, isDefault: true);
                break;
        }
    }

    private void AddButton(string content, MessageResult result, bool isDefault = false, bool isCancel = false)
    {
        var button = new System.Windows.Controls.Button
        {
            Content = content,
            MinWidth = 80,
            Margin = new Thickness(10, 0, 0, 0),
            IsDefault = isDefault,
            IsCancel = isCancel
        };

        button.Click += (s, e) =>
        {
            Result = result;
            DialogResult = result == MessageResult.OK || result == MessageResult.Yes;
            Close();
        };

        ButtonPanel.Children.Add(button);
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        // Play scale-in animation if animations are enabled
        if (ColDogStudios.ColDogLocker.Gui.WPF.Properties.Settings.Default.EnableAnimations)
        {
            var animation = (Storyboard)TryFindResource("WindowScaleInAnimation");
            animation?.Begin(this);
        }
    }

    // Static helper methods for easy usage
    public static MessageResult Show(string message, string title = "Message", MessageType type = MessageType.Information, MessageButtons buttons = MessageButtons.OK, Window? owner = null)
    {
        var dialog = new MessageDialog(message, title, type, buttons);
        if (owner != null)
            dialog.Owner = owner;
        dialog.ShowDialog();
        return dialog.Result;
    }

    public static void ShowInformation(string message, string title = "Information", Window? owner = null)
    {
        Show(message, title, MessageType.Information, MessageButtons.OK, owner);
    }

    public static void ShowWarning(string message, string title = "Warning", Window? owner = null)
    {
        Show(message, title, MessageType.Warning, MessageButtons.OK, owner);
    }

    public static void ShowError(string message, string title = "Error", Window? owner = null)
    {
        Show(message, title, MessageType.Error, MessageButtons.OK, owner);
    }

    public static bool ShowQuestion(string message, string title = "Question", Window? owner = null)
    {
        var result = Show(message, title, MessageType.Question, MessageButtons.YesNo, owner);
        return result == MessageResult.Yes;
    }

    public static bool ShowConfirmation(string message, string title = "Confirm", Window? owner = null)
    {
        var result = Show(message, title, MessageType.Question, MessageButtons.OKCancel, owner);
        return result == MessageResult.OK;
    }
}

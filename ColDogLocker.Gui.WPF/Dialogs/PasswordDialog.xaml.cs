using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs
{
    public partial class PasswordDialog : Window
    {
        public string Password { get; private set; } = string.Empty;
        public bool RememberPassword { get; private set; }
        public bool Success { get; private set; }

        public PasswordDialog(string lockerName)
        {
            InitializeComponent();
            LockerNameText.Text = $"Enter password for: {lockerName}";
            OkButton.IsEnabled = false;

            // Focus password box when loaded
            Loaded += (s, e) => PasswordBox.Focus();
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            OkButton.IsEnabled = !string.IsNullOrWhiteSpace(PasswordBox.Password);
            ErrorText.Visibility = Visibility.Collapsed;
        }

        private void PasswordBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Enter && OkButton.IsEnabled)
            {
                OkButton_Click(sender, new RoutedEventArgs());
            }
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            Password = PasswordBox.Password;
            RememberPassword = RememberCheckBox.IsChecked ?? false;
            Success = true;
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Success = false;
            DialogResult = false;
            Close();
        }

        public void ShowError(string message)
        {
            ErrorText.Text = message;
            ErrorText.Visibility = Visibility.Visible;
            PasswordBox.Password = string.Empty;
            PasswordBox.Focus();
        }
    }
}

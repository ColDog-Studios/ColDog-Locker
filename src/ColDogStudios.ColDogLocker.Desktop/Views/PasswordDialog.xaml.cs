using System.Windows;
using System.Windows.Controls;

namespace ColDogStudios.ColDogLocker.Desktop.Views
{
    public partial class PasswordDialog : Window
    {
        public string Password { get; private set; } = string.Empty;

        public PasswordDialog(string message)
        {
            InitializeComponent();
            MessageTextBlock.Text = message;
            PasswordBox.Focus();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(PasswordBox.Password))
            {
                MessageBox.Show("Please enter a password.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                PasswordBox.Focus();
                return;
            }

            Password = PasswordBox.Password;
            DialogResult = true;
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            OkButton.IsEnabled = !string.IsNullOrEmpty(PasswordBox.Password);
        }
    }
}

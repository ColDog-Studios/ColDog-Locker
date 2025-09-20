using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using System.IO;

namespace ColDogStudios.ColDogLocker.Desktop.Views
{
    public partial class NewLockerDialog : Window
    {
        public string LockerName { get; private set; } = string.Empty;
        public string LockerPath { get; private set; } = string.Empty;

        public NewLockerDialog()
        {
            InitializeComponent();
            LockerNameTextBox.Focus();
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                CheckFileExists = false,
                CheckPathExists = true,
                Title = "Select Locker Directory",
                FileName = "Select Directory"
            };

            if (dialog.ShowDialog() == true)
            {
                var selectedPath = Path.GetDirectoryName(dialog.FileName);
                if (!string.IsNullOrEmpty(selectedPath))
                {
                    LockerPathTextBox.Text = selectedPath;
                }
            }
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(LockerNameTextBox.Text))
            {
                MessageBox.Show("Please enter a locker name.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                LockerNameTextBox.Focus();
                return;
            }

            if (string.IsNullOrWhiteSpace(LockerPathTextBox.Text))
            {
                MessageBox.Show("Please select a locker path.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                LockerPathTextBox.Focus();
                return;
            }

            if (!Directory.Exists(LockerPathTextBox.Text))
            {
                MessageBox.Show("The selected directory does not exist.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                LockerPathTextBox.Focus();
                return;
            }

            LockerName = LockerNameTextBox.Text.Trim();
            LockerPath = LockerPathTextBox.Text.Trim();
            DialogResult = true;
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        private void LockerNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            OkButton.IsEnabled = !string.IsNullOrWhiteSpace(LockerNameTextBox.Text) && 
                                !string.IsNullOrWhiteSpace(LockerPathTextBox.Text);
        }

        private void LockerPathTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            OkButton.IsEnabled = !string.IsNullOrWhiteSpace(LockerNameTextBox.Text) && 
                                !string.IsNullOrWhiteSpace(LockerPathTextBox.Text);
        }
    }
}

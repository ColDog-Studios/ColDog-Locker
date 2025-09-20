using System.Windows;

namespace ColDogStudios.ColDogLocker.Desktop.Views
{
    public partial class SettingsDialog : Window
    {
        public SettingsDialog()
        {
            InitializeComponent();
            LoadSettings();
        }

        private void LoadSettings()
        {
            // Load current settings from configuration
            // For now, just placeholder values
            EncryptionLevelComboBox.SelectedIndex = 1; // AES-256
            BackupEnabledCheckBox.IsChecked = true;
            AutoLockCheckBox.IsChecked = false;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            // Save settings
            SaveSettings();
            DialogResult = true;
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        private void ApplyButton_Click(object sender, RoutedEventArgs e)
        {
            SaveSettings();
        }

        private void SaveSettings()
        {
            // Save settings to configuration
            // Implementation would go here
            MessageBox.Show("Settings saved successfully!", "Settings", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}

using System.IO;
using System.Windows;
using System.Windows.Controls;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs
{
    public partial class NewLockerDialog : Window
    {
        public string LockerName { get; private set; } = string.Empty;
        public string Location { get; private set; } = string.Empty;
        public string Password { get; private set; } = string.Empty;
        public bool LockImmediately { get; private set; } = true;
        public bool Success { get; private set; }

        private bool _isCustomPath = false;
        private readonly string _defaultBasePath;

        public NewLockerDialog()
        {
            InitializeComponent();
            
            // Get default locker location from settings
            _defaultBasePath = SettingsManager.Settings.DefaultLockerLocation;
            
            // Ensure the default directory exists
            if (!Directory.Exists(_defaultBasePath))
            {
                try
                {
                    Directory.CreateDirectory(_defaultBasePath);
                }
                catch
                {
                    // If we can't create it, fall back to Documents
                    _defaultBasePath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                }
            }
            
            UpdateCreateButtonState();
        }

        private void LockerNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ValidateLockerName();
            
            // Auto-update path if not using a custom path
            if (!_isCustomPath)
            {
                UpdateDefaultPath();
            }
            
            UpdateCreateButtonState();
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            ValidatePassword();
            ValidateConfirmPassword();
            UpdateCreateButtonState();
        }

        private void ConfirmPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            ValidateConfirmPassword();
            UpdateCreateButtonState();
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select folder to lock",
                InitialDirectory = _defaultBasePath
            };

            if (dialog.ShowDialog() == true)
            {
                LocationTextBox.Text = dialog.FolderName;
                Location = dialog.FolderName;
                LocationErrorText.Visibility = Visibility.Collapsed;
                
                // Mark as custom path since user browsed
                _isCustomPath = true;

                // Auto-fill locker name if empty (only when browsing)
                if (string.IsNullOrWhiteSpace(LockerNameTextBox.Text))
                {
                    LockerNameTextBox.Text = Path.GetFileName(dialog.FolderName);
                }

                UpdateCreateButtonState();
            }
        }

        private void CreateButton_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateAll())
            {
                return;
            }

            LockerName = LockerNameTextBox.Text.Trim();
            Location = LocationTextBox.Text.Trim();
            Password = PasswordBox.Password;
            LockImmediately = LockImmediatelyCheckBox.IsChecked ?? true;
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

        private bool ValidateLockerName()
        {
            var name = LockerNameTextBox.Text.Trim();

            if (string.IsNullOrWhiteSpace(name))
            {
                NameErrorText.Text = "Locker name is required";
                NameErrorText.Visibility = Visibility.Visible;
                return false;
            }

            if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                NameErrorText.Text = "Locker name contains invalid characters";
                NameErrorText.Visibility = Visibility.Visible;
                return false;
            }

            NameErrorText.Visibility = Visibility.Collapsed;
            return true;
        }

        private bool ValidatePassword()
        {
            var password = PasswordBox.Password;

            if (password.Length < 8)
            {
                PasswordErrorText.Visibility = Visibility.Visible;
                return false;
            }

            PasswordErrorText.Visibility = Visibility.Collapsed;
            return true;
        }

        private bool ValidateConfirmPassword()
        {
            if (PasswordBox.Password != ConfirmPasswordBox.Password)
            {
                ConfirmPasswordErrorText.Visibility = Visibility.Visible;
                return false;
            }

            ConfirmPasswordErrorText.Visibility = Visibility.Collapsed;
            return true;
        }

        private bool ValidateLocation()
        {
            if (string.IsNullOrWhiteSpace(LocationTextBox.Text))
            {
                LocationErrorText.Text = "Please select a folder";
                LocationErrorText.Visibility = Visibility.Visible;
                return false;
            }

            if (!Directory.Exists(LocationTextBox.Text))
            {
                LocationErrorText.Text = "Selected folder does not exist";
                LocationErrorText.Visibility = Visibility.Visible;
                return false;
            }

            LocationErrorText.Visibility = Visibility.Collapsed;
            return true;
        }

        private bool ValidateAll()
        {
            var isNameValid = ValidateLockerName();
            var isLocationValid = ValidateLocation();
            var isPasswordValid = ValidatePassword();
            var isConfirmPasswordValid = ValidateConfirmPassword();

            return isNameValid && isLocationValid && isPasswordValid && isConfirmPasswordValid;
        }

        private void UpdateCreateButtonState()
        {
            CreateButton.IsEnabled =
                !string.IsNullOrWhiteSpace(LockerNameTextBox.Text) &&
                !string.IsNullOrWhiteSpace(LocationTextBox.Text) &&
                PasswordBox.Password.Length >= 8 &&
                PasswordBox.Password == ConfirmPasswordBox.Password;
        }

        private void UpdateDefaultPath()
        {
            var lockerName = LockerNameTextBox.Text.Trim();
            
            if (!string.IsNullOrWhiteSpace(lockerName))
            {
                // Construct the default path: basePath\LockerName
                var defaultPath = Path.Combine(_defaultBasePath, lockerName);
                LocationTextBox.Text = defaultPath;
                Location = defaultPath;
                LocationErrorText.Visibility = Visibility.Collapsed;
            }
            else
            {
                // Clear the path if locker name is empty
                LocationTextBox.Text = string.Empty;
                Location = string.Empty;
            }
        }
    }
}

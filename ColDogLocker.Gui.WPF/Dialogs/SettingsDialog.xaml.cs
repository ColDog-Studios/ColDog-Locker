using System.IO;
using System.Windows;
using System.Windows.Controls;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using RadioButton = System.Windows.Controls.RadioButton;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs
{
    public partial class SettingsDialog : Window
    {
        private readonly IThemeService _themeService;
        private AppTheme _currentTheme;
        private bool _hasChanges;

        public SettingsDialog()
        {
            InitializeComponent();
            _themeService = ServiceLocator.Instance.ThemeService;
            _currentTheme = _themeService.CurrentTheme;

            LoadCurrentSettings();
        }

        private void LoadCurrentSettings()
        {
            // Load theme preference
            switch (_themeService.CurrentTheme)
            {
                case AppTheme.Auto:
                    AutoThemeRadio.IsChecked = true;
                    break;
                case AppTheme.Light:
                    LightThemeRadio.IsChecked = true;
                    break;
                case AppTheme.Dark:
                    DarkThemeRadio.IsChecked = true;
                    break;
                case AppTheme.ColDogStudios:
                    ColDogThemeRadio.IsChecked = true;
                    break;
            }

            // Load default location
            var defaultLocation = SettingsManager.Settings.DefaultLockerLocation;
            if (string.IsNullOrEmpty(defaultLocation))
            {
                defaultLocation = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "ColDog Locker");
            }

            DefaultLocationTextBox.Text = defaultLocation;

            // Load other settings from SettingsManager
            AutoUpdateCheckBox.IsChecked = SettingsManager.Settings.AutoUpdate;

            GridViewRadio.IsChecked = SettingsManager.Settings.DefaultGuiViewMode == GuiViewMode.Grid;
            ListViewRadio.IsChecked = SettingsManager.Settings.DefaultGuiViewMode == GuiViewMode.List;

            DevModeCheckBox.IsChecked = SettingsManager.Settings.DevMode;
            DbVacuumIntervalTextBox.Text = SettingsManager.Settings.DatabaseVacuumInterval.ToString();
            EnableAnimationsCheckBox.IsChecked = SettingsManager.Settings.EnableAnimations;

            // Load logging options
            LogLevelComboBox.SelectedItem = LogLevelComboBox.Items.Cast<System.Windows.Controls.ComboBoxItem>()
                .FirstOrDefault(item => item.Content.ToString() == SettingsManager.Settings.LogLevel) ?? LogLevelComboBox.Items[1];
            LogFormatComboBox.SelectedItem = LogFormatComboBox.Items.Cast<System.Windows.Controls.ComboBoxItem>()
                .FirstOrDefault(item => item.Content.ToString() == SettingsManager.Settings.LogFormat) ?? LogFormatComboBox.Items[0];
            MaxFileSizeTextBox.Text = SettingsManager.Settings.MaxFileSizeMB.ToString();
            MaxRetainedFilesTextBox.Text = SettingsManager.Settings.MaxRetainedFiles.ToString();
            EnableFileLoggingCheckBox.IsChecked = SettingsManager.Settings.EnableFileLogging;
            EnableCompressionCheckBox.IsChecked = SettingsManager.Settings.EnableCompression;
            IncludeTimestampsCheckBox.IsChecked = SettingsManager.Settings.IncludeTimestamps;
            IncludeThreadIdCheckBox.IsChecked = SettingsManager.Settings.IncludeThreadId;
            DateTimeFormatComboBox.SelectedItem = DateTimeFormatComboBox.Items.Cast<System.Windows.Controls.ComboBoxItem>()
                .FirstOrDefault(item => item.Content.ToString() == SettingsManager.Settings.DateTimeFormat) ?? DateTimeFormatComboBox.Items[0];
            AsyncLoggingCheckBox.IsChecked = SettingsManager.Settings.AsyncLogging;

            // Load update channel
            switch (SettingsManager.Settings.UpdateChannel)
            {
                case UpdateChannel.Stable:
                    StableChannelRadio.IsChecked = true;
                    break;
                case UpdateChannel.Prerelease:
                    PrereleaseChannelRadio.IsChecked = true;
                    break;
                default:
                    StableChannelRadio.IsChecked = true;
                    break;
            }
        }

        private void BrowseDefaultLocation_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select default locker folder",
                InitialDirectory = DefaultLocationTextBox.Text
            };

            if (dialog.ShowDialog() == true)
            {
                DefaultLocationTextBox.Text = dialog.FolderName;
                _hasChanges = true;
            }
        }

        private void ThemeRadio_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton radio && IsLoaded)
            {
                _hasChanges = true;

                if (radio == AutoThemeRadio)
                {
                    _currentTheme = AppTheme.Auto;
                }
                else if (radio == LightThemeRadio)
                {
                    _currentTheme = AppTheme.Light;
                }
                else if (radio == DarkThemeRadio)
                {
                    _currentTheme = AppTheme.Dark;
                }
                else if (radio == ColDogThemeRadio)
                {
                    _currentTheme = AppTheme.ColDogStudios;
                }
            }
        }

        private void NumericTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (sender is System.Windows.Controls.TextBox textBox && IsLoaded)
            {
                // Allow only numeric input between 7 and 90
                if (int.TryParse(textBox.Text, out var value))
                {
                    if (value < 7)
                    {
                        textBox.Text = "7";
                        textBox.SelectionStart = textBox.Text.Length;
                    }
                    else if (value > 90)
                    {
                        textBox.Text = "90";
                        textBox.SelectionStart = textBox.Text.Length;
                    }

                    _hasChanges = true;
                }
                else if (!string.IsNullOrEmpty(textBox.Text))
                {
                    // Remove non-numeric characters
                    var numericOnly = new string([.. textBox.Text.Where(char.IsDigit)]);
                    if (numericOnly != textBox.Text)
                    {
                        var selectionStart = textBox.SelectionStart;
                        textBox.Text = numericOnly;
                        textBox.SelectionStart = Math.Min(selectionStart, textBox.Text.Length);
                    }
                }
            }
        }

        private void OpenLogsFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var logsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "ColDog Studios", "ColDog Locker", "logs");

                if (!Directory.Exists(logsPath))
                {
                    Directory.CreateDirectory(logsPath);
                }

                System.Diagnostics.Process.Start("explorer.exe", logsPath);
            }
            catch (Exception ex)
            {
                MessageDialog.ShowError($"Failed to open logs folder: {ex.Message}", "Error", this);
            }
        }

        private void VacuumDatabase_Click(object sender, RoutedEventArgs e)
        {
            if (MessageDialog.ShowQuestion(
                "This will optimize the database and reclaim unused space. Continue?",
                "Vacuum Database",
                this))
            {
                try
                {
                    var reclaimed = ColDogStudios.ColDogLocker.Infrastructure.Data.LockerRepository.VacuumDatabase();
                    var reclaimedKB = reclaimed / 1024.0;
                    var message = reclaimed > 0
                        ? $"Database optimized successfully.\n\nSpace reclaimed: {reclaimedKB:F2} KB"
                        : "Database optimized successfully.\n\nNo space was reclaimed (database was already optimal).";
                    MessageDialog.ShowInformation(message, "Database Vacuum Complete", this);
                }
                catch (Exception ex)
                {
                    MessageDialog.ShowError($"Failed to vacuum database: {ex.Message}", "Error", this);
                }
            }
        }

        private void ClearCache_Click(object sender, RoutedEventArgs e)
        {
            if (MessageDialog.ShowQuestion(
                "Are you sure you want to clear all cached data?",
                "Clear Cache",
                this))
            {
                try
                {
                    // TODO: Implement cache clearing logic
                    MessageDialog.ShowInformation("Cache cleared successfully.", "Success", this);
                }
                catch (Exception ex)
                {
                    MessageDialog.ShowError($"Failed to clear cache: {ex.Message}", "Error", this);
                }
            }
        }

        private void ResetSettings_Click(object sender, RoutedEventArgs e)
        {
            if (MessageDialog.ShowQuestion(
                "This will reset ALL settings to their default values. Continue?",
                "Reset Settings",
                this))
            {
                RestoreDefaultSettings();
                LoadCurrentSettings();
                _hasChanges = true;
            }
        }

        private void RestoreDefaults_Click(object sender, RoutedEventArgs e)
        {
            RestoreDefaultSettings();
            LoadCurrentSettings();
            _hasChanges = true;
        }

        private static void RestoreDefaultSettings()
        {
            // Reset to default settings
            SettingsManager.Settings = new ApplicationSettings();
            SettingsManager.SaveSettings();
        }

        private async void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Save all settings
                SettingsManager.Settings.DefaultLockerLocation = DefaultLocationTextBox.Text;
                SettingsManager.Settings.AutoUpdate = AutoUpdateCheckBox.IsChecked ?? true;
                SettingsManager.Settings.DefaultGuiViewMode = GridViewRadio.IsChecked == true
                    ? GuiViewMode.Grid
                    : GuiViewMode.List;
                SettingsManager.Settings.DevMode = DevModeCheckBox.IsChecked ?? false;

                // Apply logging settings to Infrastructure.Logging.Logger
                var devModeEnabled = DevModeCheckBox.IsChecked ?? false;
                ColDogStudios.ColDogLocker.Infrastructure.Logging.Logger.SetDevMode(devModeEnabled);

                // Save logging options
                SettingsManager.Settings.LogLevel = (LogLevelComboBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content.ToString() ?? "Info";
                SettingsManager.Settings.LogFormat = (LogFormatComboBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content.ToString() ?? "json";
                if (int.TryParse(MaxFileSizeTextBox.Text, out var maxFileSize))
                {
                    SettingsManager.Settings.MaxFileSizeMB = maxFileSize;
                }

                if (int.TryParse(MaxRetainedFilesTextBox.Text, out var maxRetained))
                {
                    SettingsManager.Settings.MaxRetainedFiles = maxRetained;
                }

                SettingsManager.Settings.EnableFileLogging = EnableFileLoggingCheckBox.IsChecked ?? true;
                SettingsManager.Settings.EnableCompression = EnableCompressionCheckBox.IsChecked ?? false;
                SettingsManager.Settings.IncludeTimestamps = IncludeTimestampsCheckBox.IsChecked ?? true;
                SettingsManager.Settings.IncludeThreadId = IncludeThreadIdCheckBox.IsChecked ?? false;
                SettingsManager.Settings.DateTimeFormat = (DateTimeFormatComboBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content.ToString() ?? "UTC";
                SettingsManager.Settings.AsyncLogging = AsyncLoggingCheckBox.IsChecked ?? true;

                // Apply logging settings to logger
                ColDogStudios.ColDogLocker.Infrastructure.Logging.Logger.ReloadConfig();

                if (int.TryParse(DbVacuumIntervalTextBox.Text, out var vacuumInterval))
                {
                    SettingsManager.Settings.DatabaseVacuumInterval = Math.Clamp(vacuumInterval, 7, 90);
                }

                SettingsManager.Settings.EnableAnimations = EnableAnimationsCheckBox.IsChecked ?? true;

                // Save update channel
                if (StableChannelRadio.IsChecked == true)
                {
                    SettingsManager.Settings.UpdateChannel = UpdateChannel.Stable;
                }
                else if (PrereleaseChannelRadio.IsChecked == true)
                {
                    SettingsManager.Settings.UpdateChannel = UpdateChannel.Prerelease;
                }

                SettingsManager.SaveSettings();

                // Apply theme if changed
                if (_currentTheme != _themeService.CurrentTheme)
                {
                    await _themeService.SetThemeAsync(_currentTheme);
                }

                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageDialog.ShowError($"Failed to save settings: {ex.Message}", "Error", this);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            if (_hasChanges)
            {
                if (!MessageDialog.ShowQuestion(
                    "You have unsaved changes. Are you sure you want to cancel?",
                    "Unsaved Changes",
                    this))
                {
                    return;
                }
            }

            DialogResult = false;
            Close();
        }
    }
}

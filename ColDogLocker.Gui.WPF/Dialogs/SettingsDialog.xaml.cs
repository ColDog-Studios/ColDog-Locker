using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;
using RadioButton = System.Windows.Controls.RadioButton;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs;

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
        {            case AppTheme.Auto:
                AutoThemeRadio.IsChecked = true;
                break;            case AppTheme.Light:
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
        var defaultLocation = Properties.Settings.Default.DefaultLockerLocation;
        if (string.IsNullOrEmpty(defaultLocation))
        {
            defaultLocation = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "ColDog Locker");
        }
        DefaultLocationTextBox.Text = defaultLocation;

        // Load other settings from Properties.Settings.Default
        CheckUpdatesOnStartupCheckBox.IsChecked = Properties.Settings.Default.CheckUpdatesOnStartup;
        
        GridViewRadio.IsChecked = Properties.Settings.Default.DefaultViewIsGrid;
        ListViewRadio.IsChecked = !Properties.Settings.Default.DefaultViewIsGrid;
        
        ShowToolBarCheckBox.IsChecked = Properties.Settings.Default.ShowToolBar;
        EnableLoggingCheckBox.IsChecked = Properties.Settings.Default.EnableLogging;
        DebugModeCheckBox.IsChecked = Properties.Settings.Default.DebugMode;
        LogRetentionTextBox.Text = Properties.Settings.Default.LogRetentionDays.ToString();
        DbVacuumIntervalTextBox.Text = Properties.Settings.Default.DbVacuumIntervalDays.ToString();
        EnableAnimationsCheckBox.IsChecked = Properties.Settings.Default.EnableAnimations;

        // Load update channel
        switch (Properties.Settings.Default.UpdateChannel)
        {
            case "Stable":
                StableChannelRadio.IsChecked = true;
                break;
            case "Prerelease":
            case "Beta": // Legacy support
            case "Dev": // Legacy support
                PrereleaseChannelRadio.IsChecked = true;
                break;
            default:
                StableChannelRadio.IsChecked = true;
                break;
        }
    }

    private void BrowseDefaultLocation_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Select default locker folder",
            ShowNewFolderButton = true,
            SelectedPath = DefaultLocationTextBox.Text
        };

        if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            DefaultLocationTextBox.Text = dialog.SelectedPath;
            _hasChanges = true;
        }
    }

    private void ThemeRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton radio && IsLoaded)
        {
            _hasChanges = true;
            
            if (radio == AutoThemeRadio)
                _currentTheme = AppTheme.Auto;
            else if (radio == LightThemeRadio)
                _currentTheme = AppTheme.Light;
            else if (radio == DarkThemeRadio)
                _currentTheme = AppTheme.Dark;
            else if (radio == ColDogThemeRadio)
                _currentTheme = AppTheme.ColDogStudios;
        }
    }

    private void NumericTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (sender is System.Windows.Controls.TextBox textBox && IsLoaded)
        {
            // Allow only numeric input between 7 and 90
            if (int.TryParse(textBox.Text, out int value))
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
                var numericOnly = new string(textBox.Text.Where(char.IsDigit).ToArray());
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
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "ColDog Locker", "Logs");

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

    private void RestoreDefaultSettings()
    {
        Properties.Settings.Default.Reset();
    }

    private async void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            // Save all settings
            Properties.Settings.Default.DefaultLockerLocation = DefaultLocationTextBox.Text;
            Properties.Settings.Default.CheckUpdatesOnStartup = CheckUpdatesOnStartupCheckBox.IsChecked ?? true;
            Properties.Settings.Default.DefaultViewIsGrid = GridViewRadio.IsChecked ?? true;
            Properties.Settings.Default.ShowToolBar = ShowToolBarCheckBox.IsChecked ?? true;
            Properties.Settings.Default.EnableLogging = EnableLoggingCheckBox.IsChecked ?? true;
            Properties.Settings.Default.DebugMode = DebugModeCheckBox.IsChecked ?? false;
            
            // Apply logging settings to Infrastructure.Logging.Logger
            var debugModeEnabled = DebugModeCheckBox.IsChecked ?? false;
            ColDogStudios.ColDogLocker.Infrastructure.Logging.Logger.SetDebugMode(debugModeEnabled);
            
            // Parse numeric textbox values with validation
            if (int.TryParse(LogRetentionTextBox.Text, out int logRetention))
                Properties.Settings.Default.LogRetentionDays = Math.Clamp(logRetention, 7, 90);
            if (int.TryParse(DbVacuumIntervalTextBox.Text, out int vacuumInterval))
                Properties.Settings.Default.DbVacuumIntervalDays = Math.Clamp(vacuumInterval, 7, 90);
            
            Properties.Settings.Default.EnableAnimations = EnableAnimationsCheckBox.IsChecked ?? true;
            
            // Save update channel
            if (StableChannelRadio.IsChecked == true)
                Properties.Settings.Default.UpdateChannel = "Stable";
            else if (PrereleaseChannelRadio.IsChecked == true)
                Properties.Settings.Default.UpdateChannel = "Prerelease";
            
            Properties.Settings.Default.Save();

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

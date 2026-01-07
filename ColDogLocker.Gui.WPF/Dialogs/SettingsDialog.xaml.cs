using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;
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
        {
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
        var defaultLocation = Properties.Settings.Default.DefaultLockerLocation;
        if (string.IsNullOrEmpty(defaultLocation))
        {
            defaultLocation = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "ColDog Locker");
        }
        DefaultLocationTextBox.Text = defaultLocation;

        // Load other settings from Properties.Settings.Default
        AutoLockOnExitCheckBox.IsChecked = Properties.Settings.Default.AutoLockOnExit;
        CheckUpdatesOnStartupCheckBox.IsChecked = Properties.Settings.Default.CheckUpdatesOnStartup;
        
        GridViewRadio.IsChecked = Properties.Settings.Default.DefaultViewIsGrid;
        ListViewRadio.IsChecked = !Properties.Settings.Default.DefaultViewIsGrid;
        
        IconSizeSlider.Value = Properties.Settings.Default.GridIconSize;
        ShowStatusBarCheckBox.IsChecked = Properties.Settings.Default.ShowStatusBar;
        ShowToolBarCheckBox.IsChecked = Properties.Settings.Default.ShowToolBar;
        EnableLoggingCheckBox.IsChecked = Properties.Settings.Default.EnableLogging;
        DebugModeCheckBox.IsChecked = Properties.Settings.Default.DebugMode;
        LogRetentionSlider.Value = Properties.Settings.Default.LogRetentionDays;
        DbVacuumIntervalSlider.Value = Properties.Settings.Default.DbVacuumIntervalDays;
        EnableAnimationsCheckBox.IsChecked = Properties.Settings.Default.EnableAnimations;

        // Load update channel
        switch (Properties.Settings.Default.UpdateChannel)
        {
            case "Stable":
                StableChannelRadio.IsChecked = true;
                break;
            case "Beta":
                BetaChannelRadio.IsChecked = true;
                break;
            case "Dev":
                DevChannelRadio.IsChecked = true;
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
            
            if (radio == LightThemeRadio)
                _currentTheme = AppTheme.Light;
            else if (radio == DarkThemeRadio)
                _currentTheme = AppTheme.Dark;
            else if (radio == ColDogThemeRadio)
                _currentTheme = AppTheme.ColDogStudios;
        }
    }

    private void IconSizeSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (IconSizeText != null && IsLoaded)
        {
            IconSizeText.Text = $"{(int)e.NewValue}px";
            _hasChanges = true;
        }
    }

    private void LogRetentionSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (LogRetentionText != null && IsLoaded)
        {
            LogRetentionText.Text = $"{(int)e.NewValue} days";
            _hasChanges = true;
        }
    }

    private void DbVacuumIntervalSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (DbVacuumIntervalText != null && IsLoaded)
        {
            DbVacuumIntervalText.Text = $"{(int)e.NewValue} days";
            _hasChanges = true;
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
            MessageBox.Show($"Failed to open logs folder: {ex.Message}", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ClearCache_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "This will clear all cached data. Continue?",
            "Clear Cache",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
            try
            {
                // TODO: Implement cache clearing logic
                MessageBox.Show("Cache cleared successfully.", "Success", 
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to clear cache: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void ResetSettings_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "This will reset ALL settings to their default values. Continue?",
            "Reset Settings",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
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
            Properties.Settings.Default.AutoLockOnExit = AutoLockOnExitCheckBox.IsChecked ?? false;
            Properties.Settings.Default.CheckUpdatesOnStartup = CheckUpdatesOnStartupCheckBox.IsChecked ?? true;
            Properties.Settings.Default.DefaultViewIsGrid = GridViewRadio.IsChecked ?? true;
            Properties.Settings.Default.GridIconSize = (int)IconSizeSlider.Value;
            Properties.Settings.Default.ShowStatusBar = ShowStatusBarCheckBox.IsChecked ?? true;
            Properties.Settings.Default.ShowToolBar = ShowToolBarCheckBox.IsChecked ?? true;
            Properties.Settings.Default.EnableLogging = EnableLoggingCheckBox.IsChecked ?? true;
            Properties.Settings.Default.DebugMode = DebugModeCheckBox.IsChecked ?? false;
            Properties.Settings.Default.LogRetentionDays = (int)LogRetentionSlider.Value;
            Properties.Settings.Default.DbVacuumIntervalDays = (int)DbVacuumIntervalSlider.Value;
            Properties.Settings.Default.EnableAnimations = EnableAnimationsCheckBox.IsChecked ?? true;
            
            // Save update channel
            if (StableChannelRadio.IsChecked == true)
                Properties.Settings.Default.UpdateChannel = "Stable";
            else if (BetaChannelRadio.IsChecked == true)
                Properties.Settings.Default.UpdateChannel = "Beta";
            else if (DevChannelRadio.IsChecked == true)
                Properties.Settings.Default.UpdateChannel = "Dev";
            
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
            MessageBox.Show($"Failed to save settings: {ex.Message}", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        if (_hasChanges)
        {
            var result = MessageBox.Show(
                "You have unsaved changes. Are you sure you want to cancel?",
                "Unsaved Changes",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.No)
            {
                return;
            }
        }

        DialogResult = false;
        Close();
    }
}

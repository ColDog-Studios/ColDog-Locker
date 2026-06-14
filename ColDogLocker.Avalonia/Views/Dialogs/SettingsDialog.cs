/*
**  Copyright (C) 2026 ColDog Studios
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  long with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class SettingsDialog : Window
    {
        private static readonly string[] ThemeChoices = ["Auto", "Light", "Dark", "ColDog Studios"];
        private static readonly string[] LogLevelChoices = ["Debug", "Info", "Warning", "Error", "Fatal"];
        private static readonly string[] LogFormatChoices = ["json", "text"];

        private IAppThemeService? _themeService;
        private IPlatformService? _platformService;
        private UpdateWorkflow? _updateWorkflow;
        private AvaloniaUpdateDialogHost? _updateDialogHost;

        private bool _hasChanges;
        private bool _isLoading;

        public SettingsDialog()
        {
            InitializeComponent();

            ConfigureControls();
            LoadCurrentSettings(markClean: true);
        }

        public SettingsDialog(
            IAppThemeService themeService,
            IPlatformService platformService,
            UpdateWorkflow updateWorkflow,
            AvaloniaUpdateDialogHost updateDialogHost)
            : this()
        {
            _themeService = themeService;
            _platformService = platformService;
            _updateWorkflow = updateWorkflow;
            _updateDialogHost = updateDialogHost;
        }

        private void ConfigureControls()
        {
            ThemeBox.ItemsSource = ThemeChoices;
            LogLevelBox.ItemsSource = LogLevelChoices;
            LogFormatBox.ItemsSource = LogFormatChoices;
            LogLevelBox.SelectionChanged += (_, _) => UpdateLogLevelDescription();
            ThemeBox.SelectionChanged += (_, _) => ApplyThemeImmediately();

            BrowseDefaultLocationButton.Click += BrowseDefaultLocation_Click;
            OpenDefaultLocationButton.Click += OpenDefaultLocation_Click;
            ResetDefaultLocationButton.Click += ResetDefaultLocation_Click;
            CheckForUpdatesButton.Click += CheckForUpdates_Click;
            OpenLogsFolderButton.Click += OpenLogsFolder_Click;
            VacuumDatabaseButton.Click += VacuumDatabase_Click;
            OpenSettingsFolderButton.Click += OpenSettingsFolder_Click;
            ResetSettingsButton.Click += ResetSettings_Click;
            SaveButton.Click += SaveButton_Click;
            CancelButton.Click += CancelButton_Click;

            TrackChanges(DefaultLocationTextBox);
            TrackInstantViewChange(GridViewRadio);
            TrackInstantViewChange(ListViewRadio);
            TrackChanges(AutoUpdateCheckBox);
            TrackChanges(StableChannelRadio);
            TrackChanges(UnstableChannelRadio);
            TrackChanges(DevModeCheckBox);
            TrackChanges(EnableFileLoggingCheckBox);
            TrackChanges(LogLevelBox);
            TrackChanges(LogFormatBox);
            TrackChanges(MaxFileSizeTextBox);
            TrackChanges(DbVacuumIntervalTextBox);
        }

        private void LoadCurrentSettings(bool markClean)
        {
            var settings = SettingsManager.Settings;

            _isLoading = true;
            try
            {
                DefaultLocationTextBox.Text = string.IsNullOrWhiteSpace(settings.DefaultLockerLocation)
                    ? AppPaths.CdlDir
                    : settings.DefaultLockerLocation;

                ThemeBox.SelectedItem = settings.AppTheme == "CDS" ? "ColDog Studios" : settings.AppTheme;
                GridViewRadio.IsChecked = settings.DefaultGuiViewMode == GuiViewMode.Grid;
                ListViewRadio.IsChecked = settings.DefaultGuiViewMode == GuiViewMode.List;
                AutoUpdateCheckBox.IsChecked = settings.AutoUpdate;
                StableChannelRadio.IsChecked = settings.UpdateChannel == UpdateChannel.Stable;
                UnstableChannelRadio.IsChecked = settings.UpdateChannel == UpdateChannel.Unstable;
                DevModeCheckBox.IsChecked = settings.DevMode;
                EnableFileLoggingCheckBox.IsChecked = settings.EnableFileLogging;
                LogLevelBox.SelectedItem = ChoiceOrDefault(LogLevelChoices, settings.LogLevel, "Info");
                LogFormatBox.SelectedItem = ChoiceOrDefault(LogFormatChoices, settings.LogFormat, "json");
                MaxFileSizeTextBox.Text = settings.MaxFileSizeMb.ToString();
                DbVacuumIntervalTextBox.Text = settings.DatabaseVacuumInterval.ToString();
                UpdateLogLevelDescription();
            }
            finally
            {
                _isLoading = false;
            }

            if (markClean)
            {
                _hasChanges = false;
            }

            UpdateSaveButtonState();
        }

        private async void BrowseDefaultLocation_Click(object? sender, RoutedEventArgs e)
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Select default locker folder",
                AllowMultiple = false
            });

            var folder = folders.FirstOrDefault();
            if (folder == null)
            {
                return;
            }

            DefaultLocationTextBox.Text = folder.TryGetLocalPath() ?? folder.Path.LocalPath;
            MarkChanged();
        }

        private async void OpenDefaultLocation_Click(object? sender, RoutedEventArgs e)
        {
            var path = string.IsNullOrWhiteSpace(DefaultLocationTextBox.Text)
                ? AppPaths.CdlDir
                : DefaultLocationTextBox.Text;

            await OpenFolderAsync(path, "Failed to open default locker folder");
        }

        private void ResetDefaultLocation_Click(object? sender, RoutedEventArgs e)
        {
            DefaultLocationTextBox.Text = AppPaths.CdlDir;
            MarkChanged();
        }

        private async void CheckForUpdates_Click(object? sender, RoutedEventArgs e)
        {
            if (_updateWorkflow == null || _updateDialogHost == null)
            {
                return;
            }

            var originalChannel = SettingsManager.Settings.UpdateChannel;
            SettingsManager.Settings.UpdateChannel = UnstableChannelRadio.IsChecked == true
                ? UpdateChannel.Unstable
                : UpdateChannel.Stable;

            using var ownerScope = _updateDialogHost.UseOwner(this);
            try
            {
                await _updateWorkflow.RunAsync();
            }
            finally
            {
                SettingsManager.Settings.UpdateChannel = originalChannel;
            }
        }

        private async void OpenLogsFolder_Click(object? sender, RoutedEventArgs e)
        {
            var logsPath = Path.GetDirectoryName(Logger.GetCurrentLogFilePath())
                ?? Path.Combine(AppPaths.LocalConfig, "logs");
            await OpenFolderAsync(logsPath, "Failed to open logs folder");
        }

        private async void VacuumDatabase_Click(object? sender, RoutedEventArgs e)
        {
            var confirmed = await new MessageDialog(
                    "Vacuum Database",
                    "This will optimize the database and reclaim unused space. Continue?",
                    MessageDialogKind.Confirmation)
                .ShowDialog<bool>(this);

            if (!confirmed)
            {
                return;
            }

            try
            {
                var reclaimed = LockerRepository.VacuumDatabase();
                var reclaimedKb = reclaimed / 1024.0;
                var message = reclaimed > 0
                    ? $"Database optimized successfully.\n\nSpace reclaimed: {reclaimedKb:F2} KB"
                    : "Database optimized successfully.\n\nNo space was reclaimed; the database was already optimal.";

                await new MessageDialog("Database Vacuum Complete", message, MessageDialogKind.Information)
                    .ShowDialog<object?>(this);
            }
            catch (Exception ex)
            {
                await new MessageDialog("Error", $"Failed to vacuum database: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
        }

        private async void OpenSettingsFolder_Click(object? sender, RoutedEventArgs e)
        {
            await OpenFolderAsync(AppPaths.LocalConfig, "Failed to open settings folder");
        }

        private async void ResetSettings_Click(object? sender, RoutedEventArgs e)
        {
            var confirmed = await new MessageDialog(
                    "Reset Settings",
                    "This will reset all settings to their default values. Continue?",
                    MessageDialogKind.Confirmation)
                .ShowDialog<bool>(this);

            if (!confirmed)
            {
                return;
            }

            RestoreDefaultSettings();
            LoadCurrentSettings(markClean: true);
            _themeService?.SetTheme(SettingsManager.Settings.AppTheme);
        }

        private async void SaveButton_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                SaveSettingsFromControls();
                SettingsManager.SaveSettings();
                Logger.SetDevMode(SettingsManager.Settings.DevMode);
                Logger.ReloadConfig();
                _hasChanges = false;
                UpdateSaveButtonState();
                Close(SettingsManager.Settings.AppTheme);
            }
            catch (Exception ex)
            {
                await new MessageDialog("Error", $"Failed to save settings: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
        }

        private async void CancelButton_Click(object? sender, RoutedEventArgs e)
        {
            if (_hasChanges)
            {
                var confirmed = await new MessageDialog(
                        "Unsaved Changes",
                        "You have unsaved changes. Are you sure you want to cancel?",
                        MessageDialogKind.Confirmation)
                    .ShowDialog<bool>(this);

                if (!confirmed)
                {
                    return;
                }
            }

            Close(null);
        }

        private void SaveSettingsFromControls()
        {
            var settings = SettingsManager.Settings;
            settings.DefaultLockerLocation = string.IsNullOrWhiteSpace(DefaultLocationTextBox.Text)
                ? AppPaths.CdlDir
                : DefaultLocationTextBox.Text;
            settings.AppTheme = ThemeToSettingsValue(ThemeBox.SelectedItem?.ToString() ?? _themeService?.CurrentTheme ?? "Auto");
            settings.DefaultGuiViewMode = ListViewRadio.IsChecked == true ? GuiViewMode.List : GuiViewMode.Grid;
            settings.AutoUpdate = AutoUpdateCheckBox.IsChecked == true;
            settings.UpdateChannel = UnstableChannelRadio.IsChecked == true ? UpdateChannel.Unstable : UpdateChannel.Stable;
            settings.DevMode = DevModeCheckBox.IsChecked == true;
            settings.EnableFileLogging = EnableFileLoggingCheckBox.IsChecked == true;
            settings.LogLevel = LogLevelBox.SelectedItem?.ToString() ?? "Info";
            settings.LogFormat = LogFormatBox.SelectedItem?.ToString() ?? "json";
            settings.MaxFileSizeMb = ReadInt(MaxFileSizeTextBox, defaultValue: 10, min: 1, max: 1024);
            settings.DatabaseVacuumInterval = ReadInt(DbVacuumIntervalTextBox, defaultValue: 30, min: 7, max: 90);
        }

        private static void RestoreDefaultSettings()
        {
            SettingsManager.Settings = new ApplicationSettings();
            SettingsManager.SaveSettings();
            Logger.ReloadConfig();
        }

        private async Task OpenFolderAsync(string path, string failureMessage)
        {
            if (_platformService == null)
            {
                return;
            }

            try
            {
                Directory.CreateDirectory(path);
                await _platformService.OpenFolderAsync(path);
            }
            catch (Exception ex)
            {
                await new MessageDialog("Error", $"{failureMessage}: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
        }

        private void MarkChanged()
        {
            if (_isLoading)
            {
                return;
            }

            _hasChanges = true;
            UpdateSaveButtonState();
        }

        private void ApplyThemeImmediately()
        {
            if (_isLoading || _themeService == null)
            {
                return;
            }

            _themeService.SetTheme(ThemeToSettingsValue(ThemeBox.SelectedItem?.ToString() ?? "Auto"));
        }

        private void ApplyDefaultViewImmediately()
        {
            if (_isLoading)
            {
                return;
            }

            SettingsManager.Settings.DefaultGuiViewMode = ListViewRadio.IsChecked == true ? GuiViewMode.List : GuiViewMode.Grid;
            SettingsManager.SaveSettings();
        }

        private void UpdateSaveButtonState()
        {
            SaveButton.IsEnabled = _hasChanges;
        }

        private static int ReadInt(TextBox textBox, int defaultValue, int min, int max)
        {
            if (!int.TryParse(textBox.Text, out var value))
            {
                value = defaultValue;
            }

            value = Math.Clamp(value, min, max);
            textBox.Text = value.ToString();
            return value;
        }

        private static string ThemeToSettingsValue(string value)
        {
            return value == "ColDog Studios" ? "CDS" : value;
        }

        private static string ChoiceOrDefault(IEnumerable<string> choices, string value, string fallback)
        {
            return choices.FirstOrDefault(choice => string.Equals(choice, value, StringComparison.OrdinalIgnoreCase)) ?? fallback;
        }

        private void UpdateLogLevelDescription()
        {
            LogLevelDescriptionText.Text = LogLevelBox.SelectedItem?.ToString() switch
            {
                "Debug" => "Includes verbose diagnostic details for troubleshooting prerelease builds.",
                "Info" => "Includes normal application activity, warnings, errors, and fatal failures.",
                "Warning" => "Includes unexpected but recoverable problems, errors, and fatal failures.",
                "Error" => "Includes failed operations and fatal failures only.",
                "Fatal" => "Includes only critical failures that stop or seriously break the app.",
                _ => string.Empty
            };
        }

        private void TrackChanges(TextBox textBox)
        {
            textBox.TextChanged += (_, _) => MarkChanged();
        }

        private void TrackChanges(ComboBox comboBox)
        {
            comboBox.SelectionChanged += (_, _) => MarkChanged();
        }

        private void TrackChanges(ToggleButton toggleButton)
        {
            toggleButton.PropertyChanged += (_, e) =>
            {
                if (e.Property == ToggleButton.IsCheckedProperty)
                {
                    MarkChanged();
                }
            };
        }

        private void TrackInstantViewChange(ToggleButton toggleButton)
        {
            toggleButton.PropertyChanged += (_, e) =>
            {
                if (e.Property == ToggleButton.IsCheckedProperty && toggleButton.IsChecked == true)
                {
                    ApplyDefaultViewImmediately();
                }
            };
        }

    }
}

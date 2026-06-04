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

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class SettingsDialog : Window
    {
        private static readonly string[] ThemeChoices = ["Auto", "Light", "Dark", "ColDog Studios"];
        private static readonly string[] LogLevelChoices = ["Debug", "Info", "Warning", "Error", "Fatal"];
        private static readonly string[] LogFormatChoices = ["json", "text"];
        private static readonly string[] DateTimeFormatChoices = ["UTC", "Local"];

        private IAppThemeService? _themeService;
        private IPlatformService? _platformService;

        private bool _hasChanges;

        public SettingsDialog()
        {
            InitializeComponent();

            ConfigureControls();
            LoadCurrentSettings(markClean: true);
        }

        public SettingsDialog(IAppThemeService themeService, IPlatformService platformService)
            : this()
        {
            _themeService = themeService;
            _platformService = platformService;
        }

        private void ConfigureControls()
        {
            ThemeBox.ItemsSource = ThemeChoices;
            LogLevelBox.ItemsSource = LogLevelChoices;
            LogFormatBox.ItemsSource = LogFormatChoices;
            DateTimeFormatBox.ItemsSource = DateTimeFormatChoices;

            BrowseDefaultLocationButton.Click += BrowseDefaultLocation_Click;
            OpenLogsFolderButton.Click += OpenLogsFolder_Click;
            VacuumDatabaseButton.Click += VacuumDatabase_Click;
            ClearCacheButton.Click += ClearCache_Click;
            ResetSettingsButton.Click += ResetSettings_Click;
            RestoreDefaultsButton.Click += RestoreDefaults_Click;
            SaveButton.Click += SaveButton_Click;
            CancelButton.Click += CancelButton_Click;

            TrackChanges(DefaultLocationTextBox);
            TrackChanges(ThemeBox);
            TrackChanges(GridViewRadio);
            TrackChanges(ListViewRadio);
            TrackChanges(AutoUpdateCheckBox);
            TrackChanges(StableChannelRadio);
            TrackChanges(UnstableChannelRadio);
            TrackChanges(DevModeCheckBox);
            TrackChanges(EnableFileLoggingCheckBox);
            TrackChanges(LogLevelBox);
            TrackChanges(LogFormatBox);
            TrackChanges(MaxFileSizeTextBox);
            TrackChanges(MaxRetainedFilesTextBox);
            TrackChanges(EnableCompressionCheckBox);
            TrackChanges(IncludeTimestampsCheckBox);
            TrackChanges(IncludeThreadIdCheckBox);
            TrackChanges(DateTimeFormatBox);
            TrackChanges(AsyncLoggingCheckBox);
            TrackChanges(DbVacuumIntervalTextBox);
            TrackChanges(EnableAnimationsCheckBox);
        }

        private void LoadCurrentSettings(bool markClean)
        {
            var settings = SettingsManager.Settings;

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
            MaxRetainedFilesTextBox.Text = settings.MaxRetainedFiles.ToString();
            EnableCompressionCheckBox.IsChecked = settings.EnableCompression;
            IncludeTimestampsCheckBox.IsChecked = settings.IncludeTimestamps;
            IncludeThreadIdCheckBox.IsChecked = settings.IncludeThreadId;
            DateTimeFormatBox.SelectedItem = ChoiceOrDefault(DateTimeFormatChoices, settings.DateTimeFormat, "UTC");
            AsyncLoggingCheckBox.IsChecked = settings.AsyncLogging;
            DbVacuumIntervalTextBox.Text = settings.DatabaseVacuumInterval.ToString();
            EnableAnimationsCheckBox.IsChecked = settings.EnableAnimations;

            if (markClean)
            {
                _hasChanges = false;
            }
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

        private async void OpenLogsFolder_Click(object? sender, RoutedEventArgs e)
        {
            if (_platformService == null)
            {
                return;
            }

            try
            {
                var logsPath = Path.GetDirectoryName(Logger.GetCurrentLogFilePath())
                    ?? Path.Combine(AppPaths.LocalConfig, "logs");
                Directory.CreateDirectory(logsPath);
                await _platformService.OpenFolderAsync(logsPath);
            }
            catch (Exception ex)
            {
                await new MessageDialog("Error", $"Failed to open logs folder: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
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

        private async void ClearCache_Click(object? sender, RoutedEventArgs e)
        {
            await new MessageDialog(
                    "Clear Cache",
                    "There is no application cache to clear yet.",
                    MessageDialogKind.Information)
                .ShowDialog<object?>(this);
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
            LoadCurrentSettings(markClean: false);
            MarkChanged();
        }

        private void RestoreDefaults_Click(object? sender, RoutedEventArgs e)
        {
            RestoreDefaultSettings();
            LoadCurrentSettings(markClean: false);
            MarkChanged();
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
            settings.MaxRetainedFiles = ReadInt(MaxRetainedFilesTextBox, defaultValue: 9, min: 1, max: 1000);
            settings.EnableCompression = EnableCompressionCheckBox.IsChecked == true;
            settings.IncludeTimestamps = IncludeTimestampsCheckBox.IsChecked == true;
            settings.IncludeThreadId = IncludeThreadIdCheckBox.IsChecked == true;
            settings.DateTimeFormat = DateTimeFormatBox.SelectedItem?.ToString() ?? "UTC";
            settings.AsyncLogging = AsyncLoggingCheckBox.IsChecked == true;
            settings.DatabaseVacuumInterval = ReadInt(DbVacuumIntervalTextBox, defaultValue: 30, min: 7, max: 90);
            settings.EnableAnimations = EnableAnimationsCheckBox.IsChecked == true;
        }

        private static void RestoreDefaultSettings()
        {
            SettingsManager.Settings = new ApplicationSettings();
            SettingsManager.SaveSettings();
            Logger.ReloadConfig();
        }

        private void MarkChanged()
        {
            _hasChanges = true;
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
    }
}

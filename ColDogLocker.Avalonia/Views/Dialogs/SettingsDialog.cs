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

using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class SettingsDialog : Window
    {
        private static readonly string[] ThemeChoices = ["Auto", "Light", "Dark", "ColDog Studios"];
        private static readonly string[] LogLevelChoices = ["Debug", "Info", "Warning", "Error", "Fatal"];
        private static readonly string[] LogFormatChoices = ["json", "text"];
        private static readonly string[] DateTimeFormatChoices = ["UTC", "Local"];

        private readonly IAppThemeService _themeService;
        private readonly IPlatformService _platformService;

        private bool _hasChanges;

        private readonly TextBox _defaultLocationTextBox;
        private readonly ComboBox _themeBox;
        private readonly RadioButton _gridViewRadio;
        private readonly RadioButton _listViewRadio;
        private readonly CheckBox _autoUpdateCheckBox;
        private readonly RadioButton _stableChannelRadio;
        private readonly RadioButton _unstableChannelRadio;
        private readonly CheckBox _devModeCheckBox;
        private readonly CheckBox _enableFileLoggingCheckBox;
        private readonly ComboBox _logLevelBox;
        private readonly ComboBox _logFormatBox;
        private readonly TextBox _maxFileSizeTextBox;
        private readonly TextBox _maxRetainedFilesTextBox;
        private readonly CheckBox _enableCompressionCheckBox;
        private readonly CheckBox _includeTimestampsCheckBox;
        private readonly CheckBox _includeThreadIdCheckBox;
        private readonly ComboBox _dateTimeFormatBox;
        private readonly CheckBox _asyncLoggingCheckBox;
        private readonly TextBox _dbVacuumIntervalTextBox;
        private readonly CheckBox _enableAnimationsCheckBox;

        public SettingsDialog(IAppThemeService themeService, IPlatformService platformService)
        {
            _themeService = themeService;
            _platformService = platformService;

            Title = "Settings";
            Width = 680;
            Height = 620;
            MinWidth = 620;
            MinHeight = 520;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            _defaultLocationTextBox = TextBox(readOnly: true);
            _themeBox = ComboBox(ThemeChoices);
            _gridViewRadio = Radio("Grid View (Tiles)", "DefaultView");
            _listViewRadio = Radio("List View (Details)", "DefaultView");
            _autoUpdateCheckBox = CheckBox("Enable Auto Update");
            _stableChannelRadio = Radio("Stable (Recommended)", "UpdateChannel");
            _unstableChannelRadio = Radio("Unstable", "UpdateChannel");
            _devModeCheckBox = CheckBox("Enable dev mode");
            _enableFileLoggingCheckBox = CheckBox("Enable file logging");
            _logLevelBox = ComboBox(LogLevelChoices);
            _logFormatBox = ComboBox(LogFormatChoices);
            _maxFileSizeTextBox = TextBox();
            _maxRetainedFilesTextBox = TextBox();
            _enableCompressionCheckBox = CheckBox("Compress rotated log files (.gz)");
            _includeTimestampsCheckBox = CheckBox("Include timestamps in log entries");
            _includeThreadIdCheckBox = CheckBox("Include thread ID in log entries");
            _dateTimeFormatBox = ComboBox(DateTimeFormatChoices);
            _asyncLoggingCheckBox = CheckBox("Enable asynchronous logging");
            _dbVacuumIntervalTextBox = TextBox();
            _enableAnimationsCheckBox = CheckBox("Enable UI animations");

            LoadCurrentSettings(markClean: true);
            Content = BuildContent();
        }

        private Control BuildContent()
        {
            var tabs = new TabControl
            {
                Margin = new Thickness(16, 16, 16, 0),
                Items =
                {
                    Tab("General", GeneralTab()),
                    Tab("Appearance", AppearanceTab()),
                    Tab("Updates", UpdatesTab()),
                    Tab("Logging", LoggingTab()),
                    Tab("Database", DatabaseTab()),
                    Tab("Advanced", AdvancedTab())
                }
            };

            var restoreButton = DialogHelpers.Button("Restore Defaults");
            restoreButton.Click += RestoreDefaults_Click;

            var saveButton = DialogHelpers.Button("Save");
            saveButton.Click += SaveButton_Click;

            var cancelButton = DialogHelpers.Button("Cancel");
            cancelButton.Click += CancelButton_Click;

            var footer = new Border
            {
                Padding = new Thickness(16),
                Child = DialogHelpers.Buttons(restoreButton, cancelButton, saveButton)
            };

            var root = new Grid
            {
                RowDefinitions = new RowDefinitions("*,Auto")
            };
            root.Children.Add(tabs);
            Grid.SetRow(footer, 1);
            root.Children.Add(footer);
            return root;
        }

        private Control GeneralTab()
        {
            var browseButton = DialogHelpers.Button("Browse...");
            browseButton.Click += BrowseDefaultLocation_Click;

            var locationGrid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("*,Auto"),
                ColumnSpacing = 8,
                Children = { _defaultLocationTextBox, browseButton }
            };
            Grid.SetColumn(browseButton, 1);

            return ScrollContent(
                Section(
                    "Default Locker Location",
                    "New lockers will be created in this folder by default.",
                    locationGrid));
        }

        private Control AppearanceTab()
        {
            return ScrollContent(
                Section(
                    "Theme",
                    "Choose the application color theme.",
                    _themeBox),
                Section(
                    "Default View",
                    null,
                    _gridViewRadio,
                    _listViewRadio));
        }

        private Control UpdatesTab()
        {
            return ScrollContent(
                Section(
                    "Update Checks",
                    null,
                    _autoUpdateCheckBox),
                Section(
                    "Update Channel",
                    "Choose which type of updates you want to receive.",
                    _stableChannelRadio,
                    Description("Receive only stable, tested releases.", leftMargin: 22),
                    _unstableChannelRadio,
                    Description("Receive the newest available release, including unstable builds.", leftMargin: 22)));
        }

        private Control LoggingTab()
        {
            var openLogsButton = DialogHelpers.Button("Open Logs Folder");
            openLogsButton.Click += OpenLogsFolder_Click;

            return ScrollContent(
                Section(
                    "Basic Logging Options",
                    null,
                    _devModeCheckBox,
                    _enableFileLoggingCheckBox),
                Section(
                    "Minimum Log Level",
                    "Only log messages at or above this level.",
                    Narrow(_logLevelBox)),
                Section(
                    "Log Format",
                    "Choose how log entries are formatted.",
                    Narrow(_logFormatBox)),
                Section(
                    "Log File Rotation",
                    "Automatically rotate log files based on size.",
                    Field("Max file size (MB)", Narrow(_maxFileSizeTextBox)),
                    Field("Max retained files", Narrow(_maxRetainedFilesTextBox)),
                    _enableCompressionCheckBox),
                Section(
                    "Advanced Options",
                    null,
                    _includeTimestampsCheckBox,
                    _includeThreadIdCheckBox,
                    Field("Date/time format", Narrow(_dateTimeFormatBox)),
                    _asyncLoggingCheckBox),
                Section(
                    "Logs",
                    null,
                    openLogsButton));
        }

        private Control DatabaseTab()
        {
            var vacuumButton = DialogHelpers.Button("Vacuum Database Now");
            vacuumButton.Click += VacuumDatabase_Click;

            return ScrollContent(
                Section(
                    "Database Maintenance",
                    "Optimize the database to improve performance and reclaim disk space.",
                    Field("Auto-vacuum interval (days)", Narrow(_dbVacuumIntervalTextBox)),
                    vacuumButton,
                    Description("Manually optimize database and reclaim unused space.")));
        }

        private Control AdvancedTab()
        {
            var clearCacheButton = DialogHelpers.Button("Clear Application Cache");
            clearCacheButton.Click += ClearCache_Click;

            var resetButton = DialogHelpers.Button("Reset All Settings");
            resetButton.Click += ResetSettings_Click;

            return ScrollContent(
                Section(
                    "Performance",
                    null,
                    _enableAnimationsCheckBox,
                    Description("Disable for better performance on slower systems.", leftMargin: 22)),
                Section(
                    "Data Management",
                    null,
                    clearCacheButton,
                    Description("Removes temporary files and cached data when implemented."),
                    resetButton,
                    Description("Restores all settings to their default values.")));
        }

        private void LoadCurrentSettings(bool markClean)
        {
            var settings = SettingsManager.Settings;

            _defaultLocationTextBox.Text = string.IsNullOrWhiteSpace(settings.DefaultLockerLocation)
                ? AppPaths.CdlDir
                : settings.DefaultLockerLocation;

            _themeBox.SelectedItem = settings.AppTheme == "CDS" ? "ColDog Studios" : settings.AppTheme;
            _gridViewRadio.IsChecked = settings.DefaultGuiViewMode == GuiViewMode.Grid;
            _listViewRadio.IsChecked = settings.DefaultGuiViewMode == GuiViewMode.List;
            _autoUpdateCheckBox.IsChecked = settings.AutoUpdate;
            _stableChannelRadio.IsChecked = settings.UpdateChannel == UpdateChannel.Stable;
            _unstableChannelRadio.IsChecked = settings.UpdateChannel == UpdateChannel.Unstable;
            _devModeCheckBox.IsChecked = settings.DevMode;
            _enableFileLoggingCheckBox.IsChecked = settings.EnableFileLogging;
            _logLevelBox.SelectedItem = ChoiceOrDefault(LogLevelChoices, settings.LogLevel, "Info");
            _logFormatBox.SelectedItem = ChoiceOrDefault(LogFormatChoices, settings.LogFormat, "json");
            _maxFileSizeTextBox.Text = settings.MaxFileSizeMb.ToString();
            _maxRetainedFilesTextBox.Text = settings.MaxRetainedFiles.ToString();
            _enableCompressionCheckBox.IsChecked = settings.EnableCompression;
            _includeTimestampsCheckBox.IsChecked = settings.IncludeTimestamps;
            _includeThreadIdCheckBox.IsChecked = settings.IncludeThreadId;
            _dateTimeFormatBox.SelectedItem = ChoiceOrDefault(DateTimeFormatChoices, settings.DateTimeFormat, "UTC");
            _asyncLoggingCheckBox.IsChecked = settings.AsyncLogging;
            _dbVacuumIntervalTextBox.Text = settings.DatabaseVacuumInterval.ToString();
            _enableAnimationsCheckBox.IsChecked = settings.EnableAnimations;

            if (markClean)
            {
                _hasChanges = false;
            }
        }

        private async void BrowseDefaultLocation_Click(object? sender, EventArgs e)
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

            _defaultLocationTextBox.Text = folder.Path.LocalPath;
            MarkChanged();
        }

        private async void OpenLogsFolder_Click(object? sender, EventArgs e)
        {
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

        private async void VacuumDatabase_Click(object? sender, EventArgs e)
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

        private async void ClearCache_Click(object? sender, EventArgs e)
        {
            await new MessageDialog(
                    "Clear Cache",
                    "There is no application cache to clear yet.",
                    MessageDialogKind.Information)
                .ShowDialog<object?>(this);
        }

        private async void ResetSettings_Click(object? sender, EventArgs e)
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

        private void RestoreDefaults_Click(object? sender, EventArgs e)
        {
            RestoreDefaultSettings();
            LoadCurrentSettings(markClean: false);
            MarkChanged();
        }

        private async void SaveButton_Click(object? sender, EventArgs e)
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

        private async void CancelButton_Click(object? sender, EventArgs e)
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
            settings.DefaultLockerLocation = string.IsNullOrWhiteSpace(_defaultLocationTextBox.Text)
                ? AppPaths.CdlDir
                : _defaultLocationTextBox.Text;
            settings.AppTheme = ThemeToSettingsValue(_themeBox.SelectedItem?.ToString() ?? _themeService.CurrentTheme);
            settings.DefaultGuiViewMode = _listViewRadio.IsChecked == true ? GuiViewMode.List : GuiViewMode.Grid;
            settings.AutoUpdate = _autoUpdateCheckBox.IsChecked == true;
            settings.UpdateChannel = _unstableChannelRadio.IsChecked == true ? UpdateChannel.Unstable : UpdateChannel.Stable;
            settings.DevMode = _devModeCheckBox.IsChecked == true;
            settings.EnableFileLogging = _enableFileLoggingCheckBox.IsChecked == true;
            settings.LogLevel = _logLevelBox.SelectedItem?.ToString() ?? "Info";
            settings.LogFormat = _logFormatBox.SelectedItem?.ToString() ?? "json";
            settings.MaxFileSizeMb = ReadInt(_maxFileSizeTextBox, defaultValue: 10, min: 1, max: 1024);
            settings.MaxRetainedFiles = ReadInt(_maxRetainedFilesTextBox, defaultValue: 9, min: 1, max: 1000);
            settings.EnableCompression = _enableCompressionCheckBox.IsChecked == true;
            settings.IncludeTimestamps = _includeTimestampsCheckBox.IsChecked == true;
            settings.IncludeThreadId = _includeThreadIdCheckBox.IsChecked == true;
            settings.DateTimeFormat = _dateTimeFormatBox.SelectedItem?.ToString() ?? "UTC";
            settings.AsyncLogging = _asyncLoggingCheckBox.IsChecked == true;
            settings.DatabaseVacuumInterval = ReadInt(_dbVacuumIntervalTextBox, defaultValue: 30, min: 7, max: 90);
            settings.EnableAnimations = _enableAnimationsCheckBox.IsChecked == true;
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

        private TabItem Tab(string header, Control content)
        {
            return new TabItem
            {
                Header = new TextBlock
                {
                    Text = header,
                    FontSize = 14,
                    FontWeight = FontWeight.Normal,
                    TextWrapping = TextWrapping.NoWrap,
                    TextTrimming = TextTrimming.CharacterEllipsis
                },
                Content = content
            };
        }

        private static ScrollViewer ScrollContent(params Control[] sections)
        {
            var panel = new StackPanel
            {
                Margin = new Thickness(20),
                Spacing = 18
            };

            foreach (var section in sections)
            {
                panel.Children.Add(section);
            }

            return new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Content = panel
            };
        }

        private static Border Section(string title, string? description, params Control[] controls)
        {
            var panel = new StackPanel
            {
                Spacing = 8
            };

            panel.Children.Add(new TextBlock
            {
                Text = title,
                FontWeight = FontWeight.SemiBold,
                FontSize = 14
            });

            if (!string.IsNullOrWhiteSpace(description))
            {
                panel.Children.Add(Description(description));
            }

            foreach (var control in controls)
            {
                panel.Children.Add(control);
            }

            return new Border
            {
                Padding = new Thickness(14),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Child = panel
            };
        }

        private static TextBlock Description(string text, double leftMargin = 0)
        {
            return new TextBlock
            {
                Text = text,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Opacity = 0.75,
                Margin = new Thickness(leftMargin, 0, 0, 0)
            };
        }

        private static StackPanel Field(string label, Control control)
        {
            return new StackPanel
            {
                Spacing = 4,
                Children =
                {
                    new TextBlock
                    {
                        Text = label,
                        FontWeight = FontWeight.SemiBold,
                        FontSize = 12
                    },
                    control
                }
            };
        }

        private static T Narrow<T>(T control) where T : Control
        {
            control.Width = 160;
            control.HorizontalAlignment = HorizontalAlignment.Left;
            return control;
        }

        private TextBox TextBox(bool readOnly = false)
        {
            var textBox = new TextBox
            {
                IsReadOnly = readOnly
            };
            textBox.TextChanged += (_, _) => MarkChanged();
            return textBox;
        }

        private ComboBox ComboBox(IEnumerable<string> items)
        {
            var comboBox = new ComboBox
            {
                ItemsSource = items
            };
            comboBox.SelectionChanged += (_, _) => MarkChanged();
            return comboBox;
        }

        private CheckBox CheckBox(string content)
        {
            var checkBox = new CheckBox
            {
                Content = content
            };
            checkBox.PropertyChanged += (_, e) =>
            {
                if (e.Property == ToggleButton.IsCheckedProperty)
                {
                    MarkChanged();
                }
            };
            return checkBox;
        }

        private RadioButton Radio(string content, string groupName)
        {
            var radioButton = new RadioButton
            {
                Content = content,
                GroupName = groupName
            };
            radioButton.PropertyChanged += (_, e) =>
            {
                if (e.Property == ToggleButton.IsCheckedProperty)
                {
                    MarkChanged();
                }
            };
            return radioButton;
        }
    }
}

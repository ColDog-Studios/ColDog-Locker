using Avalonia.Controls;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Services.Configuration;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class SettingsDialog : Window
    {
        public SettingsDialog(IAppThemeService themeService)
        {
            Title = "Settings";
            Width = 560;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var themeBox = new ComboBox
            {
                ItemsSource = new[] { "Auto", "Light", "Dark", "ColDog Studios" },
                SelectedItem = SettingsManager.Settings.AppTheme == "CDS" ? "ColDog Studios" : SettingsManager.Settings.AppTheme
            };
            var defaultLocationBox = new TextBox { Text = SettingsManager.Settings.DefaultLockerLocation };
            var autoUpdateBox = new CheckBox { Content = "Check for updates automatically", IsChecked = SettingsManager.Settings.AutoUpdate };
            var devModeBox = new CheckBox { Content = "Enable developer menu", IsChecked = SettingsManager.Settings.DevMode };
            var listViewBox = new CheckBox
            {
                Content = "Use list view by default",
                IsChecked = SettingsManager.Settings.DefaultGuiViewMode == GuiViewMode.List
            };

            var saveButton = DialogHelpers.Button("Save");
            saveButton.Click += (_, _) =>
            {
                SettingsManager.Settings.DefaultLockerLocation = defaultLocationBox.Text ?? SettingsManager.Settings.DefaultLockerLocation;
                SettingsManager.Settings.AutoUpdate = autoUpdateBox.IsChecked == true;
                SettingsManager.Settings.DevMode = devModeBox.IsChecked == true;
                SettingsManager.Settings.DefaultGuiViewMode = listViewBox.IsChecked == true ? GuiViewMode.List : GuiViewMode.Grid;
                var selectedTheme = themeBox.SelectedItem?.ToString() == "ColDog Studios"
                    ? "CDS"
                    : themeBox.SelectedItem?.ToString() ?? themeService.CurrentTheme;
                SettingsManager.SaveSettings();
                Close(selectedTheme);
            };

            var cancelButton = DialogHelpers.Button("Cancel");
            cancelButton.Click += (_, _) => Close(null);

            Content = new StackPanel
            {
                Margin = new global::Avalonia.Thickness(18),
                Spacing = 14,
                Children =
                {
                    DialogHelpers.Field("Theme", themeBox),
                    DialogHelpers.Field("Default Locker Location", defaultLocationBox),
                    autoUpdateBox,
                    listViewBox,
                    devModeBox,
                    DialogHelpers.Buttons(cancelButton, saveButton)
                }
            };
        }
    }
}

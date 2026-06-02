using System.Diagnostics;
using System.Windows;
using System.Windows.Media.Animation;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs
{
    public partial class AboutDialog : Window
    {
        public AboutDialog()
        {
            InitializeComponent();
            LoadSystemInformation();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Play scale-in animation if animations are enabled
            if (SettingsManager.Settings.EnableAnimations)
            {
                try
                {
                    if (TryFindResource("WindowScaleInAnimation") is Storyboard storyboard)
                    {
                        storyboard.Begin(this);
                    }
                }
                catch
                {
                    // Animation failed, continue without it
                }
            }
        }

        private void LoadSystemInformation()
        {
            // Set application version
            VersionText.Text = $"Version {AppInfo.SemanticVersion ?? "Version unknown"}";

            // Set OS information
            try
            {
                OSText.Text = Environment.OSVersion.ToString();
            }
            catch
            {
                OSText.Text = "Unknown";
            }

            // Set .NET Runtime version
            try
            {
                RuntimeText.Text = $".NET {Environment.Version}";
            }
            catch
            {
                RuntimeText.Text = "Unknown";
            }

            // Set installation path
            try
            {
                InstallPathText.Text = AppContext.BaseDirectory;
            }
            catch
            {
                InstallPathText.Text = "Unknown";
            }
        }

        private void Documentation_Click(object sender, RoutedEventArgs e)
        {
            OpenUrl("https://github.com/ColDogStudios/ColDog-Locker/wiki");
        }

        private void GitHub_Click(object sender, RoutedEventArgs e)
        {
            OpenUrl("https://github.com/ColDogStudios/ColDog-Locker");
        }

        private void ReportIssue_Click(object sender, RoutedEventArgs e)
        {
            OpenUrl("https://github.com/ColDogStudios/ColDog-Locker/issues/new");
        }

        private void ContactSupport_Click(object sender, RoutedEventArgs e)
        {
            OpenUrl("mailto:support@coldogstudios.com?subject=ColDog%20Locker%20Support");
        }

        private async void CheckForUpdates_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = await Task.Run(() => UpdateService.CheckForUpdatesAsync());

                if (result.UpdateAvailable)
                {
                    var message = $"A new version is available!\n\n" +
                                  $"Current Version: {result.CurrentVersion}\n" +
                                  $"Latest Version: {result.LatestVersion}\n";

                    if (!string.IsNullOrWhiteSpace(result.ReleaseNotesMarkdown))
                    {
                        message += $"\nRelease Notes:\n{result.ReleaseNotesMarkdown.Trim()}\n";
                    }

                    if (!result.CanDownload)
                    {
                        message += $"\n{result.UserMessage ?? "This update cannot be downloaded automatically."}";
                        if (!string.IsNullOrWhiteSpace(result.ManualUpdateInstructions))
                        {
                            message += $"\n\n{result.ManualUpdateInstructions}";
                        }

                        if (!string.IsNullOrWhiteSpace(result.ReleaseUrl))
                        {
                            message += $"\n\nRelease: {result.ReleaseUrl}";
                        }

                        MessageDialog.ShowInformation(message, "Update Available", this);
                        return;
                    }

                    message += "\nWould you like to download and install it now?";

                    if (MessageDialog.ShowQuestion(message, "Update Available", this))
                    {
                        try
                        {
                            var filePath = await Task.Run(() => UpdateService.DownloadUpdateAsync(result));
                            MessageDialog.ShowInformation(
                                $"Update downloaded successfully to:\n{filePath}\n\nPlease run the installer to complete the update.",
                                "Download Complete",
                                this);
                        }
                        catch (Exception downloadEx)
                        {
                            var errorDialog = new ErrorDialog(
                                $"Failed to download update: {downloadEx.Message}",
                                downloadEx,
                                "Download Failed") { Owner = this };
                            errorDialog.ShowDialog();
                        }
                    }
                }
                else
                {
                    var message = $"ColDog Locker is up to date.\n\n" +
                                  $"Current Version: {result.CurrentVersion}\n" +
                                  $"Latest Version: {result.LatestVersion}";
                    MessageDialog.ShowInformation(message, "No Updates Available", this);
                }
            }
            catch (Exception ex)
            {
                var errorDialog = new ErrorDialog(
                    $"Failed to check for updates: {ex.Message}",
                    ex,
                    "Update Check Failed") { Owner = this };
                errorDialog.ShowDialog();
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void OpenUrl(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageDialog.ShowError(
                    $"Failed to open URL: {ex.Message}",
                    "Error",
                    this);
            }
        }

        /// <summary>
        ///     Convenience method to show the About dialog
        /// </summary>
        public static void Show(Window? owner = null)
        {
            var dialog = new AboutDialog();
            if (owner != null)
            {
                dialog.Owner = owner;
            }

            dialog.ShowDialog();
        }
    }
}

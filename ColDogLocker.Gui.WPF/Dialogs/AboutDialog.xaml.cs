using System.Diagnostics;
using System.Windows;
using System.Windows.Media.Animation;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;

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
            // Play scale-in animation
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
            await WpfUpdateWorkflow.RunAsync(this);
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

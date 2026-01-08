using System;
using System.Diagnostics;
using System.Windows;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs;

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
        if (Properties.Settings.Default.EnableAnimations)
        {
            try
            {
                if (TryFindResource("WindowScaleInAnimation") is System.Windows.Media.Animation.Storyboard storyboard)
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
        try
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            VersionText.Text = $"Version {version?.ToString(3) ?? "1.0.0"}";
        }
        catch
        {
            VersionText.Text = "Version 1.0.0";
        }

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

    private void CheckForUpdates_Click(object sender, RoutedEventArgs e)
    {
        // TODO: Implement actual update check via UpdateManager service
        MessageDialog.ShowInformation(
            "You are running the latest version of ColDog Locker.",
            "No Updates Available",
            this);
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
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
    /// Convenience method to show the About dialog
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

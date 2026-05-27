using System;
using System.IO;
using System.Text;
using System.Windows;
using ColDogStudios.ColDogLocker.Core.Constants;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs
{
    /// <summary>
    /// Developer Information Dialog - shows detailed build and system information
    /// </summary>
    public partial class DevDialog : Window
    {
        public DevDialog()
        {
            InitializeComponent();
            LoadInformation();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Play scale-in animation if animations are enabled
            if (SettingsManager.Settings.EnableAnimations)
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

        private void LoadInformation()
        {
            // Load Build Information
            VersionText.Text = AppInfo.SemanticVersion ?? "Unknown";
            BuildNumberText.Text = AppInfo.BuildNumber ?? "Unknown";
            BuildDateText.Text = AppInfo.BuildDate ?? "Unknown";
            BuildTimeText.Text = AppInfo.BuildTime ?? "Unknown";
            FullVersionText.Text = AppInfo.BuildVersion ?? "Unknown";

            // Load System Information
            try
            {
                OSText.Text = Environment.OSVersion.VersionString;
            }
            catch
            {
                OSText.Text = "Unknown";
            }

            try
            {
                RuntimeText.Text = $".NET {Environment.Version}";
            }
            catch
            {
                RuntimeText.Text = "Unknown";
            }

            try
            {
                ProcessorCountText.Text = Environment.ProcessorCount.ToString();
            }
            catch
            {
                ProcessorCountText.Text = "Unknown";
            }

            try
            {
                var totalMemory = GC.GetTotalMemory(false);
                var totalMemoryMB = totalMemory / (1024.0 * 1024.0);
                TotalMemoryText.Text = $"{totalMemoryMB:F2} MB";
            }
            catch
            {
                TotalMemoryText.Text = "Unknown";
            }

            try
            {
                var workingSet = Environment.WorkingSet;
                var workingSetMB = workingSet / (1024.0 * 1024.0);
                AvailableMemoryText.Text = $"{workingSetMB:F2} MB";
            }
            catch
            {
                AvailableMemoryText.Text = "Unknown";
            }

            try
            {
                ArchitectureText.Text = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            }
            catch
            {
                ArchitectureText.Text = "Unknown";
            }

            try
            {
                InstallPathText.Text = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "Unknown";
            }
            catch
            {
                InstallPathText.Text = "Unknown";
            }

            // Load Application Paths
            try
            {
                ConfigDirText.Text = Variables.localConfig;
            }
            catch
            {
                ConfigDirText.Text = "Unknown";
            }

            try
            {
                var dbPath = Path.Combine(Variables.localConfig, "lockers.db");
                DatabasePathText.Text = dbPath;
            }
            catch
            {
                DatabasePathText.Text = "Unknown";
            }
        }

        private void CopyToClipboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var info = new System.Text.StringBuilder();
                info.AppendLine("=== ColDog Locker Developer Information ===");
                info.AppendLine();
                info.AppendLine("BUILD INFORMATION:");
                info.AppendLine($"  Version: {VersionText.Text}");
                info.AppendLine($"  Build Number: {BuildNumberText.Text}");
                info.AppendLine($"  Build Date: {BuildDateText.Text}");
                info.AppendLine($"  Build Time: {BuildTimeText.Text}");
                info.AppendLine($"  Full Version: {FullVersionText.Text}");
                info.AppendLine();
                info.AppendLine("SYSTEM INFORMATION:");
                info.AppendLine($"  OS: {OSText.Text}");
                info.AppendLine($"  .NET Version: {RuntimeText.Text}");
                info.AppendLine($"  CPU Cores: {ProcessorCountText.Text}");
                info.AppendLine($"  Total Memory: {TotalMemoryText.Text}");
                info.AppendLine($"  Available Memory: {AvailableMemoryText.Text}");
                info.AppendLine($"  Architecture: {ArchitectureText.Text}");
                info.AppendLine($"  Install Path: {InstallPathText.Text}");
                info.AppendLine();
                info.AppendLine("APPLICATION PATHS:");
                info.AppendLine($"  Config Directory: {ConfigDirText.Text}");
                info.AppendLine($"  Database Path: {DatabasePathText.Text}");

                System.Windows.Clipboard.SetText(info.ToString());
                MessageDialog.ShowInformation("Developer information copied to clipboard.", "Success", this);
            }
            catch (Exception ex)
            {
                ErrorDialog.Show("Failed to copy developer information to clipboard.", ex, "Error", this);
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}

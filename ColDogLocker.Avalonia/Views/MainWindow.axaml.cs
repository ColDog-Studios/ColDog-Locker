using Avalonia.Controls;
using Avalonia.Interactivity;
//using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Avalonia.Views
{
    /// <summary>
    /// Main windows for ColDog Locker Avalonia GUI.
    /// </summary>
    public partial class MainWindow : Window
    {
        //private readonly MainWindowViewModel _viewModel;
        private bool _isGridView = true;
        private string _currentSortColumn = "";
        private bool _currentSortAscending = true;
        private bool _listViewInitialized = false;

        public MainWindow()
        {
            InitializeComponent();

            // Initialize UI state
            //UpdateStatusBar();
            //UpdateCommandStates();
            //UpdateDeveloperMenuVisibility();

            // Load lockers from database
            LoadLockers();
        }

        private void LoadLockers()
        {
            try
            {
                
            }
            catch (Exception ex)
            {

            }
        }

        private long CalculateDirectorySize(string path)
        {
            try
            {
                if (!System.IO.Directory.Exists(path))
                {
                    return 0;
                }

                var dirInfo = new System.IO.DirectoryInfo(path);
                return dirInfo.EnumerateFiles("*", System.IO.SearchOption.AllDirectories)
                    .Sum(file => file.Length);
            }
            catch
            {
                return 0;
            }
        }

        #region Menu and Toolbar Event Handlers

        private void New_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void Exit_Click(object? sender, RoutedEventArgs e)
        {
            Logger.Log(LogLevel.Debug, "Exiting ColDog Locker");
            Close();
        }

        private void Lock_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void Unlock_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void Remove_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void Properties_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void OpenLocation_Click(object? sender, RoutedEventArgs e)
        {
            /*
            var selectedLockers = GetSelectedLockers();
            if (selectedLockers.Count == 0)
            {
                return;
            }

            foreach (var locker in selectedLockers)
            {
                try
                {
                    System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{locker.Location}\"");
                }
                catch (Exception ex)
                {
                    Logger.Log(LogLevel.Error, $"Failed to open locker location for {locker.Name}", ex);
                    // Show error dialog
                }
            }
            */
        }

        private void ToggleView_Click(object? sender, RoutedEventArgs e)
        {
            _isGridView = !_isGridView;

            if (_isGridView)
            {
                // Switch to ListView
            }
            else
            {
                // Switch to GridView
            }
        }

        private void Refresh_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                // Reload lockers from database
                //TODO: LockerService.LoadLockers();

                // Refresh the UI
                LoadLockers();

                // TODO: Show success message
                Logger.Log(LogLevel.Debug, "Lockers refreshed successfully");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Error, "Failed to refresh lockers", ex);
                // TODO: Show error dialog
            }
        }

        private void Settings_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void CheckUpdates_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void DevInfo_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void TestErrorDialog_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        private void Documentation_Click(object? sender, RoutedEventArgs e)
        {
            // Open the docs in the default browser
            try
            {
                // Use Cross Platform approach
                var url = "https://github.com/ColDog-Studios/ColDog-Locker";
                if (OperatingSystem.IsWindows())
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = url,
                        UseShellExecute = true
                    });
                }
                else if (OperatingSystem.IsLinux())
                {
                    // Use Multi-distro multi-display manager approach
                    System.Diagnostics.Process.Start("xdg-open", url);
                }
            }
            catch
            {
                Logger.Log(LogLevel.Error, "Failed to open documentation URL");
                // TODO: Show error dialog
            }
        }

        private void About_Click(object? sender, RoutedEventArgs e)
        {
            
        }

        #endregion
    }
}

using Avalonia.Controls;
using Avalonia.Interactivity;

namespace ColDogStudios.ColDogLocker.Avalonia.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        #region Menu and Toolbar Event Handlers

        private void New_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void Exit_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close();
        }

        private void Lock_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void Unlock_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void Remove_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void Properties_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void OpenLocation_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void ToggleView_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void Refresh_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void Settings_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void CheckUpdates_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void DevInfo_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void TestErrorDialog_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        private void Documentation_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            // Open the docs in the default browser
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "https://github.com/ColDog-Studios/ColDog-Locker",
                    UseShellExecute = true
                });
            }
            catch { }
        }

        private void About_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            
        }

        #endregion
    }
}

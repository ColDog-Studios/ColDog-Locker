using System;
using System.Windows;
using System.Windows.Controls;

namespace ColDogStudios.ColDogLocker.Desktop
{
    public partial class MainWindow : Window
    {
        private MainWindowViewModel? viewModel;

        public MainWindow()
        {
            try
            {
                InitializeComponent();
                
                // Create ViewModel but don't initialize it yet
                viewModel = new MainWindowViewModel();
                DataContext = viewModel;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error in MainWindow constructor: {ex.Message}\n\nStack trace:\n{ex.StackTrace}", 
                    "MainWindow Error", MessageBoxButton.OK, MessageBoxImage.Error);
                throw;
            }
        }

        // Method to initialize the ViewModel after Core services are ready
        public async void InitializeViewModel()
        {
            if (viewModel != null)
            {
                try
                {
                    await viewModel.InitializeAsync();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Warning: Could not initialize locker data: {ex.Message}", 
                        "Initialization Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }

        private void DataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Handle selection changes if needed
            if (DataContext is MainWindowViewModel vm && sender is DataGrid dataGrid)
            {
                vm.SelectedLocker = dataGrid.SelectedItem as ColDogStudios.ColDogLocker.Core.Models.LockerModel;
            }
        }

        private void ToggleView_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainWindowViewModel vm)
            {
                vm.ToggleViewCommand.Execute(null);
                
                // Update visibility based on current view mode
                LockersDataGrid.Visibility = vm.IsGridView ? Visibility.Collapsed : Visibility.Visible;
                LockersListView.Visibility = vm.IsGridView ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }
}

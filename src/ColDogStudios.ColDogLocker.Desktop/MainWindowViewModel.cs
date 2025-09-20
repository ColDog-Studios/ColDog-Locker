using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows;
using ColDogStudios.ColDogLocker.Core;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Core.Services;
using ColDogStudios.ColDogLocker.Core.Utils;

namespace ColDogStudios.ColDogLocker.Desktop
{
    public class MainWindowViewModel : INotifyPropertyChanged
    {
        private bool _isGridView = true;
        private LockerModel? _selectedLocker;
        private string _statusMessage = "Ready";

        public MainWindowViewModel()
        {
            LoadLockersCommand = new RelayCommand(async () => await LoadLockersAsync(), () => true);
            CreateLockerCommand = new RelayCommand(() => CreateLocker(), () => true);
            LockCommand = new RelayCommand(async () => await LockSelectedAsync(), () => SelectedLocker != null && !SelectedLocker.IsLocked);
            UnlockCommand = new RelayCommand(async () => await UnlockSelectedAsync(), () => SelectedLocker != null && SelectedLocker.IsLocked);
            DeleteCommand = new RelayCommand(() => DeleteSelected(), () => SelectedLocker != null);
            SettingsCommand = new RelayCommand(() => ShowSettings(), () => true);
            AboutCommand = new RelayCommand(() => ShowAbout(), () => true);
            ToggleViewCommand = new RelayCommand(() => ToggleView(), () => true);
            
            // Set initial status
            StatusMessage = "Ready";
            
            // Don't load lockers immediately in constructor - do it after initialization
        }

        // Method to initialize after Core services are ready
        public async Task InitializeAsync()
        {
            await LoadLockersAsync();
        }

        public ObservableCollection<LockerModel> Lockers { get; } = new ObservableCollection<LockerModel>();

        public bool IsGridView
        {
            get => _isGridView;
            set
            {
                _isGridView = value;
                OnPropertyChanged();
            }
        }

        public LockerModel? SelectedLocker
        {
            get => _selectedLocker;
            set
            {
                _selectedLocker = value;
                OnPropertyChanged();
                ((RelayCommand)LockCommand).RaiseCanExecuteChanged();
                ((RelayCommand)UnlockCommand).RaiseCanExecuteChanged();
                ((RelayCommand)DeleteCommand).RaiseCanExecuteChanged();
            }
        }

        public string StatusMessage
        {
            get => _statusMessage;
            set
            {
                _statusMessage = value;
                OnPropertyChanged();
            }
        }

        // Commands
        public ICommand LoadLockersCommand { get; }
        public ICommand CreateLockerCommand { get; }
        public ICommand LockCommand { get; }
        public ICommand UnlockCommand { get; }
        public ICommand DeleteCommand { get; }
        public ICommand SettingsCommand { get; }
        public ICommand AboutCommand { get; }
        public ICommand ToggleViewCommand { get; }

        private async Task LoadLockersAsync()
        {
            try
            {
                StatusMessage = "Loading lockers...";
                
                // Ensure this runs on a background thread
                await Task.Run(() => 
                {
                    try
                    {
                        LockerService.LoadLockers();
                    }
                    catch (Exception ex)
                    {
                        // If Core services fail, just log it and continue
                        System.Diagnostics.Debug.WriteLine($"Core service error: {ex.Message}");
                    }
                });
                
                var lockers = LockerService.GetAllLockers();
                
                // Update UI on UI thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Lockers.Clear();
                    foreach (var locker in lockers)
                    {
                        Lockers.Add(locker);
                    }
                    StatusMessage = $"Loaded {Lockers.Count} lockers";
                });
            }
            catch (Exception ex)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    StatusMessage = $"Error loading lockers: {ex.Message}";
                });
                
                try
                {
                    Logger.AddEntry($"Error loading lockers: {ex}", LogLevel.Error);
                }
                catch
                {
                    // Logger might not be initialized
                    System.Diagnostics.Debug.WriteLine($"Logger error: {ex.Message}");
                }
            }
        }

        private void CreateLocker()
        {
            try
            {
                var dialog = new Views.NewLockerDialog();
                if (dialog.ShowDialog() == true)
                {
                    var passwordDialog = new Views.PasswordDialog($"Enter password for new locker '{dialog.LockerName}':");
                    if (passwordDialog.ShowDialog() == true)
                    {
                        var newLocker = new LockerModel(dialog.LockerName, passwordDialog.Password, dialog.LockerPath);
                        LockerService.AddLocker(newLocker);
                        Lockers.Add(newLocker);
                        StatusMessage = $"Created locker: {newLocker.LockerName}";
                    }
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error creating locker: {ex.Message}";
                Logger.AddEntry($"Error creating locker: {ex}", LogLevel.Error);
                MessageBox.Show($"Error creating locker: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task LockSelectedAsync()
        {
            if (SelectedLocker == null) return;

            try
            {
                var dialog = new Views.PasswordDialog($"Enter password to lock '{SelectedLocker.LockerName}':");
                if (dialog.ShowDialog() == true)
                {
                    StatusMessage = $"Locking {SelectedLocker.LockerName}...";
                    await LockerService.LockAsync(SelectedLocker, dialog.Password);
                    StatusMessage = $"Locked {SelectedLocker.LockerName}";
                    await LoadLockersAsync(); // Refresh the list
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error locking {SelectedLocker.LockerName}: {ex.Message}";
                Logger.AddEntry($"Error locking {SelectedLocker.LockerName}: {ex}", LogLevel.Error);
                MessageBox.Show($"Error locking {SelectedLocker.LockerName}: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task UnlockSelectedAsync()
        {
            if (SelectedLocker == null) return;

            try
            {
                var dialog = new Views.PasswordDialog($"Enter password to unlock '{SelectedLocker.LockerName}':");
                if (dialog.ShowDialog() == true)
                {
                    StatusMessage = $"Unlocking {SelectedLocker.LockerName}...";
                    await LockerService.UnlockAsync(SelectedLocker, dialog.Password);
                    StatusMessage = $"Unlocked {SelectedLocker.LockerName}";
                    await LoadLockersAsync(); // Refresh the list
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error unlocking {SelectedLocker.LockerName}: {ex.Message}";
                Logger.AddEntry($"Error unlocking {SelectedLocker.LockerName}: {ex}", LogLevel.Error);
                MessageBox.Show($"Error unlocking {SelectedLocker.LockerName}: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DeleteSelected()
        {
            if (SelectedLocker == null) return;

            try
            {
                var result = MessageBox.Show(
                    $"Are you sure you want to delete the locker '{SelectedLocker.LockerName}'?",
                    "Confirm Delete", 
                    MessageBoxButton.YesNo, 
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    LockerService.RemoveLocker(SelectedLocker);
                    Lockers.Remove(SelectedLocker);
                    StatusMessage = $"Deleted locker: {SelectedLocker.LockerName}";
                    SelectedLocker = null;
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error deleting locker: {ex.Message}";
                Logger.AddEntry($"Error deleting locker: {ex}", LogLevel.Error);
                MessageBox.Show($"Error deleting locker: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowSettings()
        {
            try
            {
                var dialog = new Views.SettingsDialog();
                dialog.ShowDialog();
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error opening settings: {ex.Message}";
                Logger.AddEntry($"Error opening settings: {ex}", LogLevel.Error);
                MessageBox.Show($"Error opening settings: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowAbout()
        {
            try
            {
                var dialog = new Views.AboutDialog();
                dialog.ShowDialog();
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error opening about dialog: {ex.Message}";
                Logger.AddEntry($"Error opening about dialog: {ex}", LogLevel.Error);
                MessageBox.Show($"Error opening about dialog: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ToggleView()
        {
            IsGridView = !IsGridView;
            StatusMessage = IsGridView ? "Switched to grid view" : "Switched to list view";
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class RelayCommand : ICommand
    {
        private readonly Action _execute;
        private readonly Func<bool> _canExecute;

        public RelayCommand(Action execute, Func<bool> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public event EventHandler CanExecuteChanged;

        public bool CanExecute(object parameter)
        {
            return _canExecute?.Invoke() ?? true;
        }

        public void Execute(object parameter)
        {
            _execute();
        }

        public void RaiseCanExecuteChanged()
        {
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public class AsyncRelayCommand : ICommand
    {
        private readonly Func<Task> _execute;
        private readonly Func<bool> _canExecute;
        private bool _isExecuting;

        public AsyncRelayCommand(Func<Task> execute, Func<bool> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public event EventHandler CanExecuteChanged;

        public bool CanExecute(object parameter)
        {
            return !_isExecuting && (_canExecute?.Invoke() ?? true);
        }

        public async void Execute(object parameter)
        {
            if (CanExecute(parameter))
            {
                try
                {
                    _isExecuting = true;
                    RaiseCanExecuteChanged();
                    await _execute();
                }
                finally
                {
                    _isExecuting = false;
                    RaiseCanExecuteChanged();
                }
            }
        }

        public void RaiseCanExecuteChanged()
        {
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }
}

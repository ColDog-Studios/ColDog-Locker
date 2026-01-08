using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using ColDogStudios.ColDogLocker.Gui.WPF.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ColDogStudios.ColDogLocker.Gui.WPF.ViewModels
{
    /// <summary>
    /// Main view model for the application
    /// </summary>
    public partial class MainViewModel : ObservableObject
    {
        [ObservableProperty]
        private ObservableCollection<LockerViewModel> _lockers = new();

        [ObservableProperty]
        private ObservableCollection<LockerViewModel> _filteredLockers = new();

        [ObservableProperty]
        private ObservableCollection<LockerViewModel> _selectedLockers = new();

        [ObservableProperty]
        private string _searchText = string.Empty;

        [ObservableProperty]
        private bool _isGridView = true;

        [ObservableProperty]
        private string _sortColumn = "Name";

        [ObservableProperty]
        private bool _sortAscending = true;

        /// <summary>
        /// Gets the total number of lockers
        /// </summary>
        public int TotalLockers => Lockers.Count;

        /// <summary>
        /// Gets the number of locked lockers
        /// </summary>
        public int LockedCount => Lockers.Count(l => l.IsLocked);

        /// <summary>
        /// Gets the number of unlocked lockers
        /// </summary>
        public int UnlockedCount => Lockers.Count(l => !l.IsLocked);

        /// <summary>
        /// Gets the number of selected lockers
        /// </summary>
        public int SelectedCount => SelectedLockers.Count;

        public MainViewModel()
        {
            // Initialize with filtered lockers
            FilterLockers();
        }

        [RelayCommand]
        private async Task CreateNewLockerAsync()
        {
            // Will be implemented when we create the dialog
            await Task.CompletedTask;
        }

        [RelayCommand(CanExecute = nameof(CanLockUnlock))]
        private async Task LockSelectedAsync()
        {
            // Will be implemented with password dialog
            await Task.CompletedTask;
        }

        private bool CanLockUnlock() => SelectedLockers.Count > 0;

        [RelayCommand(CanExecute = nameof(CanLockUnlock))]
        private async Task UnlockSelectedAsync()
        {
            // Will be implemented with password dialog
            await Task.CompletedTask;
        }

        [RelayCommand(CanExecute = nameof(CanLockUnlock))]
        private async Task RemoveSelectedAsync()
        {
            // Will be implemented with confirmation dialog
            await Task.CompletedTask;
        }

        [RelayCommand(CanExecute = nameof(CanLockUnlock))]
        private async Task OpenLocationAsync()
        {
            // Will be implemented to open in file explorer
            await Task.CompletedTask;
        }

        [RelayCommand]
        private void ToggleView()
        {
            IsGridView = !IsGridView;
        }

        [RelayCommand]
        private async Task RefreshAsync()
        {
            // Will be implemented to reload lockers
            await Task.CompletedTask;
        }

        [RelayCommand]
        private async Task ShowSettingsAsync()
        {
            // Will be implemented when we create settings dialog
            await Task.CompletedTask;
        }

        partial void OnSearchTextChanged(string value)
        {
            FilterLockers();
        }

        partial void OnSortColumnChanged(string value)
        {
            SortLockers();
        }

        partial void OnSortAscendingChanged(bool value)
        {
            SortLockers();
        }

        private void FilterLockers()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                FilteredLockers = new ObservableCollection<LockerViewModel>(Lockers);
            }
            else
            {
                var filtered = Lockers.Where(l =>
                    l.Name.Contains(SearchText, System.StringComparison.OrdinalIgnoreCase));
                FilteredLockers = new ObservableCollection<LockerViewModel>(filtered);
            }

            SortLockers();
            UpdateStatusCounts();
        }

        private void SortLockers()
        {
            var sorted = SortColumn switch
            {
                "Name" => SortAscending
                    ? FilteredLockers.OrderBy(l => l.Name)
                    : FilteredLockers.OrderByDescending(l => l.Name),
                "Status" => SortAscending
                    ? FilteredLockers.OrderByDescending(l => l.IsLocked) // Locked first when ascending
                    : FilteredLockers.OrderBy(l => l.IsLocked),
                "LastModified" => SortAscending
                    ? FilteredLockers.OrderBy(l => l.LastModified)
                    : FilteredLockers.OrderByDescending(l => l.LastModified),
                "Size" => SortAscending
                    ? FilteredLockers.OrderBy(l => l.Size)
                    : FilteredLockers.OrderByDescending(l => l.Size),
                "Location" => SortAscending
                    ? FilteredLockers.OrderBy(l => l.Location)
                    : FilteredLockers.OrderByDescending(l => l.Location),
                _ => SortAscending
                    ? FilteredLockers.OrderBy(l => l.Name)
                    : FilteredLockers.OrderByDescending(l => l.Name)
            };

            FilteredLockers = new ObservableCollection<LockerViewModel>(sorted);
        }

        private void UpdateStatusCounts()
        {
            OnPropertyChanged(nameof(TotalLockers));
            OnPropertyChanged(nameof(LockedCount));
            OnPropertyChanged(nameof(UnlockedCount));
            OnPropertyChanged(nameof(SelectedCount));
        }

        public void UpdateSelection(ObservableCollection<LockerViewModel> selected)
        {
            SelectedLockers = selected;
            UpdateStatusCounts();

            // Update command states
            LockSelectedCommand.NotifyCanExecuteChanged();
            UnlockSelectedCommand.NotifyCanExecuteChanged();
            RemoveSelectedCommand.NotifyCanExecuteChanged();
            OpenLocationCommand.NotifyCanExecuteChanged();
        }
    }
}

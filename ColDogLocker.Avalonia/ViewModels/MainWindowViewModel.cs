/*
**  Copyright (C) 2026 ColDog Studios
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  long with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

using System.Collections.ObjectModel;
using ColDogStudios.ColDogLocker.Avalonia.Models;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Security;
using ColDogStudios.ColDogLocker.Services.Updates;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;

namespace ColDogStudios.ColDogLocker.Avalonia.ViewModels
{
    public partial class MainWindowViewModel : ViewModelBase
    {
        private readonly IUserDialogService _dialogs;
        private readonly IPlatformService _platformService;
        private readonly UpdateWorkflow _updateWorkflow;

        [ObservableProperty] private ObservableCollection<LockerItemViewModel> _filteredLockers = [];
        [ObservableProperty] private bool _isBusy;
        [ObservableProperty] private bool _isDeveloperMode;
        [ObservableProperty] private bool _isGridView = true;
        [ObservableProperty] private ObservableCollection<LockerItemViewModel> _lockers = [];
        [ObservableProperty] private LockerItemViewModel? _selectedLocker;
        [ObservableProperty] private string _searchText = string.Empty;
        [ObservableProperty] private bool _sortAscending = true;
        [ObservableProperty] private string _sortColumn = "Name";
        [ObservableProperty] private string _statusMessage = "Ready";

        public MainWindowViewModel(
            IUserDialogService dialogs,
            IPlatformService platformService,
            UpdateWorkflow updateWorkflow)
        {
            _dialogs = dialogs;
            _platformService = platformService;
            _updateWorkflow = updateWorkflow;
            IsDeveloperMode = SettingsManager.Settings.DevMode;
            IsGridView = SettingsManager.Settings.DefaultGuiViewMode == GuiViewMode.Grid;
        }

        public int TotalLockers => Lockers.Count;
        public int LockedCount => Lockers.Count(locker => locker.IsLocked);
        public int UnlockedCount => Lockers.Count(locker => !locker.IsLocked);
        public int SelectedCount => SelectedLocker == null ? 0 : 1;
        public bool HasSelection => SelectedLocker != null;
        public bool CanLockSelected => SelectedLocker is { IsLocked: false };
        public bool CanUnlockSelected => SelectedLocker is { IsLocked: true };
        public bool CanRemoveSelected => SelectedLocker is { IsLocked: false };
        public bool IsListView => !IsGridView;
        public MaterialIconKind ToggleViewIconKind => IsGridView ? MaterialIconKind.ViewList : MaterialIconKind.ViewGrid;
        public IReadOnlyList<string> SortColumns { get; } = ["Name", "Status", "Modified", "Size", "Location"];

        public async Task InitializeAsync(Func<Task> appInitialization)
        {
            ArgumentNullException.ThrowIfNull(appInitialization);

            await RunWithUiErrorAsync("Startup Error", "Failed to initialize ColDog Locker.", async () =>
            {
                IsBusy = true;
                StatusMessage = "Starting...";
                try
                {
                    await appInitialization();
                }
                finally
                {
                    IsBusy = false;
                }
            });

            await RefreshAsync(showMessage: false);
        }

        [RelayCommand]
        private async Task CreateLockerAsync()
        {
            var request = await _dialogs.ShowNewLockerAsync();
            if (request == null)
            {
                return;
            }

            await RunWithUiErrorAsync("Create Locker Error", $"Failed to create locker '{request.LockerName}'.", async () =>
            {
                var locker = new LockerModel(
                    request.LockerName,
                    EncryptionHelper.HashPassword(request.Password),
                    request.Location);

                await Task.Run(() => LockerService.AddLocker(locker));

                AddOrReplaceLockerItem(CreateLockerItem(locker));
                StatusMessage = $"{TotalLockers} locker{(TotalLockers == 1 ? string.Empty : "s")} loaded";
                await _dialogs.ShowMessageAsync("Locker Created", $"Locker '{request.LockerName}' was created.");
            });
        }

        [RelayCommand(CanExecute = nameof(CanLockSelected))]
        private async Task LockSelectedAsync()
        {
            if (SelectedLocker == null)
            {
                return;
            }

            var password = await _dialogs.PromptPasswordAsync($"Lock {SelectedLocker.Name}");
            if (string.IsNullOrEmpty(password))
            {
                return;
            }

            await RunLockerOperationAsync(SelectedLocker, "Lock Error", async locker =>
            {
                await Task.Run(() => LockerService.Lock(locker, password));
                await RefreshAsync(showMessage: false);
                await _dialogs.ShowMessageAsync("Locker Locked", $"Locked: {locker.LockerName}");
            });
        }

        [RelayCommand(CanExecute = nameof(CanUnlockSelected))]
        private async Task UnlockSelectedAsync()
        {
            if (SelectedLocker == null)
            {
                return;
            }

            var password = await _dialogs.PromptPasswordAsync($"Unlock {SelectedLocker.Name}");
            if (string.IsNullOrEmpty(password))
            {
                return;
            }

            await RunLockerOperationAsync(SelectedLocker, "Unlock Error", async locker =>
            {
                await Task.Run(() => LockerService.Unlock(locker, password));
                await RefreshAsync(showMessage: false);
                await _dialogs.ShowMessageAsync("Locker Unlocked", $"Unlocked: {locker.LockerName}");
            });
        }

        [RelayCommand(CanExecute = nameof(CanRemoveSelected))]
        private async Task RemoveSelectedAsync()
        {
            if (SelectedLocker == null)
            {
                return;
            }

            if (SelectedLocker.IsLocked)
            {
                await _dialogs.ShowWarningAsync("Remove Locker", "Unlock the locker before removing it.");
                return;
            }

            var confirmed = await _dialogs.ConfirmAsync(
                "Remove Locker",
                $"Remove '{SelectedLocker.Name}' from the database? This will not delete its files.");
            if (!confirmed)
            {
                return;
            }

            await RunLockerOperationAsync(SelectedLocker, "Remove Error", async locker =>
            {
                await Task.Run(() => LockerService.RemoveLocker(locker));
                await RefreshAsync(showMessage: false);
                await _dialogs.ShowMessageAsync("Locker Removed", $"Removed: {locker.LockerName}");
            });
        }

        [RelayCommand(CanExecute = nameof(HasSelection))]
        private async Task ShowPropertiesAsync()
        {
            if (SelectedLocker == null)
            {
                return;
            }

            var locker = FindLocker(SelectedLocker);
            if (locker != null)
            {
                await _dialogs.ShowLockerPropertiesAsync(locker);
                await RefreshAsync(showMessage: false);
            }
        }

        [RelayCommand(CanExecute = nameof(HasSelection))]
        private async Task OpenLocationAsync()
        {
            if (SelectedLocker == null)
            {
                return;
            }

            await RunWithUiErrorAsync("Open Location Error", "Failed to open locker location.", async () =>
            {
                await _platformService.OpenFolderAndSelectAsync(SelectedLocker.Location);
            });
        }

        [RelayCommand]
        private void ToggleView()
        {
            IsGridView = !IsGridView;
        }

        [RelayCommand]
        private Task RefreshAsync()
        {
            return RefreshAsync(showMessage: true);
        }

        [RelayCommand]
        private async Task ShowSettingsAsync()
        {
            await _dialogs.ShowSettingsAsync();
            IsDeveloperMode = SettingsManager.Settings.DevMode;
            IsGridView = SettingsManager.Settings.DefaultGuiViewMode == GuiViewMode.Grid;
        }

        [RelayCommand]
        private async Task CheckForUpdatesAsync()
        {
            await _updateWorkflow.RunAsync();
        }

        [RelayCommand]
        private Task ShowDevInfoAsync()
        {
            return _dialogs.ShowDevInfoAsync();
        }

        [RelayCommand]
        private Task TestMessageInfoDialogAsync()
        {
            return _dialogs.ShowMessageAsync(
                "Test Information Message",
                "This is a MessageDialog information test.");
        }

        [RelayCommand]
        private Task TestMessageWarningDialogAsync()
        {
            return _dialogs.ShowWarningAsync(
                "Test Warning Message",
                "This is a MessageDialog warning test.");
        }

        [RelayCommand]
        private Task TestMessageErrorDialogAsync()
        {
            return _dialogs.ShowErrorAsync(
                "Test Error Message",
                "This is a simple MessageDialog error test without exception details.");
        }

        [RelayCommand]
        private async Task TestErrorDialogAsync()
        {
            try
            {
                throw new InvalidOperationException("Test exception");
            }
            catch (Exception ex)
            {
                await _dialogs.ShowErrorAsync(
                    "Test Error Dialog",
                    "This is a test error dialog.",
                    ex);
            }
        }

        [RelayCommand]
        private Task TestProgressDialogAsync()
        {
            return _dialogs.ShowProgressTestAsync();
        }

        [RelayCommand]
        private Task OpenDocumentationAsync()
        {
            return _platformService.OpenUrlAsync("https://github.com/ColDog-Studios/ColDog-Locker/tree/main/docs");
        }

        [RelayCommand]
        private Task ShowAboutAsync()
        {
            return _dialogs.ShowAboutAsync();
        }

        partial void OnSearchTextChanged(string value)
        {
            ApplyFilterAndSort();
        }

        partial void OnSortColumnChanged(string value)
        {
            ApplyFilterAndSort();
        }

        partial void OnSortAscendingChanged(bool value)
        {
            ApplyFilterAndSort();
        }

        partial void OnSelectedLockerChanged(LockerItemViewModel? value)
        {
            NotifySelectionStateChanged();
        }

        partial void OnIsGridViewChanged(bool value)
        {
            OnPropertyChanged(nameof(IsListView));
            OnPropertyChanged(nameof(ToggleViewIconKind));
        }

        private async Task RefreshAsync(bool showMessage)
        {
            await RunWithUiErrorAsync("Refresh Error", "Failed to refresh lockers.", async () =>
            {
                IsBusy = true;
                try
                {
                    var items = await LoadLockerItemsAsync();
                    Lockers = new ObservableCollection<LockerItemViewModel>(items);
                    ApplyFilterAndSort();
                    StatusMessage = $"{TotalLockers} locker{(TotalLockers == 1 ? string.Empty : "s")} loaded";
                    if (showMessage)
                    {
                        await _dialogs.ShowMessageAsync("Refresh", StatusMessage);
                    }
                }
                finally
                {
                    IsBusy = false;
                }
            });
        }

        private static async Task<List<LockerItemViewModel>> LoadLockerItemsAsync()
        {
            return await Task.Run(() =>
            {
                LockerService.LoadLockers();
                var snapshot = LockerService.GetLockersSnapshot();
                return snapshot.Select(CreateLockerItem).ToList();
            });
        }

        private void AddOrReplaceLockerItem(LockerItemViewModel item)
        {
            var existing = Lockers.FirstOrDefault(locker => locker.Guid == item.Guid);
            if (existing != null)
            {
                var index = Lockers.IndexOf(existing);
                Lockers[index] = item;
            }
            else
            {
                Lockers.Add(item);
            }

            ApplyFilterAndSort();
            SelectedLocker = FilteredLockers.FirstOrDefault(locker => locker.Guid == item.Guid);
        }

        private void ApplyFilterAndSort()
        {
            IEnumerable<LockerItemViewModel> query = Lockers;
            if (!string.IsNullOrWhiteSpace(SearchText))
            {
                query = query.Where(locker =>
                    locker.Name.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    locker.Location.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    locker.StatusText.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
            }

            query = SortColumn switch
            {
                "Status" => SortAscending ? query.OrderBy(locker => locker.IsLocked) : query.OrderByDescending(locker => locker.IsLocked),
                "Modified" => SortAscending ? query.OrderBy(locker => locker.LastModified) : query.OrderByDescending(locker => locker.LastModified),
                "Size" => SortAscending ? query.OrderBy(locker => locker.Size) : query.OrderByDescending(locker => locker.Size),
                "Location" => SortAscending ? query.OrderBy(locker => locker.Location) : query.OrderByDescending(locker => locker.Location),
                _ => SortAscending ? query.OrderBy(locker => locker.Name) : query.OrderByDescending(locker => locker.Name)
            };

            FilteredLockers = new ObservableCollection<LockerItemViewModel>(query);
            if (SelectedLocker != null && FilteredLockers.All(locker => locker.Guid != SelectedLocker.Guid))
            {
                SelectedLocker = null;
            }

            OnPropertyChanged(nameof(TotalLockers));
            OnPropertyChanged(nameof(LockedCount));
            OnPropertyChanged(nameof(UnlockedCount));
            NotifySelectionStateChanged();
        }

        private static LockerItemViewModel CreateLockerItem(LockerModel locker)
        {
            return new LockerItemViewModel
            {
                Guid = locker.Guid,
                Name = locker.LockerName,
                IsLocked = locker.IsLocked,
                Location = locker.LockerLocation,
                LastModified = Directory.Exists(locker.LockerLocation) ? Directory.GetLastWriteTime(locker.LockerLocation) : DateTime.MinValue,
                Size = CalculateDirectorySize(locker.LockerLocation)
            };
        }

        private static long CalculateDirectorySize(string path)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    return 0;
                }

                return new DirectoryInfo(path)
                    .EnumerateFiles("*", SearchOption.AllDirectories)
                    .Sum(file => file.Length);
            }
            catch
            {
                return 0;
            }
        }

        private LockerModel? FindLocker(LockerItemViewModel item)
        {
            return LockerService.FindLockerByGuid(item.Guid);
        }

        private async Task RunLockerOperationAsync(
            LockerItemViewModel item,
            string title,
            Func<LockerModel, Task> operation)
        {
            var locker = FindLocker(item);
            if (locker == null)
            {
                await _dialogs.ShowErrorAsync(title, "The selected locker was not found.");
                return;
            }

            await RunWithUiErrorAsync(title, $"Failed to update '{item.Name}'.", () => operation(locker));
        }

        private async Task RunWithUiErrorAsync(string title, string message, Func<Task> operation)
        {
            try
            {
                await operation();
            }
            catch (UnauthorizedAccessException ex)
            {
                if (ex.Message.Contains("Incorrect password", StringComparison.OrdinalIgnoreCase))
                {
                    await _dialogs.ShowWarningAsync(title, "Incorrect password.");
                    return;
                }

                await _dialogs.ShowErrorAsync(title, "Access denied.", ex);
            }
            catch (Exception ex)
            {
                await _dialogs.ShowErrorAsync(title, message, ex);
            }
        }

        private void NotifySelectionStateChanged()
        {
            OnPropertyChanged(nameof(SelectedCount));
            OnPropertyChanged(nameof(HasSelection));
            OnPropertyChanged(nameof(CanLockSelected));
            OnPropertyChanged(nameof(CanUnlockSelected));
            OnPropertyChanged(nameof(CanRemoveSelected));
            LockSelectedCommand.NotifyCanExecuteChanged();
            UnlockSelectedCommand.NotifyCanExecuteChanged();
            RemoveSelectedCommand.NotifyCanExecuteChanged();
            ShowPropertiesCommand.NotifyCanExecuteChanged();
            OpenLocationCommand.NotifyCanExecuteChanged();
        }

    }
}

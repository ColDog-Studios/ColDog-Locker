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
        private int _activeOperations;
        private readonly LockerSizeCache _sizeCache = new();
        private CancellationTokenSource? _refreshCancellation;
        private CancellationTokenSource? _lockerOperationCancellation;
        private readonly Func<CancellationToken, IProgress<string>, bool, Task<List<LockerItemViewModel>>> _loadLockerItems;
        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(CancelRefreshCommand))]
        private bool _isRefreshing;

        [ObservableProperty] private ObservableCollection<LockerItemViewModel> _filteredLockers = [];
        [ObservableProperty] private bool _isBusy;
        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(CancelLockerOperationCommand))]
        private bool _canCancelLockerOperation;
        [ObservableProperty] private bool _isLockerOperationRunning;
        [ObservableProperty] private int? _lockerOperationPercent;
        [ObservableProperty] private bool _isDeveloperMode;
        [ObservableProperty] private bool _isGridView = true;
        [ObservableProperty] private ObservableCollection<LockerItemViewModel> _lockers = [];
        [ObservableProperty] private string _searchText = string.Empty;
        [ObservableProperty] private LockerItemViewModel? _selectedLocker;
        [ObservableProperty] private bool _sortAscending = true;
        [ObservableProperty] private string _sortColumn = "Name";
        [ObservableProperty] private string _statusMessage = "Ready";

        public MainWindowViewModel(
            IUserDialogService dialogs,
            IPlatformService platformService,
            UpdateWorkflow updateWorkflow)
            : this(dialogs, platformService, updateWorkflow, null)
        {
        }

        internal MainWindowViewModel(IUserDialogService dialogs, IPlatformService platformService,
            UpdateWorkflow updateWorkflow, Func<CancellationToken, IProgress<string>, bool, Task<List<LockerItemViewModel>>>? loadLockerItems)
        {
            _loadLockerItems = loadLockerItems ?? LoadLockerItemsAsync;
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
        public bool CanLockSelected => !IsBusy && SelectedLocker is { IsLocked: false };
        public bool CanUnlockSelected => !IsBusy && SelectedLocker is { IsLocked: true };
        public bool CanRemoveSelected => !IsBusy && SelectedLocker is { IsLocked: false };
        public bool IsOperationProgressIndeterminate => LockerOperationPercent is null;
        public bool IsListView => !IsGridView;
        public MaterialIconKind ToggleViewIconKind => IsGridView ? MaterialIconKind.ViewList : MaterialIconKind.ViewGrid;
        public IReadOnlyList<string> SortColumns { get; } = ["Name", "Status", "Modified", "Size", "Location"];

        public async Task InitializeAsync(Func<Task> appInitialization)
        {
            ArgumentNullException.ThrowIfNull(appInitialization);

            await RunWithUiErrorAsync("Startup Error", "Failed to initialize ColDog Locker.", async () =>
            {
                StatusMessage = "Starting...";
                await appInitialization();
            });

            await RefreshAsync(false);
        }

        [RelayCommand(CanExecute = nameof(CanStartMutation))]
        private async Task CreateLockerAsync()
        {
            var request = await _dialogs.ShowNewLockerAsync();
            if (request == null)
            {
                return;
            }

            await RunWithUiErrorAsync("Create Locker Error", $"Failed to create locker '{request.LockerName}'.", async () =>
            {
                var passwordHash = await Task.Run(() => EncryptionHelper.HashPassword(request.Password));
                var locker = new LockerModel(
                    request.LockerName,
                    passwordHash,
                    request.Location);

                await Task.Run(() => LockerService.AddLocker(locker));

                AddOrReplaceLockerItem(await Task.Run(() => CreateLockerItem(locker)));
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

            await RunLockerOperationAsync(SelectedLocker, "Lock Error", async (locker, progress, cancellationToken) =>
            {
                await Task.Run(() => LockerService.Lock(locker, password, progress, cancellationToken));
                await RefreshAsync(false);
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

            await RunLockerOperationAsync(SelectedLocker, "Unlock Error", async (locker, progress, cancellationToken) =>
            {
                await Task.Run(() => LockerService.Unlock(locker, password, progress, cancellationToken));
                await RefreshAsync(false);
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

            await RunLockerOperationAsync(SelectedLocker, "Remove Error", async (locker, _, _) =>
            {
                await Task.Run(() => LockerService.RemoveLocker(locker));
                await RefreshAsync(false);
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
                await RefreshAsync(false);
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
            return RefreshAsync(true);
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

        partial void OnIsBusyChanged(bool value)
        {
            CreateLockerCommand.NotifyCanExecuteChanged();
            NotifySelectionStateChanged();
        }

        partial void OnLockerOperationPercentChanged(int? value)
        {
            OnPropertyChanged(nameof(IsOperationProgressIndeterminate));
        }

        [RelayCommand(CanExecute = nameof(IsRefreshing))]
        private void CancelRefresh() => _refreshCancellation?.Cancel();

        [RelayCommand(CanExecute = nameof(CanCancelLockerOperation))]
        private void CancelLockerOperation()
        {
            CanCancelLockerOperation = false;
            StatusMessage = "Cancellation requested. Waiting for a safe stopping point...";
            _lockerOperationCancellation?.Cancel();
        }

        private async Task RefreshAsync(bool showMessage)
        {
            _refreshCancellation?.Cancel();
            using var cancellation = new CancellationTokenSource();
            _refreshCancellation = cancellation;
            IsRefreshing = true;
            StatusMessage = "Refreshing lockers...";
            var scanning = true;
            var progress = new Progress<string>(message =>
            {
                if (scanning && ReferenceEquals(_refreshCancellation, cancellation) && !cancellation.IsCancellationRequested)
                {
                    StatusMessage = message;
                }
            });
            try
            {
                await RunWithUiErrorAsync("Refresh Error", "Failed to refresh lockers.", async () =>
                {
                    try
                    {
                        var items = await _loadLockerItems(cancellation.Token, progress, showMessage);
                        scanning = false;
                        cancellation.Token.ThrowIfCancellationRequested();
                        Lockers = new ObservableCollection<LockerItemViewModel>(items);
                        ApplyFilterAndSort();
                        StatusMessage = $"{TotalLockers} locker{(TotalLockers == 1 ? string.Empty : "s")} loaded";
                        if (showMessage)
                        {
                            await _dialogs.ShowMessageAsync("Refresh", StatusMessage);
                        }
                    }
                    catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
                    {
                        if (ReferenceEquals(_refreshCancellation, cancellation))
                        {
                            StatusMessage = "Refresh cancelled. The previous list is still displayed.";
                        }
                    }
                });
            }
            finally
            {
                scanning = false;
                if (ReferenceEquals(_refreshCancellation, cancellation))
                {
                    _refreshCancellation = null;
                    IsRefreshing = false;
                }
            }
        }

        private async Task<List<LockerItemViewModel>> LoadLockerItemsAsync(CancellationToken cancellationToken, IProgress<string> progress, bool forceSizeScan)
        {
            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                LockerService.LoadLockers();
                var snapshot = LockerService.GetLockersSnapshot();
                var items = new List<LockerItemViewModel>();
                foreach (var locker in snapshot)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    progress.Report($"Loading locker {items.Count + 1} of {snapshot.Count}: {locker.LockerName}");
                    items.Add(CreateLockerItem(locker, cancellationToken, forceSizeScan));
                }

                return items;
            }, cancellationToken);
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

        private LockerItemViewModel CreateLockerItem(LockerModel locker, CancellationToken cancellationToken = default, bool forceSizeScan = false)
        {
            return new LockerItemViewModel
            {
                Guid = locker.Guid,
                Name = locker.LockerName,
                IsLocked = locker.IsLocked,
                Location = locker.LockerLocation,
                LastModified = Directory.Exists(locker.LockerLocation) ? Directory.GetLastWriteTime(locker.LockerLocation) : DateTime.MinValue,
                Size = _sizeCache.GetSize(locker, forceSizeScan, cancellationToken)
            };
        }

        private LockerModel? FindLocker(LockerItemViewModel item)
        {
            return LockerService.FindLockerByGuid(item.Guid);
        }

        private async Task RunLockerOperationAsync(
            LockerItemViewModel item,
            string title,
            Func<LockerModel, IProgress<LockerOperationProgress>, CancellationToken, Task> operation)
        {
            var locker = FindLocker(item);
            if (locker == null)
            {
                await _dialogs.ShowErrorAsync(title, "The selected locker was not found.");
                return;
            }

            using var cancellation = new CancellationTokenSource();
            _lockerOperationCancellation = cancellation;
            IsLockerOperationRunning = true;
            LockerOperationPercent = null;
            var progress = new Progress<LockerOperationProgress>(update =>
            {
                if (!ReferenceEquals(_lockerOperationCancellation, cancellation))
                {
                    return;
                }

                CanCancelLockerOperation = update.CanCancel;
                LockerOperationPercent = update.Percent;
                StatusMessage = $"{update.Stage}: {update.Message}";
            });
            try
            {
                await RunWithUiErrorAsync(title, $"Failed to update '{item.Name}'.",
                    () => operation(locker, progress, cancellation.Token));
            }
            finally
            {
                if (ReferenceEquals(_lockerOperationCancellation, cancellation))
                {
                    _lockerOperationCancellation = null;
                    CanCancelLockerOperation = false;
                    IsLockerOperationRunning = false;
                    LockerOperationPercent = null;
                }
            }
        }

        public bool TryRequestClose()
        {
            if (_activeOperations == 0)
            {
                return true;
            }

            StatusMessage = "Work is still running. Wait for it to finish, then close the window.";
            return false;
        }

        private async Task RunWithUiErrorAsync(string title, string message, Func<Task> operation)
        {
            _activeOperations++;
            IsBusy = true;
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
            catch (OperationCanceledException)
            {
                StatusMessage = "Operation cancelled before publication. No source files were removed.";
            }
            catch (IOException ex) when (ex.Message.Contains("free space", StringComparison.OrdinalIgnoreCase))
            {
                await _dialogs.ShowErrorAsync(title, ex.Message, ex);
            }
            catch (Exception ex)
            {
                await _dialogs.ShowErrorAsync(title, message, ex);
            }
            finally
            {
                IsBusy = --_activeOperations > 0;
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

        private bool CanStartMutation() => !IsBusy;
    }
}

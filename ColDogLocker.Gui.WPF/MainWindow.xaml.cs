using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ColDogStudios.ColDogLocker.Gui.WPF.ViewModels;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;
using ColDogStudios.ColDogLocker.Gui.WPF.Models;
using ColDogStudios.ColDogLocker.Application.Services;

namespace ColDogStudios.ColDogLocker.Gui.WPF;

/// <summary>
/// Main window for ColDog Locker application
/// </summary>
public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private bool _isGridView = true;

    public MainWindow()
    {
        InitializeComponent();
        
        // Set window icon
        try
        {
            // Use pack URI for the window icon (taskbar)
            var iconUri = new Uri("pack://application:,,,/cdlIcon.ico", UriKind.Absolute);
            Icon = new System.Windows.Media.Imaging.BitmapImage(iconUri);
        }
        catch
        {
            // Fallback: try file system path
            try
            {
                var iconPath = System.IO.Path.Combine(AppContext.BaseDirectory, "cdlIcon.ico");
                if (System.IO.File.Exists(iconPath))
                {
                    Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(iconPath, UriKind.Absolute));
                }
            }
            catch { }
        }
        
        // Get ViewModel from service locator
        _viewModel = ServiceLocator.Instance.MainViewModel;
        DataContext = _viewModel;
        
        // Initialize UI state
        UpdateStatusBar();
        UpdateCommandStates();
        
        // Load lockers from database
        LoadLockers();
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

    #region Window Controls

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    #endregion

    private void LoadLockers()
    {
        try
        {
            // Clear existing lockers
            _viewModel.Lockers.Clear();

            // Load lockers from database via LockerService
            foreach (var locker in LockerService.Lockers)
            {
                _viewModel.Lockers.Add(new LockerViewModel
                {
                    Name = locker.LockerName,
                    IsLocked = locker.IsLocked,
                    Location = locker.LockerLocation,
                    LastModified = System.IO.Directory.Exists(locker.LockerLocation) 
                        ? System.IO.Directory.GetLastWriteTime(locker.LockerLocation) 
                        : DateTime.MinValue,
                    Size = CalculateDirectorySize(locker.LockerLocation),
                    Guid = locker.Guid
                });
            }

            // Update filtered list
            _viewModel.FilteredLockers = new ObservableCollection<LockerViewModel>(_viewModel.Lockers.OrderBy(l => l.Name));
            LockersGridView.ItemsSource = _viewModel.FilteredLockers;
            LockersListView.ItemsSource = _viewModel.FilteredLockers;
            
            UpdateStatusBar();
        }
        catch (Exception ex)
        {
            Dialogs.ErrorDialog.Show(
                "Failed to load lockers from database",
                ex,
                "Load Error",
                this);
        }
    }

    private long CalculateDirectorySize(string path)
    {
        try
        {
            if (!System.IO.Directory.Exists(path))
                return 0;

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

    private void NewLocker_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Dialogs.NewLockerDialog
        {
            Owner = this
        };

        if (dialog.ShowDialog() == true && dialog.Success)
        {
            try
            {
                // Create locker model with hashed password
                var lockerModel = new Core.Models.LockerModel(
                    dialog.LockerName,
                    Infrastructure.Encryption.EncryptionHelper.HashPassword(dialog.Password),
                    dialog.Location
                );

                // Add locker via service (creates directory and saves to database)
                LockerService.AddLocker(lockerModel);

                // Lock immediately if requested
                if (dialog.LockImmediately)
                {
                    LockerService.Lock(lockerModel, dialog.Password);
                }

                // Reload lockers to reflect changes
                LoadLockers();

                Dialogs.MessageDialog.ShowInformation(
                    $"Locker '{dialog.LockerName}' created successfully.",
                    "Success",
                    this);
            }
            catch (Exception ex)
            {
                Dialogs.ErrorDialog.Show(
                    $"Failed to create locker '{dialog.LockerName}'",
                    ex,
                    "Create Locker Error",
                    this);
            }
        }
    }

    private void Lock_Click(object sender, RoutedEventArgs e)
    {
        var selectedItems = GetSelectedLockers();
        if (selectedItems.Count == 0) return;

        foreach (var locker in selectedItems)
        {
            if (locker.IsLocked) continue;

            var passwordDialog = new Dialogs.PasswordDialog($"Lock {locker.Name}")
            {
                Owner = this
            };

            if (passwordDialog.ShowDialog() == true && passwordDialog.Success)
            {
                try
                {
                    // Find the locker model from LockerService
                    var lockerModel = LockerService.Lockers.FirstOrDefault(l => l.Guid == locker.Guid);
                    if (lockerModel != null)
                    {
                        LockerService.Lock(lockerModel, passwordDialog.Password);
                        locker.IsLocked = true;
                        Dialogs.MessageDialog.ShowInformation($"Locked: {locker.Name}", "Success", this);
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Dialogs.MessageDialog.ShowError("Incorrect password", "Lock Failed", this);
                }
                catch (Exception ex)
                {
                    Dialogs.ErrorDialog.Show($"Failed to lock '{locker.Name}'", ex, "Lock Error", this);
                }
            }
        }

        UpdateStatusBar();
    }

    private void Unlock_Click(object sender, RoutedEventArgs e)
    {
        var selectedItems = GetSelectedLockers();
        if (selectedItems.Count == 0) return;

        foreach (var locker in selectedItems)
        {
            if (!locker.IsLocked) continue;

            var passwordDialog = new Dialogs.PasswordDialog($"Unlock {locker.Name}")
            {
                Owner = this
            };

            if (passwordDialog.ShowDialog() == true && passwordDialog.Success)
            {
                try
                {
                    // Find the locker model from LockerService
                    var lockerModel = LockerService.Lockers.FirstOrDefault(l => l.Guid == locker.Guid);
                    if (lockerModel != null)
                    {
                        LockerService.Unlock(lockerModel, passwordDialog.Password);
                        locker.IsLocked = false;
                        locker.Location = lockerModel.LockerLocation; // Update location in case it changed
                        Dialogs.MessageDialog.ShowInformation($"Unlocked: {locker.Name}", "Success", this);
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Dialogs.MessageDialog.ShowError("Incorrect password", "Unlock Failed", this);
                }
                catch (Exception ex)
                {
                    Dialogs.ErrorDialog.Show($"Failed to unlock '{locker.Name}'", ex, "Unlock Error", this);
                }
            }
        }

        UpdateStatusBar();
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        var selectedItems = GetSelectedLockers();
        if (selectedItems.Count == 0) return;
        
        if (Dialogs.MessageDialog.ShowQuestion(
            $"Are you sure you want to remove {selectedItems.Count} locker(s)? This will remove them from the database but will NOT delete the files.", 
            "Confirm Remove",
            this))
        {
            try
            {
                foreach (var locker in selectedItems.ToList())
                {
                    var lockerModel = LockerService.Lockers.FirstOrDefault(l => l.Guid == locker.Guid);
                    if (lockerModel != null)
                    {
                        LockerService.RemoveLocker(lockerModel);
                    }
                }

                // Reload lockers
                LoadLockers();

                Dialogs.MessageDialog.ShowInformation(
                    $"{selectedItems.Count} locker(s) removed successfully.",
                    "Success",
                    this);
            }
            catch (Exception ex)
            {
                Dialogs.ErrorDialog.Show("Failed to remove lockers", ex, "Remove Error", this);
            }
        }
    }

    private void Properties_Click(object sender, RoutedEventArgs e)
    {
        var selectedItems = GetSelectedLockers();
        if (selectedItems.Count != 1) return;
        
        // Find the actual locker from LockerService
        var locker = LockerService.Lockers.FirstOrDefault(l => l.Guid == selectedItems[0].Guid);
        if (locker != null)
        {
            Dialogs.LockerPropertiesDialog.Show(locker, this);
            
            // Refresh the UI after properties dialog closes
            LoadLockers();
        }
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        var selectedItems = GetSelectedLockers();
        if (selectedItems.Count == 0) return;
        
        foreach (var locker in selectedItems)
        {
            try
            {
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{locker.Location}\"");
            }
            catch (Exception ex)
            {
                Dialogs.MessageDialog.ShowError($"Failed to open location: {ex.Message}", "Error", this);
            }
        }
    }

    private void ToggleView_Click(object sender, RoutedEventArgs e)
    {
        _isGridView = !_isGridView;
        
        if (_isGridView)
        {
            LockersGridView.Visibility = Visibility.Visible;
            LockersListViewContainer.Visibility = Visibility.Collapsed;
            //ViewToggleLabel.Text = "List View";
            ViewToggleIcon.Text = "\uE8FD"; // Grid icon
        }
        else
        {
            LockersGridView.Visibility = Visibility.Collapsed;
            LockersListViewContainer.Visibility = Visibility.Visible;
            //ViewToggleLabel.Text = "Grid View";
            ViewToggleIcon.Text = "\uE80A"; // List icon
        }
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            // Reload lockers from database
            LockerService.LoadLockers();
            
            // Refresh UI
            LoadLockers();
            
            Dialogs.MessageDialog.ShowInformation(
                $"Refreshed successfully. {_viewModel.Lockers.Count} locker(s) loaded.",
                "Refresh",
                this);
        }
        catch (Exception ex)
        {
            Dialogs.ErrorDialog.Show(
                "Failed to refresh lockers from database",
                ex,
                "Refresh Error",
                this);
        }
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Dialogs.SettingsDialog
        {
            Owner = this
        };

        if (dialog.ShowDialog() == true)
        {
            // Settings were saved, apply any necessary changes to the UI
            ApplySettings();
        }
    }

    private void CheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        // TODO: Check for updates
        Dialogs.MessageDialog.ShowInformation("Check for updates functionality will be implemented", "Check Updates", this);
    }

    private void Documentation_Click(object sender, RoutedEventArgs e)
    {
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

    private void About_Click(object sender, RoutedEventArgs e)
    {
        Dialogs.AboutDialog.Show(this);
    }

    private void TestErrorDialog_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            // Create a sample exception for testing
            throw new InvalidOperationException("This is a test exception to demonstrate the error dialog functionality.");
        }
        catch (Exception ex)
        {
            Dialogs.ErrorDialog.Show(
                "This is a test error message to verify the error dialog is working correctly. " +
                "The error dialog should display this message, the exception details, and a stack trace.",
                ex,
                "Test Error Dialog",
                this);
        }
    }

    private void Exit_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    #endregion

    #region Selection and Sorting

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        if (_isGridView)
        {
            LockersGridView.SelectAll();
        }
        else
        {
            LockersListView.SelectAll();
        }
    }

    private void DeselectAll_Click(object sender, RoutedEventArgs e)
    {
        if (_isGridView)
        {
            LockersGridView.UnselectAll();
        }
        else
        {
            LockersListView.UnselectAll();
        }
    }

    private void SelectAllToggle_Click(object sender, RoutedEventArgs e)
    {
        var selectedCount = GetSelectedLockers().Count;
        if (selectedCount == _viewModel.FilteredLockers.Count)
        {
            DeselectAll_Click(sender, e);
        }
        else
        {
            SelectAll_Click(sender, e);
        }
    }

    private void SelectAllCheckBox_Click(object sender, RoutedEventArgs e)
    {
        if (SelectAllCheckBox.IsChecked == true)
        {
            SelectAll_Click(sender, e);
        }
        else
        {
            DeselectAll_Click(sender, e);
        }
    }

    private void SortByName_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.SortColumn = "Name";
        _viewModel.SortAscending = !_viewModel.SortAscending;
    }

    private void SortByStatus_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.SortColumn = "Status";
        _viewModel.SortAscending = !_viewModel.SortAscending;
    }

    private void SortByLastModified_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.SortColumn = "LastModified";
        _viewModel.SortAscending = !_viewModel.SortAscending;
    }

    private void SortBySize_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.SortColumn = "Size";
        _viewModel.SortAscending = !_viewModel.SortAscending;
    }

    private void SortByLocation_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.SortColumn = "Location";
        _viewModel.SortAscending = !_viewModel.SortAscending;
    }

    #endregion

    #region UI Updates

    private void LockersView_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var selectedLockers = new ObservableCollection<LockerViewModel>(GetSelectedLockers());
        _viewModel.UpdateSelection(selectedLockers);
        UpdateStatusBar();
        UpdateCommandStates();
    }

    private void LockerItem_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        var selected = GetSelectedLockers();
        if (selected.Count == 1)
        {
            var locker = selected[0];
            if (locker.IsLocked)
            {
                Unlock_Click(sender, new RoutedEventArgs());
            }
            else
            {
                Lock_Click(sender, new RoutedEventArgs());
            }
        }
    }

    private void UpdateStatusBar()
    {
        TotalLockersText.Text = $"{_viewModel.TotalLockers} locker{(_viewModel.TotalLockers != 1 ? "s" : "")}";
        LockedCountText.Text = $"{_viewModel.LockedCount} locked";
        UnlockedCountText.Text = $"{_viewModel.UnlockedCount} unlocked";
        SelectedCountText.Text = $"{_viewModel.SelectedCount} selected";
    }

    private void UpdateCommandStates()
    {
        var hasSelection = _viewModel.SelectedCount > 0;
        
        LockButton.IsEnabled = hasSelection;
        UnlockButton.IsEnabled = hasSelection;
        RemoveButton.IsEnabled = hasSelection;
        
        LockMenuItem.IsEnabled = hasSelection;
        UnlockMenuItem.IsEnabled = hasSelection;
        RemoveMenuItem.IsEnabled = hasSelection;
        PropertiesMenuItem.IsEnabled = _viewModel.SelectedCount == 1;
        OpenLocationMenuItem.IsEnabled = hasSelection;
    }

    private ObservableCollection<LockerViewModel> GetSelectedLockers()
    {
        if (_isGridView)
        {
            return new ObservableCollection<LockerViewModel>(
                LockersGridView.SelectedItems.Cast<LockerViewModel>());
        }
        else
        {
            return new ObservableCollection<LockerViewModel>(
                LockersListView.SelectedItems.Cast<LockerViewModel>());
        }
    }

    private void ApplySettings()
    {
        // Apply settings that affect the UI immediately
        var settings = Properties.Settings.Default;

        // Apply toolbar visibility
        if (MainToolBar != null)
        {
            MainToolBar.Visibility = settings.ShowToolBar ? Visibility.Visible : Visibility.Collapsed;
        }

        // Apply default view if no lockers yet or on fresh start
        // Theme is already applied by the SettingsDialog via ThemeService
    }

    #endregion

    private void MenuItem_Click(object sender, RoutedEventArgs e)
    {

    }
}

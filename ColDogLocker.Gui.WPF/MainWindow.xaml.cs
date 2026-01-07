using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ColDogStudios.ColDogLocker.Gui.WPF.ViewModels;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;
using ColDogStudios.ColDogLocker.Gui.WPF.Models;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;

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
            var iconPath = System.IO.Path.Combine(AppContext.BaseDirectory, "cdlIcon.ico");
            if (System.IO.File.Exists(iconPath))
            {
                Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(iconPath, UriKind.Absolute));
            }
        }
        catch { }
        
        // Get ViewModel from service locator
        _viewModel = ServiceLocator.Instance.MainViewModel;
        DataContext = _viewModel;
        
        // Initialize UI state
        UpdateStatusBar();
        UpdateCommandStates();
        
        // TODO: Load lockers from service
        LoadSampleData();
    }

    private void LoadSampleData()
    {
        // Sample data for testing - will be replaced with actual service calls
        _viewModel.Lockers.Add(new LockerViewModel
        {
            Name = "Personal Documents",
            IsLocked = true,
            Location = @"C:\Users\Documents\ColDog Locker\Personal Documents",
            LastModified = DateTime.Now.AddDays(-2),
            Size = 1024 * 1024 * 150 // 150 MB
        });
        
        _viewModel.Lockers.Add(new LockerViewModel
        {
            Name = "Work Files",
            IsLocked = false,
            Location = @"C:\Users\Documents\ColDog Locker\Work Files",
            LastModified = DateTime.Now.AddHours(-5),
            Size = 1024 * 1024 * 250 // 250 MB
        });
        
        _viewModel.Lockers.Add(new LockerViewModel
        {
            Name = "Photos",
            IsLocked = true,
            Location = @"C:\Users\Documents\ColDog Locker\Photos",
            LastModified = DateTime.Now.AddDays(-10),
            Size = 1024L * 1024L * 1024L * 2 // 2 GB
        });

        // Update filtered list
        _viewModel.FilteredLockers = new ObservableCollection<LockerViewModel>(_viewModel.Lockers.OrderBy(l => l.Name));
        LockersGridView.ItemsSource = _viewModel.FilteredLockers;
        LockersListView.ItemsSource = _viewModel.FilteredLockers;
        
        UpdateStatusBar();
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
            var newLocker = new LockerViewModel
            {
                Name = dialog.LockerName,
                Location = dialog.Location,
                IsLocked = dialog.LockImmediately,
                LastModified = DateTime.Now,
                Size = 0
            };

            _viewModel.Lockers.Add(newLocker);
            _viewModel.FilteredLockers = new ObservableCollection<LockerViewModel>(_viewModel.Lockers.OrderBy(l => l.Name));
            
            if (_isGridView)
            {
                LockersGridView.ItemsSource = _viewModel.FilteredLockers;
            }
            else
            {
                LockersListView.ItemsSource = _viewModel.FilteredLockers;
            }
            
            UpdateStatusBar();
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
                // TODO: Actually lock the locker with LockerService
                locker.IsLocked = true;
                MessageBox.Show($"Locked: {locker.Name}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
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
                // TODO: Actually unlock the locker with LockerService
                locker.IsLocked = false;
                MessageBox.Show($"Unlocked: {locker.Name}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        UpdateStatusBar();
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        var selectedItems = GetSelectedLockers();
        if (selectedItems.Count == 0) return;
        
        var result = MessageBox.Show(
            $"Are you sure you want to remove {selectedItems.Count} locker(s)?", 
            "Confirm Remove", 
            MessageBoxButton.YesNo, 
            MessageBoxImage.Warning);
        
        if (result == MessageBoxResult.Yes)
        {
            // TODO: Remove selected lockers
            MessageBox.Show("Remove functionality will be implemented", "Remove", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void Properties_Click(object sender, RoutedEventArgs e)
    {
        var selectedItems = GetSelectedLockers();
        if (selectedItems.Count != 1) return;
        
        // TODO: Show properties dialog
        MessageBox.Show($"Properties for {selectedItems[0].Name}", "Properties", MessageBoxButton.OK, MessageBoxImage.Information);
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
                MessageBox.Show($"Failed to open location: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
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
            ViewToggleLabel.Text = "List View";
            ViewToggleIcon.Text = "\uE8FD"; // Grid icon
        }
        else
        {
            LockersGridView.Visibility = Visibility.Collapsed;
            LockersListViewContainer.Visibility = Visibility.Visible;
            ViewToggleLabel.Text = "Grid View";
            ViewToggleIcon.Text = "\uE80A"; // List icon
        }
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        // TODO: Reload lockers from service
        MessageBox.Show("Refresh functionality will be implemented", "Refresh", MessageBoxButton.OK, MessageBoxImage.Information);
        UpdateStatusBar();
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
        MessageBox.Show("Check for updates functionality will be implemented", "Check Updates", MessageBoxButton.OK, MessageBoxImage.Information);
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
        // TODO: Show about dialog
        MessageBox.Show("ColDog Locker\nVersion 1.0.0\n© ColDog Studios", "About", MessageBoxButton.OK, MessageBoxImage.Information);
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

        // Apply status bar visibility
        if (MainStatusBar != null)
        {
            MainStatusBar.Visibility = settings.ShowStatusBar ? Visibility.Visible : Visibility.Collapsed;
        }

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

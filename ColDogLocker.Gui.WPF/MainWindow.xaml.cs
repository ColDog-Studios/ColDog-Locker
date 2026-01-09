using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using ColDogStudios.ColDogLocker.Application.Services;
using ColDogStudios.ColDogLocker.Gui.WPF.Models;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;
using ColDogStudios.ColDogLocker.Gui.WPF.ViewModels;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;

namespace ColDogStudios.ColDogLocker.Gui.WPF
{
    /// <summary>
    /// Main window for ColDog Locker application
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _viewModel;
        private bool _isGridView = true;
        private string _currentSortColumn = "";
        private bool _currentSortAscending = true;
        private bool _listViewInitialized = false;

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

            // Don't initialize list view columns here since the view is not visible yet
            // It will be initialized when the user switches to list view
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

                // Update filtered list - don't create new collection, reuse existing one
                var sortedLockers = _viewModel.Lockers.OrderBy(l => l.Name).ToList();
                _viewModel.FilteredLockers.Clear();
                foreach (var locker in sortedLockers)
                {
                    _viewModel.FilteredLockers.Add(locker);
                }

                // Set ItemsSource only if not already set
                if (LockersGridView.ItemsSource == null)
                {
                    LockersGridView.ItemsSource = _viewModel.FilteredLockers;
                }

                if (LockersListView.ItemsSource == null)
                {
                    LockersListView.ItemsSource = _viewModel.FilteredLockers;
                }

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
            if (selectedItems.Count == 0)
            {
                return;
            }

            foreach (var locker in selectedItems)
            {
                if (locker.IsLocked)
                {
                    continue;
                }

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
            if (selectedItems.Count == 0)
            {
                return;
            }

            foreach (var locker in selectedItems)
            {
                if (!locker.IsLocked)
                {
                    continue;
                }

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
            if (selectedItems.Count == 0)
            {
                return;
            }

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
            if (selectedItems.Count != 1)
            {
                return;
            }

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
            if (selectedItems.Count == 0)
            {
                return;
            }

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
                ViewToggleIcon.Text = "\uf2c7"; // List icon
            }
            else
            {
                LockersGridView.Visibility = Visibility.Collapsed;
                LockersListViewContainer.Visibility = Visibility.Visible;
                //ViewToggleLabel.Text = "Grid View";
                ViewToggleIcon.Text = "\uE8A9"; // Grid icon

                // Initialize list view columns when first shown
                if (!_listViewInitialized)
                {
                    // Defer initialization to allow visual tree to be constructed
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        InitializeListViewColumns();
                        _listViewInitialized = true;
                    }), System.Windows.Threading.DispatcherPriority.Loaded);
                }
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

        private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = await Task.Run(() => UpdateManager.CheckForUpdatesAsync());

                if (result.UpdateAvailable)
                {
                    var message = $"A new version is available!\n\n" +
                                 $"Current Version: {result.CurrentVersion}\n" +
                                 $"Latest Version: {result.LatestVersion}\n\n" +
                                 "Would you like to download and install it now?";

                    if (Dialogs.MessageDialog.ShowQuestion(message, "Update Available", this))
                    {
                        try
                        {
                            var filePath = await Task.Run(() => UpdateManager.DownloadUpdateAsync(result));
                            Dialogs.MessageDialog.ShowInformation(
                                $"Update downloaded successfully to:\n{filePath}\n\nPlease run the installer to complete the update.",
                                "Download Complete",
                                this);
                        }
                        catch (Exception downloadEx)
                        {
                            var errorDialog = new Dialogs.ErrorDialog(
                                $"Failed to download update: {downloadEx.Message}",
                                downloadEx,
                                "Download Failed")
                            {
                                Owner = this
                            };
                            errorDialog.ShowDialog();
                        }
                    }
                }
                else
                {
                    var message = $"ColDog Locker is up to date.\n\n" +
                                 $"Current Version: {result.CurrentVersion}\n" +
                                 $"Latest Version: {result.LatestVersion}";
                    Dialogs.MessageDialog.ShowInformation(message, "No Updates Available", this);
                }
            }
            catch (Exception ex)
            {
                var errorDialog = new Dialogs.ErrorDialog(
                    $"Failed to check for updates: {ex.Message}",
                    ex,
                    "Update Check Failed")
                {
                    Owner = this
                };
                errorDialog.ShowDialog();
            }
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
            // Find the actual CheckBox in the header template
            var checkBox = sender as CheckBox;
            if (checkBox != null)
            {
                if (checkBox.IsChecked == true)
                {
                    SelectAll_Click(sender, e);
                }
                else
                {
                    DeselectAll_Click(sender, e);
                }
            }
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
            var settings = SettingsManager.Settings;

            // Theme is already applied by the SettingsDialog via ThemeService
        }

        #endregion

        #region List View Column Management

        /// <summary>
        /// Initialize column resizing and auto-sizing
        /// </summary>
        private void InitializeListViewColumns()
        {
            try
            {
                if (LockersListView == null || LockersGridViewColumns == null)
                {
                    return;
                }

                // Make sure the list view is visible and loaded
                if (LockersListView.Visibility != Visibility.Visible || !LockersListView.IsLoaded)
                {
                    return;
                }

                // Attach thumb drag events for resizing
                foreach (var column in LockersGridViewColumns.Columns)
                {
                    if (column.HeaderContainerStyle?.GetType().Name == "CheckboxColumnHeaderStyle")
                    {
                        continue; // Skip checkbox column
                    }

                    // Find the header container
                    var header = FindColumnHeader(column);
                    if (header != null)
                    {
                        AttachColumnResizeHandlers(header, column);
                    }
                }

                // Auto-size columns on first load
                AutoSizeAllColumns();
            }
            catch (Exception ex)
            {
                // Log error but don't crash
                System.Diagnostics.Debug.WriteLine($"Error initializing list view columns: {ex.Message}");
            }
        }

        /// <summary>
        /// Find the GridViewColumnHeader for a column
        /// </summary>
        private GridViewColumnHeader? FindColumnHeader(GridViewColumn column)
        {
            // Find the header in the visual tree
            return FindVisualChild<GridViewColumnHeader>(LockersListView, h => h.Column == column);
        }

        /// <summary>
        /// Attach resize handlers to column header
        /// </summary>
        private void AttachColumnResizeHandlers(GridViewColumnHeader header, GridViewColumn column)
        {
            // Find the thumb (gripper) in the header template
            var thumb = FindVisualChild<Thumb>(header, t => t.Name == "PART_HeaderGripper");
            if (thumb != null)
            {
                // Handle drag for manual resizing
                thumb.DragDelta += (s, e) => OnColumnResize(column, e.HorizontalChange);

                // Handle double-click for auto-sizing
                thumb.MouseDoubleClick += (s, e) => AutoSizeColumn(column);
            }
        }

        /// <summary>
        /// Handle column resize via drag
        /// </summary>
        private void OnColumnResize(GridViewColumn column, double widthChange)
        {
            var newWidth = column.Width + widthChange;
            if (newWidth >= 20) // Minimum column width
            {
                column.Width = newWidth;
            }
        }

        /// <summary>
        /// Auto-size a specific column to fit content
        /// </summary>
        private void AutoSizeColumn(GridViewColumn column)
        {
            try
            {
                if (column == null || _viewModel?.FilteredLockers == null || _viewModel.FilteredLockers.Count == 0)
                {
                    // Set a reasonable default width if no data
                    if (column != null)
                    {
                        column.Width = 100;
                    }

                    return;
                }

                double maxWidth = 50; // Minimum width

                // Get column header text width
                var header = FindColumnHeader(column);
                if (header != null)
                {
                    var headerWidth = MeasureString(header.Content?.ToString() ?? "", header);
                    maxWidth = Math.Max(maxWidth, headerWidth + 40); // Add padding for sort arrow and margins
                }

                // Measure content width
                foreach (var locker in _viewModel.FilteredLockers)
                {
                    string text = GetColumnValueAsString(locker, column);
                    double contentWidth = MeasureString(text, LockersListView) + 20; // Add padding
                    maxWidth = Math.Max(maxWidth, contentWidth);
                }

                // Set the new width
                column.Width = Math.Min(maxWidth, 500); // Max width cap
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error auto-sizing column: {ex.Message}");
            }
        }

        /// <summary>
        /// Auto-size all columns except Location (which fits to window)
        /// </summary>
        private void AutoSizeAllColumns()
        {
            if (LockersGridViewColumns == null)
            {
                return;
            }

            // Auto-size all columns except checkbox and location
            if (NameColumn != null)
            {
                AutoSizeColumn(NameColumn);
            }

            if (StatusColumn != null)
            {
                AutoSizeColumn(StatusColumn);
            }

            if (LastModifiedColumn != null)
            {
                AutoSizeColumn(LastModifiedColumn);
            }

            if (SizeColumn != null)
            {
                AutoSizeColumn(SizeColumn);
            }

            // Calculate remaining width for Location column
            SetLocationColumnWidth();
        }

        /// <summary>
        /// Set Location column width to fill remaining space
        /// </summary>
        private void SetLocationColumnWidth()
        {
            if (LocationColumn == null || LockersListView == null)
            {
                return;
            }

            // Calculate total width of other columns
            double otherColumnsWidth = 0;
            foreach (var column in LockersGridViewColumns.Columns)
            {
                if (column != LocationColumn)
                {
                    otherColumnsWidth += column.Width;
                }
            }

            // Calculate available width (account for scrollbar)
            double availableWidth = LockersListView.ActualWidth - otherColumnsWidth - 20;

            // Set location column width (minimum 200)
            LocationColumn.Width = Math.Max(200, availableWidth);
        }

        /// <summary>
        /// Get the value for a column as a string
        /// </summary>
        private string GetColumnValueAsString(LockerViewModel locker, GridViewColumn column)
        {
            if (column == NameColumn)
            {
                return locker.Name ?? "";
            }
            else if (column == StatusColumn)
            {
                return locker.IsLocked ? "Locked" : "Unlocked";
            }
            else if (column == LastModifiedColumn)
            {
                return locker.LastModified.ToString("MM/dd/yyyy hh:mm:ss tt");
            }
            else if (column == SizeColumn)
            {
                return locker.SizeText ?? "";
            }
            else if (column == LocationColumn)
            {
                return locker.Location ?? "";
            }

            return "";
        }

        /// <summary>
        /// Measure string width for auto-sizing
        /// </summary>
        private double MeasureString(string text, FrameworkElement element)
        {
            // Try to get font properties from Control, otherwise use defaults
            var fontFamily = (element as Control)?.FontFamily ?? new System.Windows.Media.FontFamily("Segoe UI");
            var fontSize = (element as Control)?.FontSize ?? 12;
            var fontStyle = (element as Control)?.FontStyle ?? FontStyles.Normal;
            var fontWeight = (element as Control)?.FontWeight ?? FontWeights.Normal;
            var fontStretch = (element as Control)?.FontStretch ?? FontStretches.Normal;

            var formattedText = new FormattedText(
                text,
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface(fontFamily, fontStyle, fontWeight, fontStretch),
                fontSize,
                Brushes.Black,
                VisualTreeHelper.GetDpi(element).PixelsPerDip);

            return formattedText.Width;
        }

        /// <summary>
        /// Find a visual child in the tree with optional predicate
        /// </summary>
        private T? FindVisualChild<T>(DependencyObject? parent, Func<T, bool>? predicate = null) where T : DependencyObject
        {
            if (parent == null)
            {
                return null;
            }

            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);

                if (child is T tChild && (predicate == null || predicate(tChild)))
                {
                    return tChild;
                }

                var result = FindVisualChild(child, predicate);
                if (result != null)
                {
                    return result;
                }
            }

            return null;
        }

        /// <summary>
        /// Handle column header click for sorting
        /// </summary>
        private void ColumnHeader_Click(object sender, RoutedEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine($"ColumnHeader_Click called - sender: {sender?.GetType().Name}");

            if (sender is GridViewColumnHeader header && header.Tag is string columnName)
            {
                System.Diagnostics.Debug.WriteLine($"Sorting by column: {columnName}, Current: {_currentSortColumn}, Ascending: {_currentSortAscending}");

                // Toggle sort direction if clicking the same column
                if (_currentSortColumn == columnName)
                {
                    _currentSortAscending = !_currentSortAscending;
                }
                else
                {
                    _currentSortColumn = columnName;
                    _currentSortAscending = true;
                }

                System.Diagnostics.Debug.WriteLine($"New sort: {_currentSortColumn} {(_currentSortAscending ? "ASC" : "DESC")}");

                // Apply sort
                SortLockers(columnName, _currentSortAscending);

                // Update sort indicators
                UpdateSortIndicators(header);
            }
            else
            {
                System.Diagnostics.Debug.WriteLine($"Header or Tag is null - Header: {sender is GridViewColumnHeader}, Tag: {(sender as GridViewColumnHeader)?.Tag}");
            }
        }

        /// <summary>
        /// Sort lockers by column
        /// </summary>
        private void SortLockers(string columnName, bool ascending)
        {
            try
            {
                if (_viewModel.FilteredLockers == null || _viewModel.FilteredLockers.Count == 0)
                {
                    return;
                }

                // Create a copy of the collection to sort
                var items = _viewModel.FilteredLockers.ToArray();

                IEnumerable<LockerViewModel> sorted = columnName switch
                {
                    "Name" => ascending
                        ? items.OrderBy(l => l.Name)
                        : items.OrderByDescending(l => l.Name),
                    "Status" => ascending
                        ? items.OrderBy(l => l.IsLocked)
                        : items.OrderByDescending(l => l.IsLocked),
                    "LastModified" => ascending
                        ? items.OrderBy(l => l.LastModified)
                        : items.OrderByDescending(l => l.LastModified),
                    "Size" => ascending
                        ? items.OrderBy(l => l.Size)
                        : items.OrderByDescending(l => l.Size),
                    "Location" => ascending
                        ? items.OrderBy(l => l.Location)
                        : items.OrderByDescending(l => l.Location),
                    _ => items
                };

                // Update the collection
                var sortedList = sorted.ToList();
                _viewModel.FilteredLockers.Clear();
                foreach (var locker in sortedList)
                {
                    _viewModel.FilteredLockers.Add(locker);
                }

                // Also update ViewModel sort properties
                _viewModel.SortColumn = columnName;
                _viewModel.SortAscending = ascending;

                System.Diagnostics.Debug.WriteLine($"Sorted by {columnName} {(ascending ? "ascending" : "descending")} - {sortedList.Count} items");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error sorting lockers: {ex.Message}");
            }
        }

        /// <summary>
        /// Update sort indicator arrows in column headers
        /// </summary>
        private void UpdateSortIndicators(GridViewColumnHeader clickedHeader)
        {
            // Find all column headers and update sort arrows
            foreach (var column in LockersGridViewColumns.Columns)
            {
                var header = FindColumnHeader(column);
                if (header != null)
                {
                    // Find the sort arrow TextBlock in the template
                    var sortArrow = FindVisualChild<TextBlock>(header, t => t.Name == "SortArrow");
                    if (sortArrow != null)
                    {
                        if (header == clickedHeader)
                        {
                            // Show arrow for sorted column
                            sortArrow.Visibility = Visibility.Visible;
                            sortArrow.Text = _currentSortAscending ? "\uE70E" : "\uE70D"; // Up/Down arrows
                        }
                        else
                        {
                            // Hide arrow for other columns
                            sortArrow.Visibility = Visibility.Collapsed;
                        }
                    }
                }
            }
        }

        #endregion

        private void MenuItem_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}

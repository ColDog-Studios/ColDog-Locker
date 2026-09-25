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

using System.Security;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;
using Material.Icons;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class LockerPropertiesDialog : Window
    {
        private static readonly IBrush _lockedBrush = new ImmutableSolidColorBrush(Color.Parse("#FF6923"));
        private static readonly IBrush _unlockedBrush = new ImmutableSolidColorBrush(Color.Parse("#0077B6"));

        private readonly LockerModel? _locker;
        private bool _hasChanges;
        private readonly CancellationTokenSource _scanCancellation = new();
        internal Task MetadataLoadTask { get; private set; } = Task.CompletedTask;

        public LockerPropertiesDialog()
        {
            InitializeComponent();

            BrowseButton.IsEnabled = false;
            SaveButton.IsEnabled = false;
            StatusIcon.Kind = MaterialIconKind.LockOpen;
            StatusIcon.Foreground = _unlockedBrush;
            StatusText.Text = "Unlocked";
            StatusText.Foreground = _unlockedBrush;

            NameBox.TextChanged += (_, _) => UpdateChangeState();
            BrowseButton.Click += BrowseButton_Click;
            SaveButton.Click += SaveButton_Click;
            CloseButton.Click += CloseButton_Click;
            Opened += (_, _) => MetadataLoadTask = LoadMetadataAsync();
            Closed += (_, _) =>
            {
                _scanCancellation.Cancel();
                _scanCancellation.Dispose();
            };
        }

        public LockerPropertiesDialog(LockerModel locker)
            : this()
        {
            _locker = locker;

            NameBox.Text = locker.LockerName;
            NameBox.IsReadOnly = locker.IsLocked;
            LocationBox.Text = locker.LockerLocation;
            BrowseButton.IsEnabled = !locker.IsLocked;
            LocationWarningText.IsVisible = locker.IsLocked;
            SizeText.Text = "Calculating...";
            CreatedText.Text = "Loading...";
            ModifiedText.Text = "Loading...";

            var statusBrush = locker.IsLocked ? _lockedBrush : _unlockedBrush;
            StatusIcon.Kind = locker.IsLocked ? MaterialIconKind.Lock : MaterialIconKind.LockOpen;
            StatusIcon.Foreground = statusBrush;
            StatusText.Text = locker.IsLocked ? "Locked" : "Unlocked";
            StatusText.Foreground = statusBrush;
            _hasChanges = false;
            SaveButton.IsEnabled = false;
        }

        private async void BrowseButton_Click(object? sender, RoutedEventArgs e)
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Select new location for locker",
                AllowMultiple = false
            });

            var folder = folders.FirstOrDefault();
            if (folder == null)
            {
                return;
            }

            var selectedPath = folder.TryGetLocalPath() ?? folder.Path.LocalPath;
            LocationBox.Text = selectedPath;

            var selectedName = GetFolderName(selectedPath);
            if (!string.IsNullOrWhiteSpace(selectedName))
            {
                NameBox.Text = selectedName;
            }

            UpdateChangeState();
        }

        private async void SaveButton_Click(object? sender, RoutedEventArgs e)
        {
            if (_locker == null)
            {
                return;
            }

            var newName = NameBox.Text?.Trim() ?? string.Empty;
            var newLocation = LocationBox.Text?.Trim() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(newName))
            {
                await new MessageDialog("Invalid Name", "Locker name cannot be empty.", MessageDialogKind.Warning)
                    .ShowDialog<object?>(this);
                return;
            }

            if (string.IsNullOrWhiteSpace(newLocation))
            {
                await new MessageDialog("Invalid Location", "Locker location cannot be empty.", MessageDialogKind.Warning)
                    .ShowDialog<object?>(this);
                return;
            }

            try
            {
                var locationToSave = _locker.IsLocked ? _locker.LockerLocation : newLocation;
                LockerService.UpdateLockerMetadata(_locker, newName, locationToSave);

                _hasChanges = false;
                SaveButton.IsEnabled = false;
                await new MessageDialog("Locker Properties", "Locker properties saved successfully.", MessageDialogKind.Information)
                    .ShowDialog<object?>(this);
                Close(true);
            }
            catch (ArgumentException ex)
            {
                await new MessageDialog("Error", $"Failed to save locker properties: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
            catch (UnauthorizedAccessException ex)
            {
                await new MessageDialog("Error", $"Failed to save locker properties: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
            catch (InvalidOperationException ex)
            {
                await new MessageDialog("Error", $"Failed to save locker properties: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
            catch (IOException ex)
            {
                await new MessageDialog("Error", $"Failed to save locker properties: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
        }

        private async void CloseButton_Click(object? sender, RoutedEventArgs e)
        {
            if (_hasChanges)
            {
                var confirmed = await new MessageDialog(
                        "Unsaved Changes",
                        "You have unsaved changes. Are you sure you want to close?",
                        MessageDialogKind.Confirmation)
                    .ShowDialog<bool>(this);

                if (!confirmed)
                {
                    return;
                }
            }

            Close(false);
        }

        private void UpdateChangeState()
        {
            if (_locker == null)
            {
                SaveButton.IsEnabled = false;
                return;
            }

            _hasChanges =
                !string.Equals(NameBox.Text?.Trim(), _locker.LockerName, StringComparison.Ordinal) ||
                (!_locker.IsLocked && !string.Equals(LocationBox.Text?.Trim(), _locker.LockerLocation, StringComparison.Ordinal));
            SaveButton.IsEnabled = _hasChanges;
        }

        private static string GetDirectoryDate(string path, DateKind dateKind)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    return "Directory not found";
                }

                var info = new DirectoryInfo(path);
                var value = dateKind == DateKind.Created ? info.CreationTime : info.LastWriteTime;
                return value.ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch (IOException)
            {
                return "Unable to retrieve";
            }
            catch (UnauthorizedAccessException)
            {
                return "Unable to retrieve";
            }
            catch (SecurityException)
            {
                return "Unable to retrieve";
            }
        }

        private async Task LoadMetadataAsync()
        {
            if (_locker == null)
            {
                return;
            }

            var token = _scanCancellation.Token;
            var path = _locker.LockerLocation;
            try
            {
                var metadata = await Task.Run(() =>
                {
                    var size = DirectorySizeScanner.Calculate(path, token);
                    token.ThrowIfCancellationRequested();
                    return (Size: size, Created: GetDirectoryDate(path, DateKind.Created), Modified: GetDirectoryDate(path, DateKind.Modified));
                }, token);
                if (!token.IsCancellationRequested)
                {
                    SizeText.Text = metadata.Size is { } bytes ? FormatBytes(bytes) : "Unknown";
                    CreatedText.Text = metadata.Created;
                    ModifiedText.Text = metadata.Modified;
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                // Closing the dialog cancels display-only work, not a locker operation.
            }
        }

        private static string FormatBytes(long bytes)
        {
            string[] sizes = ["B", "KB", "MB", "GB", "TB"];
            double value = bytes;
            var order = 0;
            while (value >= 1024 && order < sizes.Length - 1)
            {
                value /= 1024;
                order++;
            }

            return $"{value:0.##} {sizes[order]}";
        }

        private static string GetFolderName(string path)
        {
            var trimmedPath = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return Path.GetFileName(trimmedPath);
        }

        private enum DateKind
        {
            Created,
            Modified
        }
    }
}

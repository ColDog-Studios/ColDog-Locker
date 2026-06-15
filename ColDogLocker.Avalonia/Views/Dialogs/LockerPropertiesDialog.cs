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

using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;
using Material.Icons;
using System.IO;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class LockerPropertiesDialog : Window
    {
        private static readonly IBrush LockedBrush = new SolidColorBrush(Color.Parse("#FF6923"));
        private static readonly IBrush UnlockedBrush = new SolidColorBrush(Color.Parse("#0077B6"));

        private LockerModel? _locker;
        private bool _hasChanges;

        public LockerPropertiesDialog()
        {
            InitializeComponent();

            BrowseButton.IsEnabled = false;
            SaveButton.IsEnabled = false;
            StatusIcon.Kind = MaterialIconKind.LockOpen;
            StatusIcon.Foreground = UnlockedBrush;
            StatusText.Text = "Unlocked";
            StatusText.Foreground = UnlockedBrush;

            NameBox.TextChanged += (_, _) => UpdateChangeState();
            BrowseButton.Click += BrowseButton_Click;
            SaveButton.Click += SaveButton_Click;
            CloseButton.Click += CloseButton_Click;
        }

        public LockerPropertiesDialog(LockerModel locker)
            : this()
        {
            _locker = locker;

            NameBox.Text = locker.LockerName;
            LocationBox.Text = locker.LockerLocation;
            BrowseButton.IsEnabled = !locker.IsLocked;
            LocationWarningText.IsVisible = locker.IsLocked;
            SizeText.Text = GetSizeText(locker.LockerLocation);
            CreatedText.Text = GetDirectoryDate(locker.LockerLocation, dateKind: DateKind.Created);
            ModifiedText.Text = GetDirectoryDate(locker.LockerLocation, dateKind: DateKind.Modified);

            var statusBrush = locker.IsLocked ? LockedBrush : UnlockedBrush;
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
            catch (System.Security.SecurityException)
            {
                return "Unable to retrieve";
            }
        }

        private static string GetSizeText(string path)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    return "Directory not found";
                }

                return FormatBytes(CalculateDirectorySize(new DirectoryInfo(path)));
            }
            catch (UnauthorizedAccessException)
            {
                return "Unable to calculate";
            }
            catch (IOException)
            {
                return "Unable to calculate";
            }
            catch (System.Security.SecurityException)
            {
                return "Unable to calculate";
            }
        }

        private static long CalculateDirectorySize(DirectoryInfo directory)
        {
            long size = 0;
            try
            {
                foreach (var file in directory.EnumerateFiles())
                {
                    size += file.Length;
                }

                foreach (var child in directory.EnumerateDirectories())
                {
                    size += CalculateDirectorySize(child);
                }
            }
            catch (UnauthorizedAccessException)
            {
                return size;
            }
            catch (IOException)
            {
                return size;
            }
            catch (System.Security.SecurityException)
            {
                return size;
            }

            return size;
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

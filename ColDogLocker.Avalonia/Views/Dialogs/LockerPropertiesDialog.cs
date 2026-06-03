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
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;
using System.IO;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class LockerPropertiesDialog : Window
    {
        private static readonly IBrush LockedBrush = new SolidColorBrush(Color.Parse("#FF6923"));
        private static readonly IBrush UnlockedBrush = new SolidColorBrush(Color.Parse("#0077B6"));
        private static readonly Geometry LockedIcon = Geometry.Parse("M7 10V8C7 5.24 9.24 3 12 3S17 5.24 17 8V10H18C18.55 10 19 10.45 19 11V20C19 20.55 18.55 21 18 21H6C5.45 21 5 20.55 5 20V11C5 10.45 5.45 10 6 10H7ZM9 10H15V8C15 6.34 13.66 5 12 5S9 6.34 9 8V10Z");
        private static readonly Geometry UnlockedIcon = Geometry.Parse("M7 10V8C7 5.24 9.24 3 12 3C14.05 3 15.82 4.23 16.59 6H14.24C13.69 5.39 12.89 5 12 5C10.34 5 9 6.34 9 8V10H18C18.55 10 19 10.45 19 11V20C19 20.55 18.55 21 18 21H6C5.45 21 5 20.55 5 20V11C5 10.45 5.45 10 6 10H7Z");

        private readonly LockerModel _locker;
        private readonly TextBox _nameBox;
        private readonly TextBox _locationBox;
        private readonly Button _saveButton;
        private bool _hasChanges;

        public LockerPropertiesDialog(LockerModel locker)
        {
            _locker = locker;

            Title = "Locker Properties";
            Width = 560;
            Height = 600;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            _nameBox = new TextBox { Text = locker.LockerName };
            _nameBox.TextChanged += (_, _) => UpdateChangeState();

            _locationBox = new TextBox
            {
                Text = locker.LockerLocation,
                IsReadOnly = true
            };

            var browseButton = DialogHelpers.Button("Browse...");
            browseButton.IsEnabled = !locker.IsLocked;
            browseButton.Click += BrowseButton_Click;

            _saveButton = DialogHelpers.Button("Save");
            _saveButton.IsEnabled = false;
            _saveButton.Click += SaveButton_Click;

            var closeButton = DialogHelpers.Button("Close");
            closeButton.Click += CloseButton_Click;

            Content = BuildContent(locker, browseButton, closeButton);
        }

        private Control BuildContent(LockerModel locker, Button browseButton, Button closeButton)
        {
            var locationGrid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("*,Auto"),
                ColumnSpacing = 8,
                Children = { _locationBox, browseButton }
            };
            Grid.SetColumn(browseButton, 1);

            var lockedLocationWarning = locker.IsLocked
                ? Description("Location cannot be changed while the locker is locked.")
                : new TextBlock();

            var content = new StackPanel
            {
                Margin = new Thickness(18),
                Spacing = 18,
                Children =
                {
                    Section(
                        "General",
                        EditableField("Name", _nameBox),
                        EditableField("Location", locationGrid),
                        lockedLocationWarning,
                        StatusRow(locker)),
                    Section(
                        "Storage",
                        ReadOnlyField("Size", GetSizeText(locker.LockerLocation))),
                    Section(
                        "Dates",
                        ReadOnlyField("Created", GetDirectoryDate(locker.LockerLocation, dateKind: DateKind.Created)),
                        ReadOnlyField("Last Modified", GetDirectoryDate(locker.LockerLocation, dateKind: DateKind.Modified)))
                }
            };

            var scroller = new ScrollViewer
            {
                VerticalScrollBarVisibility = global::Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
                Content = content
            };

            var footer = new Border
            {
                Padding = new Thickness(18),
                Child = DialogHelpers.Buttons(_saveButton, closeButton)
            };

            var root = new Grid
            {
                RowDefinitions = new RowDefinitions("*,Auto")
            };
            root.Children.Add(scroller);
            Grid.SetRow(footer, 1);
            root.Children.Add(footer);
            return root;
        }

        private async void BrowseButton_Click(object? sender, EventArgs e)
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
            _locationBox.Text = selectedPath;

            var selectedName = GetFolderName(selectedPath);
            if (!string.IsNullOrWhiteSpace(selectedName))
            {
                _nameBox.Text = selectedName;
            }

            UpdateChangeState();
        }

        private async void SaveButton_Click(object? sender, EventArgs e)
        {
            var newName = _nameBox.Text?.Trim() ?? string.Empty;
            var newLocation = _locationBox.Text?.Trim() ?? string.Empty;

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
                _locker.LockerName = newName;
                if (!_locker.IsLocked)
                {
                    _locker.LockerLocation = newLocation;
                }

                LockerRepository.UpdateLocker(_locker);

                _hasChanges = false;
                _saveButton.IsEnabled = false;
                await new MessageDialog("Locker Properties", "Locker properties saved successfully.", MessageDialogKind.Information)
                    .ShowDialog<object?>(this);
                Close(true);
            }
            catch (UnauthorizedAccessException ex)
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

        private async void CloseButton_Click(object? sender, EventArgs e)
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
            _hasChanges =
                !string.Equals(_nameBox.Text?.Trim(), _locker.LockerName, StringComparison.Ordinal) ||
                (!_locker.IsLocked && !string.Equals(_locationBox.Text?.Trim(), _locker.LockerLocation, StringComparison.Ordinal));
            _saveButton.IsEnabled = _hasChanges;
        }

        private static Border Section(string title, params Control[] rows)
        {
            var panel = new StackPanel
            {
                Spacing = 10
            };

            panel.Children.Add(new TextBlock
            {
                Text = title,
                FontSize = 16,
                FontWeight = FontWeight.SemiBold
            });

            foreach (var row in rows)
            {
                if (row is TextBlock { Text: "" })
                {
                    continue;
                }

                panel.Children.Add(row);
            }

            return new Border
            {
                Padding = new Thickness(14),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Child = panel
            };
        }

        private static StackPanel EditableField(string label, Control control)
        {
            return new StackPanel
            {
                Spacing = 4,
                Children =
                {
                    Label(label),
                    control
                }
            };
        }

        private static Grid ReadOnlyField(string label, string value)
        {
            var grid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("150,*"),
                ColumnSpacing = 12
            };

            grid.Children.Add(Label(label));
            var valueText = new TextBlock
            {
                Text = value,
                TextWrapping = TextWrapping.Wrap,
                Opacity = 0.78
            };
            Grid.SetColumn(valueText, 1);
            grid.Children.Add(valueText);
            return grid;
        }

        private static Grid StatusRow(LockerModel locker)
        {
            var brush = locker.IsLocked ? LockedBrush : UnlockedBrush;

            var statusPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 6,
                Children =
                {
                    new PathIcon
                    {
                        Width = 16,
                        Height = 16,
                        Data = locker.IsLocked ? LockedIcon : UnlockedIcon,
                        Foreground = brush
                    },
                    new TextBlock
                    {
                        Text = locker.IsLocked ? "Locked" : "Unlocked",
                        Foreground = brush,
                        FontWeight = FontWeight.SemiBold
                    }
                }
            };

            var grid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("150,*"),
                ColumnSpacing = 12
            };
            grid.Children.Add(Label("Status"));
            Grid.SetColumn(statusPanel, 1);
            grid.Children.Add(statusPanel);
            return grid;
        }

        private static TextBlock Label(string label)
        {
            return new TextBlock
            {
                Text = label,
                FontWeight = FontWeight.SemiBold
            };
        }

        private static TextBlock Description(string text)
        {
            return new TextBlock
            {
                Text = text,
                FontSize = 12,
                Foreground = LockedBrush,
                TextWrapping = TextWrapping.Wrap
            };
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
            catch
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

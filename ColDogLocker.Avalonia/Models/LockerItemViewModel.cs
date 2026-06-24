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

using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using Material.Icons;

namespace ColDogStudios.ColDogLocker.Avalonia.Models
{
    public partial class LockerItemViewModel : ObservableObject
    {
        private static readonly IBrush LockedBrush = new SolidColorBrush(Color.Parse("#FF6923"));
        private static readonly IBrush UnlockedBrush = new SolidColorBrush(Color.Parse("#0077B6"));

        [ObservableProperty] private string _guid = string.Empty;
        [ObservableProperty] private bool _isLocked;
        [ObservableProperty] private DateTime _lastModified;
        [ObservableProperty] private string _location = string.Empty;
        [ObservableProperty] private string _name = string.Empty;
        [ObservableProperty] private long _size;

        public string StatusText => IsLocked ? "Locked" : "Unlocked";
        public bool CanRemove => !IsLocked;
        public MaterialIconKind StatusIconKind => IsLocked ? MaterialIconKind.Lock : MaterialIconKind.LockOpen;
        public IBrush StatusBrush => IsLocked ? LockedBrush : UnlockedBrush;
        public string SizeText => FormatBytes(Size);

        partial void OnIsLockedChanged(bool value)
        {
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(CanRemove));
            OnPropertyChanged(nameof(StatusIconKind));
            OnPropertyChanged(nameof(StatusBrush));
        }

        partial void OnSizeChanged(long value)
        {
            OnPropertyChanged(nameof(SizeText));
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
    }
}

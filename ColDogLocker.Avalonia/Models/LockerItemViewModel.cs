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

namespace ColDogStudios.ColDogLocker.Avalonia.Models
{
    public partial class LockerItemViewModel : ObservableObject
    {
        private static readonly IBrush LockedBrush = new SolidColorBrush(Color.Parse("#FF6923"));
        private static readonly IBrush UnlockedBrush = new SolidColorBrush(Color.Parse("#0077B6"));
        private static readonly Lazy<Geometry> LockedIcon = new(() => Geometry.Parse("M7 10V8C7 5.24 9.24 3 12 3S17 5.24 17 8V10H18C18.55 10 19 10.45 19 11V20C19 20.55 18.55 21 18 21H6C5.45 21 5 20.55 5 20V11C5 10.45 5.45 10 6 10H7ZM9 10H15V8C15 6.34 13.66 5 12 5S9 6.34 9 8V10Z"));
        private static readonly Lazy<Geometry> UnlockedIcon = new(() => Geometry.Parse("M7 10V8C7 5.24 9.24 3 12 3C14.05 3 15.82 4.23 16.59 6H14.24C13.69 5.39 12.89 5 12 5C10.34 5 9 6.34 9 8V10H18C18.55 10 19 10.45 19 11V20C19 20.55 18.55 21 18 21H6C5.45 21 5 20.55 5 20V11C5 10.45 5.45 10 6 10H7Z"));

        [ObservableProperty] private string _guid = string.Empty;
        [ObservableProperty] private bool _isLocked;
        [ObservableProperty] private DateTime _lastModified;
        [ObservableProperty] private string _location = string.Empty;
        [ObservableProperty] private string _name = string.Empty;
        [ObservableProperty] private long _size;

        public string StatusText => IsLocked ? "Locked" : "Unlocked";
        public Geometry StatusIconData => IsLocked ? LockedIcon.Value : UnlockedIcon.Value;
        public IBrush StatusBrush => IsLocked ? LockedBrush : UnlockedBrush;
        public string SizeText => FormatBytes(Size);

        partial void OnIsLockedChanged(bool value)
        {
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(StatusIconData));
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

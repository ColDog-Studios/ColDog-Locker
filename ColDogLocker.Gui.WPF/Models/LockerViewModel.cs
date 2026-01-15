using CommunityToolkit.Mvvm.ComponentModel;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Models
{
    /// <summary>
    /// View model representing a locker in the UI
    /// </summary>
    public partial class LockerViewModel : ObservableObject
    {
        [ObservableProperty]
        private string _guid = string.Empty;

        [ObservableProperty]
        private string _name = string.Empty;

        [ObservableProperty]
        private bool _isLocked;

        [ObservableProperty]
        private string _location = string.Empty;

        [ObservableProperty]
        private DateTime _lastModified;

        [ObservableProperty]
        private long _size;

        [ObservableProperty]
        private bool _isSelected;

        /// <summary>
        /// Gets the display icon based on lock status
        /// </summary>
        public string IconGlyph => IsLocked ? "\uE72E" : "\uE785"; // Lock/Unlock glyphs

        /// <summary>
        /// Gets the status text
        /// </summary>
        public string StatusText => IsLocked ? "Locked" : "Unlocked";

        /// <summary>
        /// Gets the formatted size string
        /// </summary>
        public string SizeText => FormatBytes(Size);

        private static string FormatBytes(long bytes)
        {
            string[] sizes = ["B", "KB", "MB", "GB", "TB"];
            double len = bytes;
            var order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        partial void OnIsLockedChanged(bool value)
        {
            OnPropertyChanged(nameof(IconGlyph));
            OnPropertyChanged(nameof(StatusText));
        }
    }
}

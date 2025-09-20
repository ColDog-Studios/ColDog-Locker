namespace ColDogStudios.ColDogLocker.Core.Models
{
    public class LockerModel(string lockerName, string password, string cdlLocation)
    {
        // Properties of the locker
        public string Guid { get; set; } = System.Guid.NewGuid().ToString();
        public string LockerName { get; set; } = lockerName;
        public string Password { get; set; } = password;
        public string LockerPath { get; set; } = cdlLocation; // Renamed for clarity
        public bool IsLocked { get; set; } = false;
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public DateTime LastModified { get; set; } = DateTime.Now;
        public long SizeBytes { get; set; } = 0;

        // Additional properties for GUI display
        public int FileCount => GetFileCount();
        public string SizeFormatted => FormatBytes(SizeBytes);
        public string LastModifiedFormatted => LastModified.ToString("yyyy-MM-dd HH:mm:ss");
        public string StatusText => IsLocked ? "Locked" : "Unlocked";

        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        // Update size by calculating directory size
        public void UpdateSize()
        {
            if (Directory.Exists(LockerPath))
            {
                SizeBytes = GetDirectorySize(LockerPath);
                LastModified = Directory.GetLastWriteTime(LockerPath);
            }
        }

        private static long GetDirectorySize(string path)
        {
            try
            {
                return Directory.GetFiles(path, "*", SearchOption.AllDirectories)
                    .Sum(file => new FileInfo(file).Length);
            }
            catch
            {
                return 0;
            }
        }

        private int GetFileCount()
        {
            try
            {
                if (Directory.Exists(LockerPath))
                {
                    return Directory.GetFiles(LockerPath, "*", SearchOption.AllDirectories).Length;
                }
                return 0;
            }
            catch
            {
                return 0;
            }
        }
    }
}

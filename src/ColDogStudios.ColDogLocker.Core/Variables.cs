namespace ColDogStudios.ColDogLocker.Core
{
    public static class Variables
    {
        //////////////////////////////////////////
        // Path Configuration
        //////////////////////////////////////////

        // Local configuration directory
        public static readonly string LocalConfig = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ColDog Studios",
            "ColDog Locker"
        );

        // Roaming configuration directory (to be phased out)
        public static readonly string RoamingConfig = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ColDog Studios",
            "ColDog Locker"
        );

        // ColDog Locker Directory
        public static readonly string CdlDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "ColDog Locker"
        );

        //////////////////////////////////////////
        // Build Information (Auto-generated)
        //////////////////////////////////////////

        public const string Version = "0.1.0-pre";
        public const string BuildVersion = "0.1.0-pre.2025.0829.1827";
        public const string BuildNumber = "2025.0829.1827";
        public const string BuildDate = "2025-08-29";
    }
}

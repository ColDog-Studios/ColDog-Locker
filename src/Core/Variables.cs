namespace ColDogStudios.ColDogLocker.Core
{
    public static class Variables
    {
        //////////////////////////////////////////
        // Path Configuration
        //////////////////////////////////////////

        // Local configuration directory
        public static readonly string localConfig = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ColDog Studios",
            "ColDog Locker"
        );

        // Roaming configuration directory (to be phased out)
        public static readonly string roamingConfig = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ColDog Studios",
            "ColDog Locker"
        );

        // ColDog Locker Directory
        public static readonly string cdlDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "ColDog Locker"
        );

        //////////////////////////////////////////
        // Build Information (Auto-generated)
        //////////////////////////////////////////

        public const string version = "0.1.0-pre";
        public const string buildVersion = "0.1.0-pre.2025.1201.1154";
        public const string buildNumber = "2025.1201.1154";
        public const string buildDate = "2025-12-01";
    }
}

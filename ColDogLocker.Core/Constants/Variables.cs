namespace ColDogStudios.ColDogLocker.Core.Constants
{
    /// <summary>
    /// Application-wide path configuration and constants.
    /// Build version information is available in BuildInfo (auto-generated at compile time).
    /// </summary>
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
    }
}

namespace ColDogStudios.ColDogLocker.Core.Constants
{
    /// <summary>
    ///     Application-wide path configuration and constants.
    ///     Application Build version information is available in AppInfo (auto-generated at compile time).
    /// </summary>
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

        // Default ColDog Locker Directory
        public static readonly string CdlDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "ColDog Locker"
        );
    }
}

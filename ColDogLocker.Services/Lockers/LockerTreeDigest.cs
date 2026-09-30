namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    /// <summary>Content/name digest used to verify an already committed unlock without deleting files.</summary>
    internal static class LockerTreeDigest
    {
        internal static string Compute(string directory, string? expectedMovedWindowsAccessControl = null)
        {
            return LockerTreeManifestDigest.Compute(directory, expectedMovedWindowsAccessControl);
        }
    }
}

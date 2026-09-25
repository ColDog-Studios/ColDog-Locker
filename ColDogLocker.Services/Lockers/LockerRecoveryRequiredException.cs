namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    /// <summary>A failed destructive operation retained its completed archive for recovery.</summary>
    public sealed class LockerRecoveryRequiredException : IOException
    {
        public string ArchivePath { get; }
        public string? SourceRecoveryPath { get; }

        public LockerRecoveryRequiredException(string archivePath, Exception innerException)
            : base($"Lock failed after source removal began. The source may be incomplete. A recovery archive was retained at '{archivePath}'. Preserve this archive and do not lock the remaining source again until recovery is complete.", innerException)
        {
            ArchivePath = archivePath;
        }

        public LockerRecoveryRequiredException(string archivePath, string sourceRecoveryPath, Exception innerException)
            : base($"Lock failed after taking ownership of the source path. The complete or surviving source was retained at '{sourceRecoveryPath}', and a recovery archive was retained at '{archivePath}'. Preserve both paths until recovery is complete.", innerException)
        {
            ArchivePath = archivePath;
            SourceRecoveryPath = sourceRecoveryPath;
        }
    }
}

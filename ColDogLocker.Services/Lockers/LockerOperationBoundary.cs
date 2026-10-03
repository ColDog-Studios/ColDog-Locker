namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    /// <summary>Internal observation seam used by subprocess crash tests.</summary>
    internal static class LockerOperationBoundary
    {
        internal static Action<string>? Observer { get; set; }

        internal static void Reached(string boundary) => Observer?.Invoke(boundary);
    }
}

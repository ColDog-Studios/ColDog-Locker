namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public sealed record LockerOperationProgress(
        string Stage,
        string Message,
        int? Percent,
        bool CanCancel);
}

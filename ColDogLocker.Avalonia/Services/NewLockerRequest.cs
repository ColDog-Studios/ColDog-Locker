namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public sealed class NewLockerRequest
    {
        public string LockerName { get; init; } = string.Empty;
        public string Location { get; init; } = string.Empty;
        public string Password { get; init; } = string.Empty;
    }
}

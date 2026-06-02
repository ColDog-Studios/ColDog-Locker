namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    public interface IPlatformService
    {
        Task OpenUrlAsync(string url);
        Task OpenFolderAsync(string path);
        Task OpenFolderAndSelectAsync(string path);
        Task CopyTextAsync(string text);
    }
}

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>Captures every existing directory from a path through its filesystem root.</summary>
    internal sealed class FileSystemPathIdentity
    {
        private readonly IReadOnlyList<(string Path, FileSystemIdentity Identity)> _chain;

        private FileSystemPathIdentity(IReadOnlyList<(string Path, FileSystemIdentity Identity)> chain)
        {
            _chain = chain;
        }

        internal FileSystemIdentity LeafIdentity => _chain[0].Identity;

        internal bool Overlaps(FileSystemPathIdentity other)
        {
            ArgumentNullException.ThrowIfNull(other);
            return _chain.Any(entry => entry.Identity == other.LeafIdentity) ||
                other._chain.Any(entry => entry.Identity == LeafIdentity);
        }

        internal static FileSystemPathIdentity CaptureDirectory(string path)
        {
            var chain = new List<(string Path, FileSystemIdentity Identity)>();
            for (var current = new DirectoryInfo(Path.GetFullPath(path)); current != null; current = current.Parent)
            {
                chain.Add((current.FullName, FileSystemIdentity.CaptureDirectory(current.FullName)));
            }

            var result = new FileSystemPathIdentity(chain);
            result.EnsureUnchanged();
            return result;
        }

        internal void EnsureUnchanged()
        {
            foreach (var entry in _chain)
            {
                if (FileSystemIdentity.CaptureDirectory(entry.Path) != entry.Identity)
                {
                    throw new IOException($"A locker directory or one of its parent directories was replaced during the operation: {entry.Path}");
                }
            }
        }
    }
}

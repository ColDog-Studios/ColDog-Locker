using System.Diagnostics;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    /// <summary>Best-effort display metadata, not a security or integrity check.</summary>
    internal static class DirectorySizeScanner
    {
        internal static long? Calculate(string path, CancellationToken cancellationToken = default,
            int maxEntries = 200000, int maxDepth = 256, TimeSpan? timeLimit = null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var clock = Stopwatch.StartNew();
            var limit = timeLimit ?? TimeSpan.FromSeconds(5);
            var pending = new Stack<(DirectoryInfo Directory, int Depth)>();
            long size = 0;
            var entries = 0;
            try
            {
                pending.Push((new DirectoryInfo(path), 0));
                while (pending.TryPop(out var next))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (clock.Elapsed >= limit || next.Depth > maxDepth || !next.Directory.Exists ||
                        next.Directory.LinkTarget != null || (next.Directory.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        return null;
                    }

                    foreach (var entry in next.Directory.EnumerateFileSystemInfos())
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (++entries > maxEntries || clock.Elapsed >= limit || entry.LinkTarget != null ||
                            (entry.Attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            return null;
                        }

                        if (entry is DirectoryInfo child)
                        {
                            pending.Push((child, next.Depth + 1));
                        }
                        else if (entry is FileInfo file)
                        {
                            size = checked(size + file.Length);
                        }
                    }
                }

                return size;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or OverflowException or ArgumentException)
            {
                return null;
            }
        }
    }
}

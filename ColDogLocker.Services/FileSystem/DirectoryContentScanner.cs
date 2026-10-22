using System.Diagnostics;
using ColDogStudios.ColDogLocker.Core.Validation;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>Bounded content counts; no filesystem snapshot or archive authentication guarantee.</summary>
    public static class DirectoryContentScanner
    {
        public static (int Files, int Directories) Count(string path) => Count(path, 200000, 256, TimeSpan.FromSeconds(5));

        internal static (int Files, int Directories) Count(string path, int maxEntries, int maxDepth, TimeSpan timeLimit)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(maxEntries);
            ArgumentOutOfRangeException.ThrowIfNegative(maxDepth);
            ArgumentOutOfRangeException.ThrowIfNegative(timeLimit.Ticks, nameof(timeLimit));
            path = Path.GetFullPath(path);
            if (LockerPathFilter.FindLinkedAncestor(path) != null)
            {
                throw new IOException("Content inspection refused a linked directory path.");
            }

            var clock = Stopwatch.StartNew();
            var pending = new Stack<(DirectoryInfo Directory, int Depth)>();
            pending.Push((new DirectoryInfo(path), 0));
            var files = 0;
            var directories = 0;
            while (pending.TryPop(out var next))
            {
                CheckBudget(next.Depth);
                FileSystemEntryPolicy.EnsureSupported(next.Directory);
                foreach (var entry in next.Directory.EnumerateFileSystemInfos())
                {
                    CheckBudget(next.Depth);
                    if ((long)files + directories >= maxEntries)
                    {
                        throw new IOException("Content inspection exceeded the supported entry limit; counts are unavailable.");
                    }

                    FileSystemEntryPolicy.EnsureSupported(entry);
                    if (entry is DirectoryInfo child)
                    {
                        directories++;
                        pending.Push((child, next.Depth + 1));
                    }
                    else
                    {
                        files++;
                    }
                }
            }

            // An OS call can outlast the budget, including the final enumeration call.
            CheckBudget(0);
            return (files, directories);

            void CheckBudget(int depth)
            {
                if (depth > maxDepth || clock.Elapsed >= timeLimit)
                {
                    throw new IOException("Content inspection exceeded its depth or time limit; counts are unavailable.");
                }
            }
        }
    }
}

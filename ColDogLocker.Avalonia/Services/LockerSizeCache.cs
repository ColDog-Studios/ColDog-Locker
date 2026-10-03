using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Avalonia.Services
{
    /// <summary>Short-lived display estimates. Never used for archive validation or deletion decisions.</summary>
    internal sealed class LockerSizeCache
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
        private readonly Func<string, CancellationToken, long?> _scan;
        private readonly TimeProvider _clock;
        private readonly int _capacity;
        private static readonly TimeSpan _lifetime = TimeSpan.FromSeconds(30);

        internal LockerSizeCache(Func<string, CancellationToken, long?>? scan = null, TimeProvider? clock = null, int capacity = 256)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
            _scan = scan ?? ((path, token) => DirectorySizeScanner.Calculate(path, token));
            _clock = clock ?? TimeProvider.System;
            _capacity = capacity;
        }

        internal long? GetSize(LockerModel locker, bool forceScan, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var key = new Key(locker.LockerLocation, locker.Revision, locker.IsLocked);
            var started = _clock.GetTimestamp();
            lock (_gate)
            {
                if (!forceScan && _entries.TryGetValue(locker.Guid, out var cached) && cached.Key == key &&
                    _clock.GetElapsedTime(cached.Timestamp, started) < _lifetime)
                {
                    return cached.Size;
                }
            }

            var size = _scan(key.Location, cancellationToken);
            lock (_gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_entries.ContainsKey(locker.Guid) && _entries.Count >= _capacity)
                {
                    _entries.Remove(_entries.MinBy(pair => pair.Value.Timestamp).Key);
                }

                _entries[locker.Guid] = new Entry(key, size, started);
            }

            return size;
        }

        private sealed record Key(string Location, long Revision, bool IsLocked);
        private sealed record Entry(Key Key, long? Size, long Timestamp);
    }
}

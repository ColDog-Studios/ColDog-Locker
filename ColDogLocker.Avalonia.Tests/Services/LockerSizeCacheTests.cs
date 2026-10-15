using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests.Services
{
    public class LockerSizeCacheTests
    {
        [Fact]
        public void AutomaticRefreshReusesRecentSizeButExplicitRefreshAndExpiryRescan()
        {
            var scans = 0;
            var clock = new ManualClock();
            var cache = new LockerSizeCache((_, _) => ++scans, clock);
            var locker = Locker();
            Assert.Equal(1L, cache.GetSize(locker, false, TestContext.Current.CancellationToken));
            clock.Advance(TimeSpan.FromSeconds(29));
            Assert.Equal(1L, cache.GetSize(locker, false, TestContext.Current.CancellationToken));
            Assert.Equal(2L, cache.GetSize(locker, true, TestContext.Current.CancellationToken));
            clock.Advance(TimeSpan.FromSeconds(30));
            Assert.Equal(3L, cache.GetSize(locker, false, TestContext.Current.CancellationToken));
        }

        [Theory]
        [InlineData("revision")]
        [InlineData("location")]
        [InlineData("state")]
        public void ChangedRegistrationIsRescannedImmediately(string change)
        {
            var scans = 0;
            var cache = new LockerSizeCache((_, _) => ++scans);
            var locker = Locker();
            cache.GetSize(locker, false, TestContext.Current.CancellationToken);
            switch (change)
            {
                case "revision":
                    locker.Revision++;
                    break;
                case "location":
                    locker.LockerLocation += "-moved";
                    break;
                case "state":
                    locker.IsLocked = true;
                    break;
            }

            Assert.Equal(2L, cache.GetSize(locker, false, TestContext.Current.CancellationToken));
        }

        [Fact]
        public void CacheIsBoundedAndUnknownSizeStaysUnknown()
        {
            var scans = 0;
            var clock = new ManualClock();
            var cache = new LockerSizeCache((_, _) =>
            {
                scans++;
                return null;
            }, clock, capacity: 2);
            var first = Locker();
            Assert.Null(cache.GetSize(first, false, TestContext.Current.CancellationToken));
            clock.Advance(TimeSpan.FromSeconds(1));
            cache.GetSize(Locker(), false, TestContext.Current.CancellationToken);
            clock.Advance(TimeSpan.FromSeconds(1));
            cache.GetSize(Locker(), false, TestContext.Current.CancellationToken);
            Assert.Null(cache.GetSize(first, false, TestContext.Current.CancellationToken));
            Assert.Equal(4, scans);
        }

        [Fact]
        public void CancelledScanDoesNotPopulateCache()
        {
            var scans = 0;
            using var cancellation = new CancellationTokenSource();
            var cache = new LockerSizeCache((_, _) =>
            {
                scans++;
                cancellation.Cancel();
                return 12;
            });
            var locker = Locker();
            Assert.Throws<OperationCanceledException>(() => cache.GetSize(locker, false, cancellation.Token));
            Assert.Equal(12L, cache.GetSize(locker, false, TestContext.Current.CancellationToken));
            Assert.Equal(2, scans);
        }

        private static LockerModel Locker() => new("Vault", "verifier", Path.Join(Path.GetTempPath(), "Vault"));

        private sealed class ManualClock : TimeProvider
        {
            private long _ticks;
            public override long TimestampFrequency => TimeSpan.TicksPerSecond;
            public override long GetTimestamp() => _ticks;
            internal void Advance(TimeSpan duration) => _ticks += duration.Ticks;
        }
    }
}

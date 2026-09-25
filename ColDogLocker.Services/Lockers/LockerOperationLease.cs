using System.Security.Cryptography;
using System.Text;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    /// <summary>Thread-affine, reentrant ownership shared by app processes for one user's locker.</summary>
    internal sealed class LockerOperationLease : IDisposable
    {
        private readonly Mutex _mutex;
        private bool _disposed;

        private LockerOperationLease(Mutex mutex)
        {
            _mutex = mutex;
        }

        internal static LockerOperationLease Acquire(string lockerGuid)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(lockerGuid);
            var userScope = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var identity = SHA256.HashData(Encoding.UTF8.GetBytes(userScope + "\n" + lockerGuid));
            var prefix = OperatingSystem.IsWindows() ? @"Global\ColDogLocker.Operation." : "ColDogLocker.Operation.";
            var mutex = new Mutex(false, prefix + Convert.ToHexString(identity));
            try
            {
                if (!mutex.WaitOne(0))
                {
                    throw new InvalidOperationException("Another operation is already working on this locker. Wait for it to finish and reload the locker before retrying.");
                }

                return new LockerOperationLease(mutex);
            }
            catch (AbandonedMutexException)
            {
                // WaitOne grants ownership when reporting abandonment. The durable operation journal,
                // validated under this lease, determines whether recovery is required.
                return new LockerOperationLease(mutex);
            }
            catch
            {
                mutex.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _mutex.ReleaseMutex();
                _mutex.Dispose();
                _disposed = true;
            }
        }
    }
}

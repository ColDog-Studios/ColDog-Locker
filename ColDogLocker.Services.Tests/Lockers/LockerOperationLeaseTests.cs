using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public class LockerOperationLeaseTests
    {
        [Fact]
        public void Lease_IsReentrantOnOwningThread()
        {
            var id = Guid.NewGuid().ToString();
            using var outer = LockerOperationLease.Acquire(id);
            using var inner = LockerOperationLease.Acquire(id);
        }

        [Fact]
        public void Lease_RejectsAnotherThreadUntilTheOwnerReleases()
        {
            var id = Guid.NewGuid().ToString();
            using var lease = LockerOperationLease.Acquire(id);
            Exception? error = null;
            var contender = new Thread(() => error = Record.Exception(() =>
            {
                using var other = LockerOperationLease.Acquire(id);
            }));
            contender.Start();
            Assert.True(contender.Join(TimeSpan.FromSeconds(10)));
            Assert.IsType<InvalidOperationException>(error);
            lease.Dispose();
            using var next = LockerOperationLease.Acquire(id);
        }

        [Fact]
        public void Lease_AllowsIndependentLockers()
        {
            using var first = LockerOperationLease.Acquire(Guid.NewGuid().ToString());
            Exception? error = null;
            var contender = new Thread(() => error = Record.Exception(() =>
            {
                using var second = LockerOperationLease.Acquire(Guid.NewGuid().ToString());
            }));
            contender.Start();
            Assert.True(contender.Join(TimeSpan.FromSeconds(10)));
            Assert.Null(error);
        }

        [Fact]
        public void Lease_AcquiresAbandonedMutexSoJournalValidationCanDecideRecovery()
        {
            var id = Guid.NewGuid().ToString();
            var owner = new Thread(() => LockerOperationLease.Acquire(id));
            owner.Start();
            Assert.True(owner.Join(TimeSpan.FromSeconds(10)));

            using var recovered = LockerOperationLease.Acquire(id);
        }
    }
}

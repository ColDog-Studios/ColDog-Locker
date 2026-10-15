using Avalonia.Headless;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests
{
    internal static class HeadlessTestSession
    {
        internal static async Task RunAsync(Action action)
        {
            await using var session = HeadlessUnitTestSession.StartNew(typeof(TestAppBuilder));
            await session.Dispatch(action, CancellationToken.None);
        }

        internal static async Task RunAsync(Func<Task> action)
        {
            await using var session = HeadlessUnitTestSession.StartNew(typeof(TestAppBuilder));
            await session.Dispatch(async () =>
            {
                await action();
                return true;
            }, CancellationToken.None);
        }
    }
}

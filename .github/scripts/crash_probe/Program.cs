using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Startup;

if (args.Length < 5)
{
    Console.Error.WriteLine("Usage: CrashProbe <lock|unlock|recovery> <identity> <boundary> <marker> <password> [archive destination]");
    return 2;
}

var operation = args[0];
var identity = args[1];
var expectedBoundary = args[2];
var marker = args[3];
var password = args[4];

await Initialization.InitializeAsync(checkForUpdates: false);
LockerOperationBoundary.Observer = boundary =>
{
    if (!boundary.Equals(expectedBoundary, StringComparison.Ordinal))
    {
        return;
    }

    var temporaryMarker = marker + ".tmp";
    using (var signal = new FileStream(temporaryMarker, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
    using (var writer = new StreamWriter(signal, leaveOpen: true))
    {
        writer.Write(boundary);
        writer.Flush();
        signal.Flush(flushToDisk: true);
    }

    File.Move(temporaryMarker, marker);

    Thread.Sleep(Timeout.Infinite);
};

switch (operation)
{
    case "lock":
    {
        var locker = LockerService.FindLockerByName(identity)
            ?? throw new InvalidOperationException($"Locker '{identity}' was not found.");
        LockerService.Lock(locker, password);
        break;
    }
    case "unlock":
    {
        var locker = LockerService.FindLockerByName(identity)
            ?? throw new InvalidOperationException($"Locker '{identity}' was not found.");
        LockerService.Unlock(locker, password);
        break;
    }
    case "recovery" when args.Length == 7:
        LockerRecoveryService.RecoverOperation(identity, args[5], args[6], password);
        break;
    default:
        throw new ArgumentException($"Unsupported probe operation '{operation}'.");
}

throw new InvalidOperationException($"Boundary '{expectedBoundary}' was not reached.");

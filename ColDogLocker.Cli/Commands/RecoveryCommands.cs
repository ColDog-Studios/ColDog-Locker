using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Tui.Input;

namespace ColDogStudios.ColDogLocker.Cli.Commands
{
    public static class RecoveryCommands
    {
        public static int FinishCommitted(string[] args)
        {
            if (args.Length != 2)
            {
                Console.Error.WriteLine("Usage: cdlocker recovery-finish <operation-id>");
                return 1;
            }

            var operation = LockerRecoveryService.FinishCommittedOperation(args[1]);
            Console.WriteLine($"Verified committed {operation.Kind} state. The journal was moved to recovery-history.");
            Console.WriteLine("No files were removed or modified. Inspect retained source/staging paths before cleanup.");
            return 0;
        }

        public static int RestoreOperation(string[] args)
        {
            if (args.Length is not (4 or 6) || (args.Length == 6 && args[4] != "--password"))
            {
                Console.Error.WriteLine("Usage: cdlocker recovery-restore <operation-id> <archive.cdl> <new-destination> [--password <password>]");
                return 1;
            }

            string password;
            if (args.Length == 6)
            {
                password = args[5];
            }
            else
            {
                Console.Write("Archive password: ");
                password = ConsoleHelper.ReadPassword();
                Console.WriteLine();
            }

            var restored = LockerRecoveryService.RecoverOperation(args[1], args[2], args[3], password);
            Console.WriteLine($"Recovered and registered '{restored.LockerName}' at '{restored.LockerLocation}'. Reload other app windows.");
            Console.WriteLine("Original source, archive and staging artifacts were preserved. Inspect recovery-history before any cleanup.");
            Console.WriteLine("Locking the recovered folder will not protect plaintext copies retained at the original paths.");
            return 0;
        }

        public static int CancelPrepared(string[] args)
        {
            if (args.Length != 2)
            {
                Console.Error.WriteLine("Usage: cdlocker recovery-cancel <operation-id>");
                return 1;
            }

            var operation = LockerRepository.CancelPreparedOperation(args[1]);
            Console.WriteLine($"Cancelled preparation for {operation.OperationId}. No files were removed or modified.");
            Console.WriteLine($"Retained staging: {operation.StagingPath}");
            Console.WriteLine("Its paths remain in recovery-history. Reload the locker before retrying.");
            return 0;
        }

        public static int ListHistory()
        {
            foreach (var operation in LockerRepository.GetOperationHistory())
            {
                Console.WriteLine($"{operation.OperationId}: resolved {operation.Kind} operation (last phase {operation.Phase})");
                Console.WriteLine($"  Source: {operation.SourcePath}");
                Console.WriteLine($"  Target: {operation.TargetPath}");
                Console.WriteLine($"  Retained staging: {operation.StagingPath}");
            }

            foreach (var attempt in LockerRepository.GetRecoveryAttempts())
            {
                Console.WriteLine($"Recovery {attempt.AttemptId}: {attempt.State} (operation {attempt.OperationId})");
                Console.WriteLine($"  Destination: {attempt.DestinationPath}");
                Console.WriteLine($"  Staging: {attempt.StagingPath}");
                Console.WriteLine($"  Archive: {attempt.ArchivePath}");
            }

            return 0;
        }

        public static int ListPending()
        {
            var pending = LockerRepository.GetPendingOperations();
            if (pending.Count == 0)
            {
                Console.WriteLine("No unfinished locker operations.");
            }

            foreach (var operation in pending)
            {
                Console.WriteLine($"{operation.OperationId}: {operation.Kind} / {operation.Phase} (locker {operation.LockerGuid})");
                Console.WriteLine($"  Source: {operation.SourcePath}");
                Console.WriteLine($"  Target: {operation.TargetPath}");
                Console.WriteLine($"  Staging: {operation.StagingPath}");
                Console.WriteLine(operation.Phase == "MetadataCommitted"
                    ? "  Use recovery-finish to verify committed output and resolve this record without changing files."
                    : "  Preserve all surviving files. Use recovery-restore with a retained archive and a new destination; recovery-cancel is limited to preparation.");
            }

            return 0;
        }

        public static int Recover(string[] args)
        {
            if (args.Length is not (3 or 5) || (args.Length == 5 && args[3] != "--password"))
            {
                Console.Error.WriteLine("Usage: cdlocker recover <archive.cdl> <new-destination> [--password <password>]");
                return 1;
            }

            string password;
            if (args.Length == 5)
            {
                password = args[4];
            }
            else
            {
                Console.Write("Archive password: ");
                password = ConsoleHelper.ReadPassword();
                Console.WriteLine();
            }

            LockerRecoveryService.RecoverArchive(args[1], args[2], password);
            Console.WriteLine($"Recovered files to '{Path.GetFullPath(args[2])}'. The input archive was preserved.");
            return 0;
        }
    }
}

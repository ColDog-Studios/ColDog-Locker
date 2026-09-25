using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public sealed record LockerRecoveryAttempt(string AttemptId, string OperationId, string LockerGuid,
        string ArchivePath, string ArchiveSha256, string DestinationPath, string StagingPath, string State);

    public static partial class LockerRepository
    {
        internal static string RecoveryConnectionString => _connectionString;

        public static IReadOnlyList<LockerRecoveryAttempt> GetRecoveryAttempts() => GetRecoveryAttempts(_connectionString);

        internal static IReadOnlyList<LockerRecoveryAttempt> GetRecoveryAttempts(string connectionString)
        {
            using var connection = OpenConnection(connectionString);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT AttemptId, OperationId, LockerGuid, ArchivePath, ArchiveSha256, DestinationPath, StagingPath, State FROM LockerRecoveryAttempts ORDER BY AttemptId";
            using var reader = command.ExecuteReader();
            var attempts = new List<LockerRecoveryAttempt>();
            while (reader.Read())
            {
                attempts.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7)));
            }

            return attempts;
        }

        internal static void ArchiveCommittedOperation(PendingLockerOperation operation, long revision, string connectionString)
        {
            using var connection = OpenConnection(connectionString);
            using var transaction = connection.BeginTransaction(deferred: false);
            using var archive = connection.CreateCommand();
            archive.Transaction = transaction;
            archive.CommandText = """
            INSERT INTO LockerOperationHistory
                (OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson, OutputTreeSha256, Resolution)
            SELECT OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson, OutputTreeSha256, 'VerifiedCommittedState'
            FROM LockerOperations WHERE OperationId = $operation AND LockerGuid = $guid
                AND Phase = 'MetadataCommitted' AND OutputTreeSha256 IS $tree
                AND EXISTS (SELECT 1 FROM Lockers WHERE Guid = $guid AND Revision = $revision);
            """;
            archive.Parameters.AddWithValue("$operation", operation.OperationId);
            archive.Parameters.AddWithValue("$guid", operation.LockerGuid);
            archive.Parameters.AddWithValue("$tree", (object?)operation.OutputTreeSha256 ?? DBNull.Value);
            archive.Parameters.AddWithValue("$revision", revision);
            if (archive.ExecuteNonQuery() != 1)
            {
                throw new InvalidOperationException("Operation changed during verification. Records were preserved.");
            }

            using var remove = connection.CreateCommand();
            remove.Transaction = transaction;
            remove.CommandText = "DELETE FROM LockerOperations WHERE OperationId = $operation";
            remove.Parameters.AddWithValue("$operation", operation.OperationId);
            remove.ExecuteNonQuery();
            transaction.Commit();
        }

        internal static void BeginRecoveryAttempt(LockerRecoveryAttempt attempt, LockerModel expected, string connectionString)
        {
            using var connection = OpenConnection(connectionString);
            using var transaction = connection.BeginTransaction(deferred: false);
            var destination = expected.Copy();
            destination.LockerLocation = attempt.DestinationPath;
            ValidatePathOwnership(connection, transaction, destination);
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
            INSERT INTO LockerRecoveryAttempts (AttemptId, OperationId, LockerGuid, ArchivePath, ArchiveSha256, DestinationPath, StagingPath, State)
            SELECT $attempt, $operation, $guid, $archive, $sha, $destination, $staging, 'Restoring'
            WHERE EXISTS (SELECT 1 FROM LockerOperations WHERE OperationId = $operation AND LockerGuid = $guid)
                AND EXISTS (SELECT 1 FROM Lockers WHERE Guid = $guid AND Revision = $revision)
            """;
            command.Parameters.AddWithValue("$attempt", attempt.AttemptId);
            command.Parameters.AddWithValue("$operation", attempt.OperationId);
            command.Parameters.AddWithValue("$guid", attempt.LockerGuid);
            command.Parameters.AddWithValue("$archive", attempt.ArchivePath);
            command.Parameters.AddWithValue("$sha", attempt.ArchiveSha256);
            command.Parameters.AddWithValue("$destination", attempt.DestinationPath);
            command.Parameters.AddWithValue("$staging", attempt.StagingPath);
            command.Parameters.AddWithValue("$revision", expected.Revision);
            if (command.ExecuteNonQuery() != 1)
            {
                throw new InvalidOperationException("Locker or journal changed before recovery. Reload recovery-list.");
            }

            transaction.Commit();
        }

        internal static void CommitRecoveredOperation(LockerRecoveryAttempt attempt, LockerModel restored, string connectionString)
        {
            using var connection = OpenConnection(connectionString);
            using var transaction = connection.BeginTransaction(deferred: false);
            ValidatePathOwnership(connection, transaction, restored);
            var nextRevision = checked(restored.Revision + 1);
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
            UPDATE Lockers SET LockerLocation = $destination, Password = $password, IsLocked = 0,
                StorageFormatVersion = NULL, LockedArchiveSha256 = NULL, LockedAtUtc = NULL,
                Revision = $nextRevision, UpdatedAt = datetime('now')
            WHERE Guid = $guid AND Revision = $revision
                AND EXISTS (SELECT 1 FROM LockerOperations WHERE OperationId = $operation AND LockerGuid = $guid)
                AND EXISTS (SELECT 1 FROM LockerRecoveryAttempts WHERE AttemptId = $attempt AND State = 'Restoring');
            """;
            update.Parameters.AddWithValue("$destination", restored.LockerLocation);
            update.Parameters.AddWithValue("$password", restored.Password);
            update.Parameters.AddWithValue("$nextRevision", nextRevision);
            update.Parameters.AddWithValue("$guid", restored.Guid);
            update.Parameters.AddWithValue("$revision", restored.Revision);
            update.Parameters.AddWithValue("$operation", attempt.OperationId);
            update.Parameters.AddWithValue("$attempt", attempt.AttemptId);
            if (update.ExecuteNonQuery() != 1)
            {
                throw new InvalidOperationException("Recovery state changed. Recovered files and journals were preserved.");
            }

            using var finish = connection.CreateCommand();
            finish.Transaction = transaction;
            finish.CommandText = """
            INSERT INTO LockerOperationHistory
                (OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson, OutputTreeSha256, Resolution)
            SELECT OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson, OutputTreeSha256, 'RecoveredToNewLocation'
            FROM LockerOperations WHERE OperationId = $operation;
            DELETE FROM LockerOperations WHERE OperationId = $operation;
            UPDATE LockerRecoveryAttempts SET State = 'Committed' WHERE AttemptId = $attempt;
            UPDATE LockerRecoveryAttempts SET State = 'Superseded'
                WHERE OperationId = $operation AND AttemptId <> $attempt AND State = 'Restoring';
            """;
            finish.Parameters.AddWithValue("$operation", attempt.OperationId);
            finish.Parameters.AddWithValue("$attempt", attempt.AttemptId);
            finish.ExecuteNonQuery();
            transaction.Commit();
            restored.Revision = nextRevision;
        }
    }
}

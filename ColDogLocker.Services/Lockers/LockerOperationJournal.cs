using System.Text.Json;
using System.Text.Json.Nodes;
using ColDogStudios.ColDogLocker.Core.Models;
using Microsoft.Data.Sqlite;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public sealed record PendingLockerOperation(string OperationId, string LockerGuid, string Kind,
        string Phase, string SourcePath, string TargetPath, string StagingPath, string BeforeJson, string? OutputTreeSha256 = null);

    internal sealed class LockerOperationJournal(string connectionString)
    {
        private string? _operationId;
        private string _phase = "Preparing";

        internal void Begin(LockerModel locker, string kind, string target, string staging)
        {
            if (_operationId != null)
            {
                throw new InvalidOperationException("Journal already has an active operation.");
            }

            _phase = "Preparing";
            var id = Guid.NewGuid().ToString("N");
            LockerRepository.BeginJournal(new PendingLockerOperation(id, locker.Guid, kind, _phase,
                locker.LockerLocation, target, staging, JsonSerializer.Serialize(locker)), locker.Revision, connectionString);
            _operationId = id;
        }

        internal void Advance(string phase, string? outputTreeSha256 = null)
        {
            LockerRepository.AdvanceJournal(_operationId ?? throw new InvalidOperationException("Journal not started."), _phase, phase, connectionString, outputTreeSha256);
            _phase = phase;
        }

        internal void End()
        {
            if (_operationId != null)
            {
                LockerRepository.EndJournal(_operationId, connectionString);
                _operationId = null;
            }
        }
    }

    public static partial class LockerRepository
    {
        internal static LockerOperationJournal CreateOperationJournal() => new(_connectionString);

        public static IReadOnlyList<PendingLockerOperation> GetPendingOperations() => GetPendingOperations(_connectionString);

        internal static IReadOnlyList<PendingLockerOperation> GetPendingOperations(string connectionString)
        {
            using var connection = OpenConnection(connectionString);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson, OutputTreeSha256 FROM LockerOperations ORDER BY OperationId";
            using var reader = command.ExecuteReader();
            var operations = new List<PendingLockerOperation>();
            while (reader.Read())
            {
                operations.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8)));
            }

            return operations;
        }

        public static IReadOnlyList<PendingLockerOperation> GetOperationHistory() => GetOperationHistory(_connectionString);

        internal static IReadOnlyList<PendingLockerOperation> GetOperationHistory(string connectionString)
        {
            using var connection = OpenConnection(connectionString);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson, OutputTreeSha256 FROM LockerOperationHistory ORDER BY ResolvedAtUtc, OperationId";
            using var reader = command.ExecuteReader();
            var operations = new List<PendingLockerOperation>();
            while (reader.Read())
            {
                operations.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8)));
            }

            return operations;
        }

        public static PendingLockerOperation CancelPreparedOperation(string operationId) => CancelPreparedOperation(operationId, _connectionString);

        internal static PendingLockerOperation CancelPreparedOperation(string operationId, string connectionString)
        {
            var original = GetPendingOperations(connectionString).SingleOrDefault(item => item.OperationId == operationId)
                ?? throw new InvalidOperationException("Pending operation not found.");
            using var lease = LockerOperationLease.Acquire(original.LockerGuid);
            using var connection = OpenConnection(connectionString);
            using var transaction = connection.BeginTransaction(deferred: false);
            using var query = connection.CreateCommand();
            query.Transaction = transaction;
            query.CommandText = "SELECT Phase FROM LockerOperations WHERE OperationId = $id AND LockerGuid = $guid";
            query.Parameters.AddWithValue("$id", operationId);
            query.Parameters.AddWithValue("$guid", original.LockerGuid);
            if (query.ExecuteScalar() as string != original.Phase)
            {
                throw new InvalidOperationException("Operation changed. Reload recovery-list before retrying.");
            }

            var safePhase = (original.Kind == "Lock" && original.Phase is "Preparing" or "ArchiveReady") ||
                (original.Kind == "Unlock" && original.Phase == "Preparing");
            if (!safePhase || !Directory.Exists(original.SourcePath) || Path.Exists(original.TargetPath))
            {
                throw new InvalidOperationException("Cannot cancel this operation without verifying recovered data. All records and files were preserved.");
            }

            using var state = connection.CreateCommand();
            state.Transaction = transaction;
            state.CommandText = "SELECT Guid, LockerName, Password, LockerLocation, IsLocked, StorageFormatVersion, LockedArchiveSha256, LockedAtUtc, Revision FROM Lockers WHERE Guid = $guid";
            state.Parameters.AddWithValue("$guid", original.LockerGuid);
            using (var reader = state.ExecuteReader())
            {
                if (!reader.Read() || !JsonNode.DeepEquals(JsonNode.Parse(original.BeforeJson), JsonSerializer.SerializeToNode(ReadLocker(reader))))
                {
                    throw new InvalidOperationException("Locker metadata changed after the operation started. Recovery records were preserved.");
                }
            }

            using var archive = connection.CreateCommand();
            archive.Transaction = transaction;
            archive.CommandText = """
                INSERT INTO LockerOperationHistory
                    (OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson, OutputTreeSha256, Resolution)
                SELECT OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson, OutputTreeSha256, 'CancelledBeforePublication'
                FROM LockerOperations WHERE OperationId = $id;
                DELETE FROM LockerOperations WHERE OperationId = $id;
                """;
            archive.Parameters.AddWithValue("$id", operationId);
            archive.ExecuteNonQuery();
            transaction.Commit();
            return original;
        }

        internal static void BeginJournal(PendingLockerOperation operation, long revision, string connectionString)
        {
            using var connection = OpenConnection(connectionString);
            using var transaction = connection.BeginTransaction(deferred: false);
            EnsureNoPendingOperation(connection, transaction, operation.LockerGuid);
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
            INSERT INTO LockerOperations (OperationId, LockerGuid, Kind, Phase, SourcePath, TargetPath, StagingPath, BeforeJson)
            SELECT $id, $guid, $kind, $phase, $source, $target, $staging, $before
            WHERE EXISTS (SELECT 1 FROM Lockers WHERE Guid = $guid AND Revision = $revision)
            """;
            command.Parameters.AddWithValue("$id", operation.OperationId);
            command.Parameters.AddWithValue("$guid", operation.LockerGuid);
            command.Parameters.AddWithValue("$kind", operation.Kind);
            command.Parameters.AddWithValue("$phase", operation.Phase);
            command.Parameters.AddWithValue("$source", operation.SourcePath);
            command.Parameters.AddWithValue("$target", operation.TargetPath);
            command.Parameters.AddWithValue("$staging", operation.StagingPath);
            command.Parameters.AddWithValue("$before", operation.BeforeJson);
            command.Parameters.AddWithValue("$revision", revision);
            if (command.ExecuteNonQuery() != 1)
            {
                throw new InvalidOperationException("Locker changed before operation journal creation. Reload it before retrying.");
            }

            transaction.Commit();
        }

        internal static void AdvanceJournal(string operationId, string expectedPhase, string phase, string connectionString, string? outputTreeSha256 = null)
        {
            using var connection = OpenConnection(connectionString);
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE LockerOperations SET Phase = $phase, OutputTreeSha256 = COALESCE($tree, OutputTreeSha256) WHERE OperationId = $id AND Phase = $expected";
            command.Parameters.AddWithValue("$phase", phase);
            command.Parameters.AddWithValue("$id", operationId);
            command.Parameters.AddWithValue("$expected", expectedPhase);
            command.Parameters.AddWithValue("$tree", (object?)outputTreeSha256 ?? DBNull.Value);
            if (command.ExecuteNonQuery() != 1)
            {
                throw new InvalidOperationException("Operation journal changed unexpectedly. Preserve all recovery files.");
            }
        }

        internal static void EndJournal(string operationId, string connectionString)
        {
            using var connection = OpenConnection(connectionString);
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM LockerOperations WHERE OperationId = $id";
            command.Parameters.AddWithValue("$id", operationId);
            command.ExecuteNonQuery();
        }

        private static void EnsureNoPendingOperation(SqliteConnection connection, SqliteTransaction? transaction, string guid)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT Kind, Phase FROM LockerOperations WHERE LockerGuid = $guid";
            command.Parameters.AddWithValue("$guid", guid);
            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                throw new InvalidOperationException($"Unfinished {reader.GetString(0)} operation ({reader.GetString(1)}) requires recovery. Run 'cdlocker recovery-list' to locate its files. Further changes are blocked.");
            }
        }
    }
}

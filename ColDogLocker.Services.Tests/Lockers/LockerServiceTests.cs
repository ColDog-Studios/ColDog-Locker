/*
 **  Copyright (C) 2026 ColDog Studios
 **
 **  This program is free software: you can redistribute it and/or modify
 **  it under the terms of the GNU General Public License as published by
 **  the Free Software Foundation, either version 3 of the License, or
 **  (at your option) any later version.
 **
 **  This program is distributed in the hope that it will be useful,
 **  but WITHOUT ANY WARRANTY; without even the implied warranty of
 **  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 **  GNU General Public License for more details.
 **
 **  You should have received a copy of the GNU General Public License
 **  long with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

using System.Security.Cryptography;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;
using ColDogStudios.ColDogLocker.Services.Security;
using ColDogStudios.ColDogLocker.Services.Tests.FileSystem;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public class LockerServiceTests
    {
        [Theory]
        [InlineData("none")]
        [InlineData("content")]
        [InlineData("rename")]
        [InlineData("missing")]
        [InlineData("extra-directory")]
        public void FinishCommittedUnlock_VerifiesPublishedTreeAfterArchiveRemoval(string mutation)
        {
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var source = Directory.CreateDirectory(Path.Join(workspace.Path, "Vault")).FullName;
            Directory.CreateDirectory(Path.Join(source, "empty"));
            var file = Path.Join(source, "original.txt");
            File.WriteAllText(file, "original contents");
            var connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = Path.Join(workspace.Path, "metadata.db") }.ToString();
            LockerRepository.InitializeDatabase(connectionString);
            const string Password = "Violet!River9Moon";
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), source);
            LockerRepository.InsertLocker(locker, connectionString);
            LockerService.Lock(locker, Password,
                value => LockerRepository.UpdateLocker(value, connectionString, commitOperation: true),
                path => Directory.Delete(path, true), journal: new LockerOperationJournal(connectionString));
            var lockedDirectory = locker.LockerLocation;
            Assert.Throws<IOException>(() => LockerService.Unlock(locker, Password, value =>
            {
                LockerRepository.UpdateLocker(value, connectionString, commitOperation: true);
                throw new IOException("Injected interruption after metadata commit");
            }, journal: new LockerOperationJournal(connectionString)));
            var operation = Assert.Single(LockerRepository.GetPendingOperations(connectionString));
            Assert.Equal("MetadataCommitted", operation.Phase);
            Assert.NotNull(operation.OutputTreeSha256);
            File.SetAttributes(LockerArchiveService.GetArchivePath(lockedDirectory), FileAttributes.Normal);
            File.SetAttributes(lockedDirectory, FileAttributes.Normal);
            Directory.Delete(lockedDirectory, true);
            switch (mutation)
            {
                case "content":
                    File.WriteAllText(file, "modified contents");
                    break;
                case "rename":
                    File.Move(file, Path.Join(source, "renamed.txt"));
                    break;
                case "missing":
                    File.Delete(file);
                    break;
                case "extra-directory":
                    Directory.CreateDirectory(Path.Join(source, "new-empty"));
                    break;
            }

            var digestBeforeFinish = LockerTreeDigest.Compute(source);
            if (mutation == "none")
            {
                LockerRecoveryService.FinishCommittedOperation(operation.OperationId, connectionString);
                Assert.Empty(LockerRepository.GetPendingOperations(connectionString));
                var history = Assert.Single(LockerRepository.GetOperationHistory(connectionString));
                Assert.Equal(operation.OutputTreeSha256, history.OutputTreeSha256);
                LockerRepository.EnsureCurrent(locker, connectionString);
            }
            else
            {
                Assert.Throws<InvalidDataException>(() => LockerRecoveryService.FinishCommittedOperation(operation.OperationId, connectionString));
                Assert.Single(LockerRepository.GetPendingOperations(connectionString));
                Assert.Empty(LockerRepository.GetOperationHistory(connectionString));
            }

            Assert.Equal(digestBeforeFinish, LockerTreeDigest.Compute(source));
            Assert.Equal(locker.Revision, LockerRepository.GetLockerByGuid(locker.Guid, connectionString)!.Revision);
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void FinishCommittedLock_RequiresUnchangedArchive(bool tamper)
        {
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var source = Directory.CreateDirectory(Path.Join(workspace.Path, "Vault")).FullName;
            File.WriteAllText(Path.Join(source, "original.txt"), "original contents");
            var connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = Path.Join(workspace.Path, "metadata.db") }.ToString();
            LockerRepository.InitializeDatabase(connectionString);
            const string Password = "Violet!River9Moon";
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), source);
            LockerRepository.InsertLocker(locker, connectionString);
            Assert.Throws<LockerRecoveryRequiredException>(() => LockerService.Lock(locker, Password, value =>
            {
                LockerRepository.UpdateLocker(value, connectionString, commitOperation: true);
                throw new IOException("Injected interruption after metadata commit");
            }, path => Directory.Delete(path, true), journal: new LockerOperationJournal(connectionString)));
            var operation = Assert.Single(LockerRepository.GetPendingOperations(connectionString));
            Assert.Equal("MetadataCommitted", operation.Phase);
            var archive = LockerArchiveService.GetArchivePath(operation.TargetPath);
            if (tamper)
            {
                File.SetAttributes(archive, FileAttributes.Normal);
                using var stream = new FileStream(archive, FileMode.Append);
                stream.WriteByte(42);
            }

            var hash = LockerArchiveService.ComputeSha256(archive);
            if (tamper)
            {
                Assert.Throws<InvalidDataException>(() => LockerRecoveryService.FinishCommittedOperation(operation.OperationId, connectionString));
                Assert.Single(LockerRepository.GetPendingOperations(connectionString));
            }
            else
            {
                LockerRecoveryService.FinishCommittedOperation(operation.OperationId, connectionString);
                Assert.Empty(LockerRepository.GetPendingOperations(connectionString));
                Assert.Equal(operation.OperationId, Assert.Single(LockerRepository.GetOperationHistory(connectionString)).OperationId);
            }

            Assert.Equal(hash, LockerArchiveService.ComputeSha256(archive));
            Assert.False(Directory.Exists(source));
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }

        [Fact]
        public void RecoverOperation_RepairsRegistrationAfterPartialDeletionAndRetainsOriginalArtifacts()
        {
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var source = Directory.CreateDirectory(Path.Join(workspace.Path, "Vault")).FullName;
            var connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = Path.Join(workspace.Path, "metadata.db") }.ToString();
            LockerRepository.InitializeDatabase(connectionString);
            const string Password = "Violet!River9Moon";
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), source);
            File.WriteAllText(Path.Join(source, "first.txt"), "first original");
            File.WriteAllText(Path.Join(source, "second.txt"), "second original");
            LockerRepository.InsertLocker(locker, connectionString);
            var failure = Assert.Throws<LockerRecoveryRequiredException>(() => LockerService.Lock(locker, Password,
                value => LockerRepository.UpdateLocker(value, connectionString, commitOperation: true),
                path =>
                {
                    File.Delete(Path.Join(path, "first.txt"));
                    throw new IOException("Injected partial deletion");
                },
                value => LockerRepository.EnsureCurrent(value, connectionString), new LockerOperationJournal(connectionString)));
            var operation = Assert.Single(LockerRepository.GetPendingOperations(connectionString));
            var archiveHash = LockerArchiveService.ComputeSha256(failure.ArchivePath);
            var destination = Path.Join(workspace.Path, "recovered", "Vault");
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => LockerRecoveryService.RecoverOperation(
                operation.OperationId, failure.ArchivePath, destination, "wrong", connectionString));
            Assert.False(Directory.Exists(destination));
            Assert.Single(LockerRepository.GetPendingOperations(connectionString));
            var restored = LockerRecoveryService.RecoverOperation(operation.OperationId, failure.ArchivePath, destination, Password, connectionString);
            Assert.Equal("first original", File.ReadAllText(Path.Join(destination, "first.txt")));
            Assert.Equal("second original", File.ReadAllText(Path.Join(destination, "second.txt")));
            Assert.Equal("second original", File.ReadAllText(Path.Join(source, "second.txt")));
            Assert.Equal(archiveHash, LockerArchiveService.ComputeSha256(failure.ArchivePath));
            Assert.Empty(LockerRepository.GetPendingOperations(connectionString));
            Assert.Equal(operation.OperationId, Assert.Single(LockerRepository.GetOperationHistory(connectionString)).OperationId);
            Assert.Single(LockerRepository.GetRecoveryAttempts(connectionString), attempt => attempt.State == "Committed");
            Assert.Single(LockerRepository.GetRecoveryAttempts(connectionString), attempt => attempt.State == "Superseded");
            var persisted = LockerRepository.GetLockerByGuid(locker.Guid, connectionString)!;
            Assert.Equal(destination, persisted.LockerLocation);
            Assert.False(persisted.IsLocked);
            Assert.Equal(1, persisted.Revision);
            Assert.True(EncryptionHelper.VerifyPassword(Password, persisted.Password));
            LockerRepository.EnsureCurrent(restored, connectionString);
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }

        [Fact]
        public void RecoverOperation_DiskFullRetainsArchiveJournalAndPartialStaging()
        {
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var source = Directory.CreateDirectory(Path.Join(workspace.Path, "Vault")).FullName;
            var connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = Path.Join(workspace.Path, "metadata.db") }.ToString();
            LockerRepository.InitializeDatabase(connectionString);
            const string Password = "Violet!River9Moon";
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), source);
            File.WriteAllText(Path.Join(source, "first.txt"), "first original");
            File.WriteAllText(Path.Join(source, "second.txt"), "second original");
            LockerRepository.InsertLocker(locker, connectionString);

            var failure = Assert.Throws<LockerRecoveryRequiredException>(() => LockerService.Lock(
                locker,
                Password,
                value => LockerRepository.UpdateLocker(value, connectionString, commitOperation: true),
                path =>
                {
                    File.Delete(Path.Join(path, "first.txt"));
                    throw new IOException("Injected partial deletion");
                },
                value => LockerRepository.EnsureCurrent(value, connectionString),
                new LockerOperationJournal(connectionString)));
            var archiveHash = LockerArchiveService.ComputeSha256(failure.ArchivePath);
            var operation = Assert.Single(LockerRepository.GetPendingOperations(connectionString));
            var destination = Path.Join(workspace.Path, "recovered", "Vault");

            var diskFull = Assert.Throws<IOException>(() => LockerRecoveryService.RecoverOperation(
                operation.OperationId,
                failure.ArchivePath,
                destination,
                Password,
                connectionString,
                (_, staging, _, _) =>
                {
                    Directory.CreateDirectory(staging);
                    File.WriteAllText(Path.Join(staging, "partial.txt"), "partially restored plaintext");
                    throw new IOException("No space left on device");
                }));

            Assert.Contains("No space left", diskFull.Message);
            Assert.False(Directory.Exists(destination));
            Assert.Equal(archiveHash, LockerArchiveService.ComputeSha256(failure.ArchivePath));
            Assert.Equal("second original", File.ReadAllText(Path.Join(source, "second.txt")));
            Assert.Equal(operation.OperationId, Assert.Single(LockerRepository.GetPendingOperations(connectionString)).OperationId);
            var attempt = Assert.Single(LockerRepository.GetRecoveryAttempts(connectionString));
            Assert.Equal("Restoring", attempt.State);
            Assert.Equal("partially restored plaintext", File.ReadAllText(Path.Join(attempt.StagingPath, "partial.txt")));

            var restored = LockerRecoveryService.RecoverOperation(
                operation.OperationId, failure.ArchivePath, destination, Password, connectionString);
            Assert.Equal("first original", File.ReadAllText(Path.Join(restored.LockerLocation, "first.txt")));
            Assert.Equal("second original", File.ReadAllText(Path.Join(restored.LockerLocation, "second.txt")));
            Assert.Equal(archiveHash, LockerArchiveService.ComputeSha256(failure.ArchivePath));
            Assert.Empty(LockerRepository.GetPendingOperations(connectionString));
            Assert.Single(LockerRepository.GetRecoveryAttempts(connectionString), item => item.State == "Committed");
            Assert.Single(LockerRepository.GetRecoveryAttempts(connectionString), item => item.State == "Superseded");
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }

        [Fact]
        public void Lock_StaleRevisionFailsBeforeArchiveCreationOrSourceDeletion()
        {
            using var directory = TestDirectory.CreateAllowed("Vault");
            const string Password = "Violet!River9Moon";
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), directory.Path);
            File.WriteAllText(Path.Join(directory.Path, "original.txt"), "untouched");
            var parent = Path.GetDirectoryName(directory.Path)!;
            var connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = Path.Join(parent, "metadata.db") }.ToString();
            LockerRepository.InitializeDatabase(connectionString);
            LockerRepository.InsertLocker(locker, connectionString);
            var stale = locker.Copy();
            locker.Password = "new verifier";
            LockerRepository.UpdateLocker(locker, connectionString);

            Assert.Throws<InvalidOperationException>(() => LockerService.Lock(stale, Password,
                _ => throw new Exception("Persistence must not run"),
                _ => throw new Exception("Deletion must not run"),
                expected => LockerRepository.EnsureCurrent(expected, connectionString)));
            Assert.Equal("untouched", File.ReadAllText(Path.Join(directory.Path, "original.txt")));
            Assert.Empty(Directory.EnumerateDirectories(parent, "*.locking"));
            Assert.False(Directory.Exists(Path.Join(parent, ".Vault")));
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }

        [Theory]
        [InlineData("create")]
        [InlineData("overwrite")]
        [InlineData("truncate")]
        [InlineData("rename")]
        [InlineData("delete")]
        public void Lock_SourceMutationBeforeClaimAbortsAndPreservesChangedTree(string mutation)
        {
            using var directory = TestDirectory.CreateAllowed("Vault");
            const string Password = "Violet!River9Moon";
            var source = directory.Path;
            var original = Path.Join(source, "original.txt");
            File.WriteAllText(original, "AAAA");
            var originalModified = File.GetLastWriteTimeUtc(original);
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), source);
            var persisted = false;
            var deleted = false;

            var error = Assert.Throws<IOException>(() => LockerService.Lock(
                locker,
                Password,
                _ => persisted = true,
                _ => deleted = true,
                beforeSourceClaim: path =>
                {
                    var file = Path.Join(path, "original.txt");
                    switch (mutation)
                    {
                        case "create":
                            File.WriteAllText(Path.Join(path, "late.txt"), "late bytes");
                            break;
                        case "overwrite":
                            File.WriteAllText(file, "BBBB");
                            File.SetLastWriteTimeUtc(file, originalModified);
                            break;
                        case "truncate":
                            using (var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.Read))
                            {
                                stream.SetLength(1);
                            }

                            break;
                        case "rename":
                            File.Move(file, Path.Join(path, "renamed.txt"));
                            break;
                        case "delete":
                            File.Delete(file);
                            break;
                    }
                }));

            Assert.IsNotType<LockerRecoveryRequiredException>(error);
            Assert.Contains("changed", error.Message, StringComparison.OrdinalIgnoreCase);
            Assert.False(persisted);
            Assert.False(deleted);
            Assert.True(Directory.Exists(source));
            Assert.False(Directory.Exists(Path.Join(Path.GetDirectoryName(source)!, ".Vault")));
            Assert.Empty(Directory.EnumerateDirectories(Path.GetDirectoryName(source)!, "*.locking"));
            switch (mutation)
            {
                case "create":
                    Assert.Equal("AAAA", File.ReadAllText(original));
                    Assert.Equal("late bytes", File.ReadAllText(Path.Join(source, "late.txt")));
                    break;
                case "overwrite":
                    Assert.Equal("BBBB", File.ReadAllText(original));
                    break;
                case "truncate":
                    Assert.Equal("A", File.ReadAllText(original));
                    break;
                case "rename":
                    Assert.False(File.Exists(original));
                    Assert.Equal("AAAA", File.ReadAllText(Path.Join(source, "renamed.txt")));
                    break;
                case "delete":
                    Assert.False(File.Exists(original));
                    break;
            }
        }

        [Fact]
        public void Lock_ParentReplacementBeforeClaimAbortsWithoutDeletingEitherTree()
        {
            using var directory = TestDirectory.CreateAllowed("Vault");
            const string Password = "Violet!River9Moon";
            var source = directory.Path;
            File.WriteAllText(Path.Join(source, "original.txt"), "original bytes");
            var parent = Path.GetDirectoryName(source)!;
            var displacedParent = parent + "-displaced";
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), source);
            var deletionReached = false;

            try
            {
                Assert.Throws<IOException>(() => LockerService.Lock(
                    locker,
                    Password,
                    _ => throw new InvalidOperationException("Persistence must not run."),
                    _ => deletionReached = true,
                    beforeSourceClaim: _ =>
                    {
                        Directory.Move(parent, displacedParent);
                        Directory.CreateDirectory(source);
                        File.WriteAllText(Path.Join(source, "replacement.txt"), "replacement bytes");
                    }));

                Assert.False(deletionReached);
                Assert.Equal("replacement bytes", File.ReadAllText(Path.Join(source, "replacement.txt")));
                Assert.Equal("original bytes", File.ReadAllText(Path.Join(displacedParent, "Vault", "original.txt")));
            }
            finally
            {
                if (Directory.Exists(parent))
                {
                    Directory.Delete(parent, recursive: true);
                }

                if (Directory.Exists(displacedParent))
                {
                    Directory.Move(displacedParent, parent);
                }
            }
        }

        [Fact]
        public void Lock_CancellationDuringArchivePreservesSourceAndSkipsDeletion()
        {
            using var directory = TestDirectory.CreateAllowed("Vault");
            const string Password = "Violet!River9Moon";
            File.WriteAllBytes(Path.Join(directory.Path, "large.bin"), RandomNumberGenerator.GetBytes(200000));
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), directory.Path);
            using var cancellation = new CancellationTokenSource();
            var updates = new List<LockerOperationProgress>();
            var progress = new InlineProgress<LockerOperationProgress>(update =>
            {
                updates.Add(update);
                if (update.Stage == "Archiving" && update.Message.StartsWith("Archiving item", StringComparison.Ordinal))
                {
                    cancellation.Cancel();
                }
            });
            var deletionReached = false;

            Assert.Throws<OperationCanceledException>(() => LockerService.Lock(
                locker,
                Password,
                _ => throw new InvalidOperationException("Persistence must not run."),
                _ => deletionReached = true,
                progress: progress,
                cancellationToken: cancellation.Token));

            Assert.False(deletionReached);
            Assert.True(File.Exists(Path.Join(directory.Path, "large.bin")));
            Assert.False(Directory.Exists(Path.Join(Path.GetDirectoryName(directory.Path)!, ".Vault")));
            Assert.Empty(Directory.EnumerateDirectories(Path.GetDirectoryName(directory.Path)!, "*.locking"));
            Assert.Contains(updates, update => update.CanCancel);
        }

        [Fact]
        public void Lock_CancellationRequestedAfterPublicationBoundaryCompletesOperation()
        {
            using var directory = TestDirectory.CreateAllowed("Vault");
            const string Password = "Violet!River9Moon";
            File.WriteAllText(Path.Join(directory.Path, "secret.txt"), "classified");
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), directory.Path);
            using var cancellation = new CancellationTokenSource();
            var updates = new List<LockerOperationProgress>();
            var progress = new InlineProgress<LockerOperationProgress>(update =>
            {
                updates.Add(update);
                if (update.Stage == "Publishing")
                {
                    Assert.False(update.CanCancel);
                    cancellation.Cancel();
                }
            });

            LockerService.Lock(
                locker,
                Password,
                _ => { },
                path => Directory.Delete(path, true),
                progress: progress,
                cancellationToken: cancellation.Token);

            Assert.True(cancellation.IsCancellationRequested);
            Assert.True(locker.IsLocked);
            Assert.True(File.Exists(LockerArchiveService.GetArchivePath(locker.LockerLocation)));
            Assert.Contains(updates, update => update.Stage == "Completed" && !update.CanCancel);
        }

        [UnixFact]
        public void Lock_ReplacedSourceSentinelPreservesReplacementAndRecoveryArchive()
        {
            using var directory = TestDirectory.CreateAllowed("Vault");
            const string Password = "Violet!River9Moon";
            var source = directory.Path;
            File.WriteAllText(Path.Join(source, "original.txt"), "original bytes");
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), source);

            var failure = Assert.Throws<LockerRecoveryRequiredException>(() => LockerService.Lock(
                locker,
                Password,
                _ => throw new InvalidOperationException("Persistence must not run."),
                path => Directory.Delete(path, true),
                afterSourceClaim: sentinelPath =>
                {
                    File.Delete(sentinelPath);
                    File.WriteAllText(sentinelPath, "concurrent replacement");
                }));

            Assert.Equal("concurrent replacement", File.ReadAllText(source));
            Assert.True(File.Exists(failure.ArchivePath));
            var recovered = Path.Join(Path.GetDirectoryName(source)!, "recovered");
            LockerRecoveryService.RecoverArchive(failure.ArchivePath, recovered, Password);
            Assert.Equal("original bytes", File.ReadAllText(Path.Join(recovered, "original.txt")));
            Assert.False(locker.IsLocked);
        }

        [Theory]
        [InlineData("partial-delete")]
        [InlineData("complete-delete")]
        [InlineData("persistence")]
        [InlineData("destination-collision")]
        public void Lock_FailureAfterDeletionRetainsACompleteRecoverableArchive(string failure)
        {
            using var directory = TestDirectory.CreateAllowed("Vault");
            const string Password = "Violet!River9Moon";
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(Password), directory.Path);
            File.WriteAllText(Path.Join(directory.Path, "first.txt"), "first complete original");
            File.WriteAllText(Path.Join(directory.Path, "second.txt"), "second complete original");
            var parent = Path.GetDirectoryName(directory.Path)!;
            var target = Path.Join(parent, ".Vault");
            var persisted = false;

            var error = Assert.Throws<LockerRecoveryRequiredException>(() => LockerService.Lock(locker, Password,
                _ =>
                {
                    if (failure == "persistence")
                    {
                        throw new IOException("Injected database failure");
                    }

                    persisted = true;
                },
                source =>
                {
                    File.Delete(Path.Join(source, "first.txt"));
                    if (failure == "partial-delete")
                    {
                        throw new IOException("Injected deletion failure after one file");
                    }

                    Directory.Delete(source, true);
                    if (failure == "complete-delete")
                    {
                        throw new IOException("Injected failure after removing root");
                    }

                    if (failure == "destination-collision")
                    {
                        Directory.CreateDirectory(target);
                        File.WriteAllText(Path.Join(target, "unrelated.txt"), "belongs to another operation");
                    }
                }));

            Assert.False(persisted);
            Assert.False(locker.IsLocked);
            Assert.Equal(directory.Path, locker.LockerLocation);
            Assert.True(File.Exists(error.ArchivePath));
            Assert.Contains(error.ArchivePath, error.Message);
            var recovered = Path.Join(parent, "recovered");
            LockerRecoveryService.RecoverArchive(error.ArchivePath, recovered, Password);
            Assert.Equal("first complete original", File.ReadAllText(Path.Join(recovered, "first.txt")));
            Assert.Equal("second complete original", File.ReadAllText(Path.Join(recovered, "second.txt")));
            if (failure == "partial-delete")
            {
                Assert.Equal("second complete original", File.ReadAllText(Path.Join(directory.Path, "second.txt")));
            }

            if (failure == "destination-collision")
            {
                Assert.Equal("belongs to another operation", File.ReadAllText(Path.Join(target, "unrelated.txt")));
            }
        }

        [Fact]
        public void ChangePassword_PersistenceFailureDoesNotChangeCurrentVerifier()
        {
            using var directory = TestDirectory.CreateAllowed("ChangeFailure");
            var original = EncryptionHelper.HashPassword("Violet!River9Moon");
            var locker = new LockerModel("ChangeFailure", original, directory.Path);
            Assert.Throws<IOException>(() => LockerService.ChangePassword(locker,
                "Violet!River9Moon", "Copper!River8Moon", _ => throw new IOException("Disk full")));
            Assert.Equal(original, locker.Password);
        }

        [Fact]
        public void Lock_UnsupportedVerifierPreservesOriginals()
        {
            using var directory = TestDirectory.CreateAllowed("Legacy");
            const string Legacy = "$2a$04$b9STetOS4I7Zinp/E655pO6q0DttM8rC0frGST6cq81p0LIJsCLBC";
            var locker = new LockerModel("Legacy", Legacy, directory.Path);
            File.WriteAllText(Path.Join(directory.Path, "original.txt"), "keep");
            Assert.Throws<InvalidDataException>(() => LockerService.Lock(locker, "Legacy!Pass582"));
            Assert.Equal("keep", File.ReadAllText(Path.Join(directory.Path, "original.txt")));
        }

        [Fact]
        public void Snapshots_DoNotAllowCallersToMutateSharedLockerState()
        {
            var locker = new LockerModel("Original", "hash", "/example");
            LockerService.ReplaceLockersForTesting([locker]);
            try
            {
                locker.LockerName = "Changed";
                LockerService.GetLockersSnapshot()[0].LockerName = "AlsoChanged";
                Assert.Equal("Original", LockerService.FindLockerByGuid(locker.Guid)!.LockerName);
            }
            finally
            {
                LockerService.ClearLockersForTesting();
            }
        }

        [Fact]
        public void LoadLockers_FailedReloadPreservesExistingStateAndSurfacesError()
        {
            var existing = new LockerModel("Existing", "hash", "/existing");
            LockerService.ReplaceLockersForTesting([existing]);
            try
            {
                var error = Assert.Throws<IOException>(() => LockerService.LoadLockers(
                    () => throw new IOException("registry unavailable"),
                    () => throw new InvalidOperationException("Pending-operation read must not run")));

                Assert.Contains("registry unavailable", error.Message);
                Assert.Equal(existing.Guid, Assert.Single(LockerService.GetLockersSnapshot()).Guid);
            }
            finally
            {
                LockerService.ClearLockersForTesting();
            }
        }

        [Fact]
        public void LoadLockers_FailedPendingOperationReadDoesNotPublishPartialReload()
        {
            var existing = new LockerModel("Existing", "hash", "/existing");
            var replacement = new LockerModel("Replacement", "hash", "/replacement");
            LockerService.ReplaceLockersForTesting([existing]);
            try
            {
                Assert.Throws<IOException>(() => LockerService.LoadLockers(
                    () => [replacement],
                    () => throw new IOException("journal unavailable")));

                Assert.Equal(existing.Guid, Assert.Single(LockerService.GetLockersSnapshot()).Guid);
            }
            finally
            {
                LockerService.ClearLockersForTesting();
            }
        }

        [Theory]
        [InlineData("Renamed", false)]
        [InlineData("Locked", true)]
        public void UpdateLockedMetadata_RejectsChangesWithoutMutatingModel(string name, bool changeLocation)
        {
            var location = Path.Join(Path.GetTempPath(), "Locked");
            var locker = new LockerModel("Locked", "hash", location) { IsLocked = true };

            Assert.Throws<InvalidOperationException>(() =>
                LockerService.UpdateLockerMetadata(locker, name, changeLocation ? location + "-moved" : location));

            Assert.Equal("Locked", locker.LockerName);
            Assert.Equal(location, locker.LockerLocation);
        }

        [Fact]
        public void Verify_NullLocker_ShouldThrowArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => LockerService.Verify(null!));
        }

        [Fact]
        public void AddLocker_WithInvalidName_ShouldThrowArgumentException()
        {
            var locker = new LockerModel("bad/name", "hash", Path.Join(Path.GetTempPath(), Guid.NewGuid().ToString()));

            var exception = Assert.Throws<ArgumentException>(() => LockerService.AddLocker(locker));

            Assert.Contains("Locker name must be a valid file name", exception.Message);
        }

        [Fact]
        public void AddLocker_WithProtectedPath_ShouldThrowUnauthorizedAccessException()
        {
            var locker = new LockerModel(
                "Protected",
                "hash",
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

            Assert.Throws<UnauthorizedAccessException>(() => LockerService.AddLocker(locker));
        }

        [Fact]
        public void DeleteLockerDirectory_WithMismatchedDirectoryName_ShouldThrowUnauthorizedAccessException()
        {
            using var directory = TestDirectory.CreateAllowed("ActualDirectory");
            var locker = new LockerModel("MetadataName", "hash", directory.Path);

            Assert.Throws<UnauthorizedAccessException>(() => LockerService.DeleteLockerDirectory(locker));
            Assert.True(Directory.Exists(directory.Path));
        }

        [Fact]
        public void RemoveLocker_WithLockedLocker_ShouldThrowInvalidOperationException()
        {
            var locker = new LockerModel("Locked", "hash", Path.Join(Path.GetTempPath(), Guid.NewGuid().ToString())) { IsLocked = true };

            var exception = Assert.Throws<InvalidOperationException>(() => LockerService.RemoveLocker(locker));

            Assert.Contains("Unlock the locker before removing it", exception.Message);
        }

        [Fact]
        public void Verify_MissingDirectory_ShouldReturnInvalidResult()
        {
            var locker = new LockerModel("Missing", "hash", Path.Join(Path.GetTempPath(), Guid.NewGuid().ToString()));

            var result = LockerService.Verify(locker);

            Assert.Equal("Missing", result.LockerName);
            Assert.Equal(locker.Guid, result.Guid);
            Assert.False(result.DirectoryExists);
            Assert.False(result.HasAccess);
            Assert.False(result.IsValid);
            Assert.Contains("Directory does not exist at specified location", result.Errors);
        }

        [Fact]
        public void Verify_UnlockedDirectory_ShouldCountFilesAndDirectories()
        {
            using var directory = TestDirectory.CreateAllowed("Unlocked");
            File.WriteAllText(Path.Join(directory.Path, "file.txt"), "content");
            var childDirectory = Directory.CreateDirectory(Path.Join(directory.Path, "child"));
            File.WriteAllText(Path.Join(childDirectory.FullName, "nested.txt"), "content");
            var locker = new LockerModel("Unlocked", "hash", directory.Path);

            var result = LockerService.Verify(locker);

            Assert.True(result.DirectoryExists);
            Assert.True(result.HasAccess);
            Assert.True(result.IsValid);
            Assert.Equal(2, result.FileCount);
            Assert.Equal(1, result.DirectoryCount);
            Assert.Empty(result.Errors);
            Assert.Empty(result.Warnings);
        }

        [Fact]
        public void Verify_UnlockedDirectoryWithHiddenName_ShouldAddWarning()
        {
            using var directory = TestDirectory.CreateAllowed(".Unlocked");
            var locker = new LockerModel("Unlocked", "hash", directory.Path);

            var result = LockerService.Verify(locker);

            Assert.True(result.IsValid);
            Assert.Contains(result.Warnings, warning => warning.Contains("Unlocked locker directory name should not start"));
        }

        [Fact]
        public void Verify_LockedDirectoryWithoutArchive_ShouldReturnInvalidResult()
        {
            using var directory = TestDirectory.CreateAllowed("Locked");
            var locker = new LockerModel("Locked", "hash", directory.Path) { IsLocked = true };

            var result = LockerService.Verify(locker);

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, error => error.Contains("Locked archive does not exist"));
        }

        [Fact]
        public void Verify_LockedDirectoryWithArchive_ShouldValidateArchiveMetadata()
        {
            using var source = TestDirectory.CreateAllowed("Source");
            File.WriteAllText(Path.Join(source.Path, "secret.txt"), "classified");
            var parent = Directory.GetParent(source.Path)!.FullName;
            var lockedPath = Path.Join(parent, "Locked");
            Directory.CreateDirectory(lockedPath);

            var locker = new LockerModel("Locked", "hash", lockedPath) { IsLocked = true };
            var archive = LockerArchiveService.CreateFromDirectory(
                source.Path,
                LockerArchiveService.GetArchivePath(lockedPath),
                locker,
                "CorrectHorseBatteryStaple123!");
            locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
            locker.LockedArchiveSha256 = archive.Sha256;
            locker.LockedAtUtc = archive.LockedAtUtc;

            var result = LockerService.Verify(locker);

            Assert.True(result.IsValid);
            Assert.True(result.ArchiveExists);
            Assert.True(result.ArchiveHashMatches);
            Assert.True(result.ArchiveMetadataReadable);
            Assert.True(result.ArchiveMetadataMatches);
            Assert.Contains(result.Warnings, warning => warning.Contains("Locked locker directory name should start"));
        }

        [Fact]
        public void Verify_LockedDirectoryWithExtraEntry_ShouldReturnInvalidResult()
        {
            using var source = TestDirectory.CreateAllowed("Source");
            File.WriteAllText(Path.Join(source.Path, "secret.txt"), "classified");
            var parent = Directory.GetParent(source.Path)!.FullName;
            var lockedPath = Path.Join(parent, ".Locked");
            Directory.CreateDirectory(lockedPath);

            var locker = new LockerModel("Locked", "hash", lockedPath) { IsLocked = true };
            var archive = LockerArchiveService.CreateFromDirectory(
                source.Path,
                LockerArchiveService.GetArchivePath(lockedPath),
                locker,
                "CorrectHorseBatteryStaple123!");
            locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
            locker.LockedArchiveSha256 = archive.Sha256;
            locker.LockedAtUtc = archive.LockedAtUtc;
            File.WriteAllText(Path.Join(lockedPath, "extra.txt"), "unexpected");

            var result = LockerService.Verify(locker);

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, error => error.Contains("unexpected entries"));
        }

        [Fact]
        public void Unlock_WhenPersistenceFails_ShouldKeepLockedArchiveAndRemovePlaintextTarget()
        {
            var password = "CorrectHorseBatteryStaple123!";
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var sourcePath = Path.Join(workspace.Path, "source");
            Directory.CreateDirectory(sourcePath);
            File.WriteAllText(Path.Join(sourcePath, "secret.txt"), "classified");

            var lockedPath = Path.Join(workspace.Path, ".Vault");
            Directory.CreateDirectory(lockedPath);
            var unlockedPath = Path.Join(workspace.Path, "Vault");
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(password), lockedPath) { IsLocked = true };
            var archive = LockerArchiveService.CreateFromDirectory(
                sourcePath,
                LockerArchiveService.GetArchivePath(lockedPath),
                locker,
                password);
            locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
            locker.LockedArchiveSha256 = archive.Sha256;
            locker.LockedAtUtc = archive.LockedAtUtc;
            Directory.Delete(sourcePath, true);

            var exception = Assert.Throws<InvalidOperationException>(() =>
                LockerService.Unlock(locker, password, _ => throw new InvalidOperationException("database unavailable")));

            Assert.Contains("database unavailable", exception.Message);
            Assert.True(Directory.Exists(lockedPath));
            Assert.True(File.Exists(LockerArchiveService.GetArchivePath(lockedPath)));
            Assert.False(Directory.Exists(unlockedPath));
            Assert.True(locker.IsLocked);
            Assert.Equal(lockedPath, locker.LockerLocation);
            Assert.Equal(LockerArchiveService.CurrentStorageFormatVersion, locker.StorageFormatVersion);
            Assert.Equal(archive.Sha256, locker.LockedArchiveSha256);
            Assert.Equal(archive.LockedAtUtc, locker.LockedAtUtc);
        }

        [Fact]
        public void Unlock_DestinationCollisionPreservesUnrelatedDirectoryAndArchive()
        {
            var password = "CorrectHorseBatteryStaple123!";
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var sourcePath = Path.Join(workspace.Path, "source");
            Directory.CreateDirectory(sourcePath);
            File.WriteAllText(Path.Join(sourcePath, "secret.txt"), "classified");

            var lockedPath = Path.Join(workspace.Path, ".Vault");
            Directory.CreateDirectory(lockedPath);
            var unlockedPath = Path.Join(workspace.Path, "Vault");
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(password), lockedPath) { IsLocked = true };
            var archive = LockerArchiveService.CreateFromDirectory(
                sourcePath,
                LockerArchiveService.GetArchivePath(lockedPath),
                locker,
                password);
            locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
            locker.LockedArchiveSha256 = archive.Sha256;
            locker.LockedAtUtc = archive.LockedAtUtc;
            Directory.Delete(sourcePath, true);

            Assert.Throws<IOException>(() => LockerService.Unlock(locker, password,
                _ => throw new InvalidOperationException("Persistence must not run"),
                (staging, destination) =>
                {
                    Directory.CreateDirectory(destination);
                    File.WriteAllText(Path.Join(destination, "unrelated.txt"), "keep this file");
                    Directory.Move(staging, destination);
                }));

            Assert.Equal("keep this file", File.ReadAllText(Path.Join(unlockedPath, "unrelated.txt")));
            Assert.Empty(Directory.EnumerateDirectories(workspace.Path, "*.unlocking"));
            Assert.Equal(archive.Sha256, LockerArchiveService.ComputeSha256(archive.ArchivePath));
            Assert.True(Directory.Exists(lockedPath));
            Assert.True(File.Exists(LockerArchiveService.GetArchivePath(lockedPath)));
            Assert.True(locker.IsLocked);
            Assert.Equal(lockedPath, locker.LockerLocation);
            Assert.Equal(LockerArchiveService.CurrentStorageFormatVersion, locker.StorageFormatVersion);
            Assert.Equal(archive.Sha256, locker.LockedArchiveSha256);
            Assert.Equal(archive.LockedAtUtc, locker.LockedAtUtc);
        }

        [Fact]
        public void Unlock_PersistenceFailureDoesNotDeleteReplacementAtPublishedPath()
        {
            var password = "CorrectHorseBatteryStaple123!";
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var sourcePath = Path.Join(workspace.Path, "source");
            Directory.CreateDirectory(sourcePath);
            File.WriteAllText(Path.Join(sourcePath, "secret.txt"), "classified");

            var lockedPath = Path.Join(workspace.Path, ".Vault");
            Directory.CreateDirectory(lockedPath);
            var unlockedPath = Path.Join(workspace.Path, "Vault");
            var displacedPlaintext = Path.Join(workspace.Path, "displaced-plaintext");
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(password), lockedPath) { IsLocked = true };
            var archive = LockerArchiveService.CreateFromDirectory(
                sourcePath,
                LockerArchiveService.GetArchivePath(lockedPath),
                locker,
                password);
            locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
            locker.LockedArchiveSha256 = archive.Sha256;
            locker.LockedAtUtc = archive.LockedAtUtc;
            Directory.Delete(sourcePath, true);

            Assert.Throws<InvalidOperationException>(() => LockerService.Unlock(locker, password, _ =>
            {
                Directory.Move(unlockedPath, displacedPlaintext);
                Directory.CreateDirectory(unlockedPath);
                File.WriteAllText(Path.Join(unlockedPath, "unrelated.txt"), "preserve replacement");
                throw new InvalidOperationException("database unavailable");
            }));

            Assert.Equal("preserve replacement", File.ReadAllText(Path.Join(unlockedPath, "unrelated.txt")));
            Assert.Equal("classified", File.ReadAllText(Path.Join(displacedPlaintext, "secret.txt")));
            Assert.True(locker.IsLocked);
            Assert.Equal(lockedPath, locker.LockerLocation);
        }

        [Fact]
        public void Unlock_ArchiveCleanupDoesNotDeleteReplacementAtLockedPath()
        {
            var password = "CorrectHorseBatteryStaple123!";
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var sourcePath = Path.Join(workspace.Path, "source");
            Directory.CreateDirectory(sourcePath);
            File.WriteAllText(Path.Join(sourcePath, "secret.txt"), "classified");

            var lockedPath = Path.Join(workspace.Path, ".Vault");
            Directory.CreateDirectory(lockedPath);
            var displacedArchive = Path.Join(workspace.Path, "displaced-archive");
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(password), lockedPath) { IsLocked = true };
            var archive = LockerArchiveService.CreateFromDirectory(
                sourcePath,
                LockerArchiveService.GetArchivePath(lockedPath),
                locker,
                password);
            locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
            locker.LockedArchiveSha256 = archive.Sha256;
            locker.LockedAtUtc = archive.LockedAtUtc;
            Directory.Delete(sourcePath, true);

            LockerService.Unlock(locker, password, _ =>
            {
                Directory.Move(lockedPath, displacedArchive);
                Directory.CreateDirectory(lockedPath);
                File.WriteAllText(Path.Join(lockedPath, "unrelated.txt"), "preserve replacement");
            });

            Assert.Equal("preserve replacement", File.ReadAllText(Path.Join(lockedPath, "unrelated.txt")));
            Assert.True(File.Exists(LockerArchiveService.GetArchivePath(displacedArchive)));
            Assert.Equal("classified", File.ReadAllText(Path.Join(workspace.Path, "Vault", "secret.txt")));
            Assert.False(locker.IsLocked);
        }

        [Fact]
        public void Unlock_CancellationDuringExtractionPreservesArchiveAndLockedState()
        {
            var password = "CorrectHorseBatteryStaple123!";
            using var workspace = TestDirectory.CreateAllowed("Workspace");
            var sourcePath = Path.Join(workspace.Path, "source");
            Directory.CreateDirectory(sourcePath);
            File.WriteAllBytes(Path.Join(sourcePath, "secret.bin"), RandomNumberGenerator.GetBytes(200000));
            var lockedPath = Path.Join(workspace.Path, ".Vault");
            Directory.CreateDirectory(lockedPath);
            var locker = new LockerModel("Vault", EncryptionHelper.HashPassword(password), lockedPath) { IsLocked = true };
            var archive = LockerArchiveService.CreateFromDirectory(
                sourcePath,
                LockerArchiveService.GetArchivePath(lockedPath),
                locker,
                password);
            locker.StorageFormatVersion = LockerArchiveService.CurrentStorageFormatVersion;
            locker.LockedArchiveSha256 = archive.Sha256;
            locker.LockedAtUtc = archive.LockedAtUtc;
            Directory.Delete(sourcePath, true);
            using var cancellation = new CancellationTokenSource();
            var progress = new InlineProgress<LockerOperationProgress>(update =>
            {
                if (update.Stage == "Restoring")
                {
                    cancellation.Cancel();
                }
            });

            Assert.Throws<OperationCanceledException>(() => LockerService.Unlock(
                locker,
                password,
                _ => throw new InvalidOperationException("Persistence must not run."),
                progress: progress,
                cancellationToken: cancellation.Token));

            Assert.True(locker.IsLocked);
            Assert.Equal(lockedPath, locker.LockerLocation);
            Assert.True(File.Exists(LockerArchiveService.GetArchivePath(lockedPath)));
            Assert.False(Directory.Exists(Path.Join(workspace.Path, "Vault")));
            Assert.Empty(Directory.EnumerateDirectories(workspace.Path, "*.unlocking"));
        }

        [Fact]
        public void LockerVerificationResult_IsValid_ShouldRequireNoErrorsDirectoryAndAccess()
        {
            var result = new LockerVerificationResult { DirectoryExists = true, HasAccess = true, CountsComplete = true };

            Assert.True(result.IsValid);

            result.AddWarning("warning");
            Assert.True(result.IsValid);

            result.AddError("error");
            Assert.False(result.IsValid);
        }

        private sealed class TestDirectory : IDisposable
        {
            private TestDirectory(string path)
            {
                Path = path;
            }

            public string Path { get; }

            public void Dispose()
            {
                var parent = Directory.GetParent(Path)?.FullName;
                if (parent != null && Directory.Exists(parent))
                {
                    DeleteDirectory(parent);
                }
            }

            public static TestDirectory Create(string name)
            {
                var parent = System.IO.Path.Join(System.IO.Path.GetTempPath(), $"cdlocker-tests-{Guid.NewGuid():N}");
                var path = System.IO.Path.Join(parent, name);
                Directory.CreateDirectory(path);
                return new TestDirectory(path);
            }

            public static TestDirectory CreateAllowed(string name)
            {
                var parent = System.IO.Path.Join(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    $"cdlocker-tests-{Guid.NewGuid():N}");
                var path = System.IO.Path.Join(parent, name);
                Directory.CreateDirectory(path);
                return new TestDirectory(path);
            }

            private static void DeleteDirectory(string path)
            {
                foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                }

                foreach (var directory in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(directory, File.GetAttributes(directory) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                }

                File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.Hidden & ~FileAttributes.ReadOnly & ~FileAttributes.System);
                Directory.Delete(path, true);
            }
        }

        private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
        {
            public void Report(T value) => report(value);
        }
    }
}

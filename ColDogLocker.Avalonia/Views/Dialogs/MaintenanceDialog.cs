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

using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    /// <summary>Direct service workflows remain available after failed startup; no CLI process or shell is used.</summary>
    public sealed partial class MaintenanceDialog : Window
    {
        private bool _isRunning;
        internal Task CurrentOperation { get; private set; } = Task.CompletedTask;

        public MaintenanceDialog()
        {
            InitializeComponent();
            Closing += (_, e) => e.Cancel = _isRunning;
            Opened += (_, _) => CurrentOperation = ReloadAsync();
        }

        internal async Task RunAsync(Func<string> action)
        {
            if (_isRunning)
            {
                return;
            }

            _isRunning = true;
            ActionsTabs.IsEnabled = false;
            CloseButton.IsEnabled = false;
            ResultBox.Text = "Working… Please wait before closing.";
            try
            {
                ResultBox.Text = await Task.Run(action);
            }
            catch (Exception ex)
            {
                // Keep the underlying service refusal visible; never suggest deleting recovery artifacts.
                ResultBox.Text = $"Unable to complete this action: {ex.Message}";
            }
            finally
            {
                ArchivePasswordBox.Text = string.Empty;
                ActionsTabs.IsEnabled = true;
                CloseButton.IsEnabled = true;
                _isRunning = false;
            }
        }

        private Task ReloadAsync() => RunAsync(() =>
        {
            var pending = LockerRepository.GetPendingOperations();
            global::Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                OperationBox.ItemsSource = pending.Select(p => $"{p.OperationId} | {p.Kind} | {p.Phase}\nSource: {p.SourcePath}\nTarget: {p.TargetPath}\nStaging: {p.StagingPath}").ToArray();
                OperationBox.SelectedIndex = pending.Count > 0 ? 0 : -1;
            });
            return pending.Count == 0 ? "No unfinished locker operations." : $"{pending.Count} unfinished operation(s). Preserve all recorded paths.";
        });

        private void Start(Func<string> action) => CurrentOperation = RunAsync(action);

        private void Recover_Click(object? sender, RoutedEventArgs e)
        {
            var archive = ArchiveBox.Text ?? "";
            var destination = DestinationBox.Text ?? "";
            var password = ArchivePasswordBox.Text ?? "";
            Start(() =>
            {
                LockerRecoveryService.RecoverArchive(archive, destination, password);
                return $"Recovered files to {Path.GetFullPath(destination)}. The input archive was preserved. Compare restored files with your backup before cleanup.";
            });
        }

        private void RestoreOperation_Click(object? sender, RoutedEventArgs e)
        {
            var selected = OperationBox.SelectedItem;
            var archive = ArchiveBox.Text ?? "";
            var destination = DestinationBox.Text ?? "";
            var password = ArchivePasswordBox.Text ?? "";
            Start(() =>
            {
                var id = SelectedId(selected);
                var locker = LockerRecoveryService.RecoverOperation(id, archive, destination, password);
                return $"Recovered and registered {locker.LockerName} at {locker.LockerLocation}. Original source, archive and staging paths were preserved; inspect recovery history before cleanup.";
            });
        }

        private static string SelectedId(object? selected) => selected is string item
            ? item.Split(" | ", StringSplitOptions.None)[0]
            : throw new InvalidOperationException("Select an unfinished operation first.");

        private void CancelOperation_Click(object? sender, RoutedEventArgs e)
        {
            var selected = OperationBox.SelectedItem;
            Start(() =>
            {
                var op = LockerRepository.CancelPreparedOperation(SelectedId(selected));
                return $"Preparation cancelled. All files are preserved. Retained staging: {op.StagingPath}. Reload operations before another action.";
            });
        }

        private void FinishOperation_Click(object? sender, RoutedEventArgs e)
        {
            var selected = OperationBox.SelectedItem;
            Start(() =>
            {
                var op = LockerRecoveryService.FinishCommittedOperation(SelectedId(selected));
                return $"Verified committed {op.Kind} output. No files were changed. Inspect recovery history before cleanup.";
            });
        }

        private void History_Click(object? sender, RoutedEventArgs e) => Start(() =>
        {
            var history = LockerRepository.GetOperationHistory().Select(p => $"{p.OperationId}: {p.Kind} / {p.Phase}\nSource: {p.SourcePath}\nTarget: {p.TargetPath}\nStaging: {p.StagingPath}");
            var attempts = LockerRepository.GetRecoveryAttempts().Select(p => $"{p.AttemptId}: {p.State} (operation {p.OperationId})\nDestination: {p.DestinationPath}\nArchive: {p.ArchivePath}\nStaging: {p.StagingPath}");
            var lines = history.Concat(attempts).ToArray();
            return lines.Length == 0 ? "No recovery history." : string.Join("\n\n", lines);
        });

        private void Backup_Click(object? sender, RoutedEventArgs e)
        {
            var destination = BackupBox.Text ?? "";
            Start(() => $"Verified database backup: {LockerRepository.BackupDatabase(destination)}\nCopy locker archives separately; this backup contains metadata only.");
        }

        private void RestoreDatabase_Click(object? sender, RoutedEventArgs e)
        {
            var database = DatabaseBox.Text ?? "";
            Start(() => $"Restored database: {LockerRepository.RestoreDatabase(database)}\nLocker files were not changed. Reload unfinished operations and inspect them before continuing.");
        }

        private void DatabaseInfo_Click(object? sender, RoutedEventArgs e) => Start(() =>
        {
            var info = LockerRepository.GetDatabaseInfo();
            return $"Path: {info.Path}\nExists: {info.Exists}\nSize: {info.SizeBytes:N0} bytes\nCreated: {info.Created:g}\nModified: {info.LastModified:g}\nLockers: {info.LockerCount}\nSQLite: {info.SqliteVersion}\nIntegrity: {(info.IntegrityOk ? "OK" : "FAILED")}";
        });

        private void Vacuum_Click(object? sender, RoutedEventArgs e) => Start(() =>
        {
            var bytes = LockerRepository.VacuumDatabase();
            SettingsManager.Settings.LastDatabaseVacuum = DateTime.Now;
            SettingsManager.SaveSettings();
            return $"Database optimized. Reclaimed {bytes:N0} bytes.";
        });

        private void Reload_Click(object? sender, RoutedEventArgs e) => CurrentOperation = ReloadAsync();
        private void Close_Click(object? sender, RoutedEventArgs e)
        {
            if (!_isRunning)
            {
                Close();
            }
        }
        private async void BrowseArchive_Click(object? sender, RoutedEventArgs e) => await BrowseFileAsync(ArchiveBox, "Select encrypted archive");
        private async void BrowseDatabase_Click(object? sender, RoutedEventArgs e) => await BrowseFileAsync(DatabaseBox, "Select database backup");
        private async void BrowseDestination_Click(object? sender, RoutedEventArgs e) => await BrowseParentAsync(DestinationBox, "RecoveredLocker");
        private async void BrowseBackup_Click(object? sender, RoutedEventArgs e) => await BrowseParentAsync(BackupBox, "registry-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));

        private async Task BrowseFileAsync(TextBox target, string title)
        {
            try
            {
                var items = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = title, AllowMultiple = false });
                if (items.FirstOrDefault()?.TryGetLocalPath() is { } path)
                {
                    target.Text = path;
                }
            }
            catch (Exception ex)
            {
                ResultBox.Text = ex.Message;
            }
        }

        private async Task BrowseParentAsync(TextBox target, string newName)
        {
            try
            {
                var items = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Select existing parent directory", AllowMultiple = false });
                if (items.FirstOrDefault()?.TryGetLocalPath() is { } path)
                {
                    target.Text = Path.Join(path, newName);
                }
            }
            catch (Exception ex)
            {
                ResultBox.Text = ex.Message;
            }
        }
    }
}

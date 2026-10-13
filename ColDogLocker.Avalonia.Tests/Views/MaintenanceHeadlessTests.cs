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
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests.Views
{
    public class MaintenanceHeadlessTests
    {
        [Fact]
        public async Task WorkBlocksCloseAndDuplicateActionsThenClearsPasswordOnFailure()
        {
            await HeadlessTestSession.RunAsync(async () =>
            {
                var dialog = new MaintenanceDialog();
                dialog.Show();
                await dialog.CurrentOperation;
                var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var release = new ManualResetEventSlim();
                var password = dialog.FindControl<TextBox>("ArchivePasswordBox")!;
                password.Text = "never print this";
                var running = dialog.RunAsync(() =>
                {
                    entered.SetResult();
                    release.Wait();
                    throw new IOException("Archive is not authentic");
                });
                try
                {
                    await entered.Task;
                    Assert.False(dialog.FindControl<TabControl>("ActionsTabs")!.IsEnabled);
                    dialog.Close();
                    Assert.True(dialog.IsVisible);
                    var duplicateRan = false;
                    await dialog.RunAsync(() =>
                    {
                        duplicateRan = true;
                        return "unexpected";
                    });
                    Assert.False(duplicateRan);
                }
                finally
                {
                    release.Set();
                }

                await running;
                Assert.True(dialog.FindControl<TabControl>("ActionsTabs")!.IsEnabled);
                Assert.Equal(string.Empty, password.Text);
                Assert.Contains("Archive is not authentic", dialog.FindControl<TextBox>("ResultBox")!.Text);
                dialog.Close();
                Assert.False(dialog.IsVisible);
            });
        }

        [Fact]
        public async Task RecoverButtonReportsMissingInputWithoutPublishingOutput()
        {
            await HeadlessTestSession.RunAsync(async () =>
            {
                var dialog = new MaintenanceDialog();
                dialog.Show();
                await dialog.CurrentOperation;
                // Exercise the actual XAML event binding rather than calling the service directly.
                var button = dialog.GetVisualDescendants().OfType<Button>().Single(b => b.Content?.ToString() == "Recover archive");
                button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                await dialog.CurrentOperation;
                Assert.Contains("Unable to complete", dialog.FindControl<TextBox>("ResultBox")!.Text);
                dialog.Close();
            });
        }

        [Fact]
        public async Task RecoverControlAuthenticatesAndPreservesArchiveAndExistingDestination()
        {
            var root = Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), $"cdlocker-gui-recovery-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            try
            {
                var source = Path.Join(root, "Original");
                Directory.CreateDirectory(source);
                var payload = RandomNumberGenerator.GetBytes(8192);
                File.WriteAllBytes(Path.Join(source, "payload.bin"), payload);
                const string Password = "Recovery!River8Cobalt";
                var archive = Path.Join(root, "backup.cdl");
                LockerArchiveService.CreateFromDirectory(source, archive, new LockerModel("Original", "unused", source), Password);
                var archiveBytes = File.ReadAllBytes(archive);
                var destination = Path.Join(root, "Recovered");
                await HeadlessTestSession.RunAsync(async () =>
                {
                    var dialog = new MaintenanceDialog();
                    dialog.Show();
                    await dialog.CurrentOperation;
                    try
                    {
                        dialog.FindControl<TextBox>("ArchiveBox")!.Text = archive;
                        dialog.FindControl<TextBox>("DestinationBox")!.Text = destination;
                        var passwordBox = dialog.FindControl<TextBox>("ArchivePasswordBox")!;
                        var result = dialog.FindControl<TextBox>("ResultBox")!;
                        var button = dialog.GetVisualDescendants().OfType<Button>().Single(b => b.Content?.ToString() == "Recover archive");
                        passwordBox.Text = "wrong password";
                        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                        await dialog.CurrentOperation;
                        Assert.Contains("Unable to complete", result.Text);
                        Assert.False(Directory.Exists(destination));
                        Assert.Equal(archiveBytes, File.ReadAllBytes(archive));
                        passwordBox.Text = Password;
                        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                        await dialog.CurrentOperation;
                        Assert.Contains("Recovered files", result.Text);
                        Assert.Equal(payload, File.ReadAllBytes(Path.Join(destination, "payload.bin")));
                        Assert.Equal(string.Empty, passwordBox.Text);
                        File.WriteAllText(Path.Join(destination, "keep.txt"), "must survive");
                        passwordBox.Text = Password;
                        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                        await dialog.CurrentOperation;
                        Assert.Contains("Unable to complete", result.Text);
                        Assert.Equal("must survive", File.ReadAllText(Path.Join(destination, "keep.txt")));
                        Assert.Equal(payload, File.ReadAllBytes(Path.Join(destination, "payload.bin")));
                        Assert.Equal(archiveBytes, File.ReadAllBytes(archive));
                    }
                    finally
                    {
                        dialog.Close();
                    }
                });
            }
            finally
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }

                Directory.Delete(root, recursive: true);
            }
        }

        [Fact]
        public async Task AboutUsesSortedCurrentInventoryWithoutRemovedDependencies()
        {
            await HeadlessTestSession.RunAsync(() =>
            {
                var dialog = new AboutDialog();
                var credits = dialog.FindControl<TextBlock>("AcknowledgementsText")!.Text!;
                Assert.DoesNotContain("BCrypt", credits);
                Assert.Contains("Avalonia 12.1.4", credits);
                var entries = credits.Split("\n\n").SkipLast(1).ToArray();
                Assert.Equal(entries.OrderBy(s => s, StringComparer.OrdinalIgnoreCase), entries);
                dialog.Close();
            });
        }
    }
}

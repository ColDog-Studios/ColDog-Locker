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
using Avalonia.Threading;
using ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests.Views
{
    public class DialogHeadlessTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task PropertiesLoadsSizeAsynchronouslyAndStopsUpdatingAfterClose(bool closeImmediately)
        {
            var directory = Directory.CreateTempSubdirectory("cdl-properties-").FullName;
            try
            {
                File.WriteAllBytes(Path.Join(directory, "data"), new byte[1024]);
                await HeadlessTestSession.RunAsync(async () =>
                {
                    var locker = new ColDogStudios.ColDogLocker.Core.Models.LockerModel("Properties", "hash", directory);
                    var dialog = new LockerPropertiesDialog(locker);
                    var size = RequiredControl<TextBlock>(dialog, "SizeText");
                    Assert.Equal("Calculating...", size.Text);
                    dialog.Show();
                    try
                    {
                        if (closeImmediately)
                        {
                            dialog.Close();
                        }

                        await dialog.MetadataLoadTask;
                        Assert.Equal(closeImmediately ? "Calculating..." : "1 KB", size.Text);
                    }
                    finally
                    {
                        dialog.Close();
                    }
                });
            }
            finally
            {
                Directory.Delete(directory, true);
            }
        }

        [Fact]
        public async Task LockedProperties_CannotEditArchiveIdentity()
        {
            await HeadlessTestSession.RunAsync(() =>
            {
                var locker = new ColDogStudios.ColDogLocker.Core.Models.LockerModel("Locked", "hash", CreateSafeLockerPath()) { IsLocked = true };
                var dialog = new LockerPropertiesDialog(locker);
                try
                {
                    dialog.Show();
                    Assert.True(RequiredControl<TextBox>(dialog, "NameBox").IsReadOnly);
                    Assert.False(RequiredControl<Button>(dialog, "BrowseButton").IsEnabled);
                    Assert.False(RequiredControl<Button>(dialog, "SaveButton").IsEnabled);
                }
                finally
                {
                    dialog.Close();
                }
            });
        }

        [Fact]
        public async Task NewLockerDialog_EnablesCreateOnlyForValidInput()
        {
            await HeadlessTestSession.RunAsync(() =>
            {
                var dialog = new NewLockerDialog();

                try
                {
                    dialog.Show();
                    var nameBox = RequiredControl<TextBox>(dialog, "NameBox");
                    var locationBox = RequiredControl<TextBox>(dialog, "LocationBox");
                    var passwordBox = RequiredControl<TextBox>(dialog, "PasswordBox");
                    var confirmBox = RequiredControl<TextBox>(dialog, "ConfirmBox");
                    var createButton = RequiredControl<Button>(dialog, "CreateButton");

                    Assert.False(createButton.IsEnabled);

                    nameBox.Text = "HeadlessLocker";
                    locationBox.Text = CreateSafeLockerPath();
                    passwordBox.Text = "Violet!River9Moon";
                    confirmBox.Text = "different";
                    Dispatcher.UIThread.RunJobs();
                    Assert.False(createButton.IsEnabled);

                    confirmBox.Text = passwordBox.Text;
                    Dispatcher.UIThread.RunJobs();
                    Assert.True(createButton.IsEnabled);

                    passwordBox.Text = "weak";
                    confirmBox.Text = "weak";
                    Dispatcher.UIThread.RunJobs();
                    Assert.False(createButton.IsEnabled);
                }
                finally
                {
                    dialog.Close();
                }
            });
        }

        [Fact]
        public async Task NewLockerDialog_UpdatesPasswordRequirementIndicators()
        {
            await HeadlessTestSession.RunAsync(() =>
            {
                var dialog = new NewLockerDialog();

                try
                {
                    dialog.Show();
                    var passwordBox = RequiredControl<TextBox>(dialog, "PasswordBox");
                    var requirements = RequiredControl<StackPanel>(dialog, "PasswordRequirementsPanel");
                    Assert.Equal(6, requirements.Children.Count);

                    passwordBox.Text = "Violet!River9Moon";
                    Dispatcher.UIThread.RunJobs();

                    Assert.All(
                        requirements.Children.OfType<StackPanel>(),
                        row => Assert.Equal("✓", Assert.IsType<TextBlock>(row.Children[0]).Text));
                }
                finally
                {
                    dialog.Close();
                }
            });
        }

        [Fact]
        public async Task SettingsDialog_TracksChangesAndEnablesSave()
        {
            await HeadlessTestSession.RunAsync(() =>
            {
                var dialog = new SettingsDialog();

                try
                {
                    dialog.Show();
                    var autoUpdate = RequiredControl<CheckBox>(dialog, "AutoUpdateCheckBox");
                    var saveButton = RequiredControl<Button>(dialog, "SaveButton");
                    Assert.False(saveButton.IsEnabled);

                    autoUpdate.IsChecked = autoUpdate.IsChecked != true;
                    Dispatcher.UIThread.RunJobs();

                    Assert.True(saveButton.IsEnabled);
                }
                finally
                {
                    dialog.Close();
                }
            });
        }

        private static string CreateSafeLockerPath()
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Join(profile, "Documents", "ColDogLockerHeadless", "HeadlessLocker");
        }

        private static T RequiredControl<T>(Control root, string name) where T : Control
        {
            return root.FindControl<T>(name) ?? throw new InvalidOperationException($"Control '{name}' was not found.");
        }
    }
}

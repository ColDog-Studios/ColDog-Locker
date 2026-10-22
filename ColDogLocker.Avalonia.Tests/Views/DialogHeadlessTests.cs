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
using ColDogStudios.ColDogLocker.Core.Validation;

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

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task PasswordDialog_NewPasswordsShowLiveRequirementsAndRequireValidInput(bool requireNewPassword)
        {
            await HeadlessTestSession.RunAsync(() =>
            {
                var dialog = new PasswordDialog("Password", requireNewPassword);
                try
                {
                    dialog.Show();
                    var password = RequiredControl<TextBox>(dialog, "PasswordBox");
                    var button = RequiredControl<Button>(dialog, "OkButton");
                    var confirmation = RequiredControl<TextBox>(dialog, "ConfirmPasswordBox");
                    Assert.Equal(requireNewPassword, RequiredControl<StackPanel>(dialog, "ConfirmationPanel").IsVisible);
                    var container = RequiredControl<StackPanel>(dialog, "PasswordRequirementsContainer");
                    var requirements = RequiredControl<StackPanel>(dialog, "PasswordRequirementsPanel");
                    Assert.Equal(requireNewPassword, container.IsVisible);
                    Assert.False(button.IsEnabled);
                    foreach (var text in new[] { "weak", "Password!Red9Moon", "Qwer!River9Moon", "Violet!River9Moon", "" })
                    {
                        password.Text = text;
                        confirmation.Text = text;
                        Dispatcher.UIThread.RunJobs();
                        Assert.Equal(requireNewPassword ? PasswordFilter.ValidatePassword(text) == null : text.Length > 0,
                            button.IsEnabled);
                        if (requireNewPassword)
                        {
                            var expected = PasswordFilter.Validate(text);
                            Assert.Equal(expected.Count, requirements.Children.Count);
                            for (var i = 0; i < expected.Count; i++)
                            {
                                var row = Assert.IsType<StackPanel>(requirements.Children[i]);
                                Assert.Equal(expected[i].IsMet ? "✓" : "○", Assert.IsType<TextBlock>(row.Children[0]).Text);
                                Assert.Equal(expected[i].Description, Assert.IsType<TextBlock>(row.Children[1]).Text);
                            }
                        }
                    }

                    password.Text = "Violet!River9Moon";
                    dialog.Close();
                    Assert.Equal(string.Empty, password.Text);
                    Assert.Equal(string.Empty, confirmation.Text);
                }
                finally
                {
                    dialog.Close();
                }
            });
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task NewPasswordDialog_RequiresMatchingFieldsAndReturnsOnlyConfirmedPassword(bool cancel)
        {
            await HeadlessTestSession.RunAsync(async () =>
            {
                var owner = new Window();
                var dialog = new PasswordDialog("New password", requireNewPassword: true);
                owner.Show();
                try
                {
                    var result = dialog.ShowDialog<string?>(owner);
                    var password = RequiredControl<TextBox>(dialog, "PasswordBox");
                    var confirmation = RequiredControl<TextBox>(dialog, "ConfirmPasswordBox");
                    var submit = RequiredControl<Button>(dialog, "OkButton");
                    var mismatch = RequiredControl<TextBlock>(dialog, "MismatchText");
                    password.Text = "Violet!River9Moon";
                    Dispatcher.UIThread.RunJobs();
                    Assert.False(submit.IsEnabled);
                    Assert.False(mismatch.IsVisible);
                    confirmation.Text = "different";
                    Dispatcher.UIThread.RunJobs();
                    Assert.False(submit.IsEnabled);
                    Assert.True(mismatch.IsVisible);
                    confirmation.Text = password.Text;
                    Dispatcher.UIThread.RunJobs();
                    Assert.True(submit.IsEnabled);
                    Assert.False(mismatch.IsVisible);
                    password.Text = "Copper!River8Moon";
                    Dispatcher.UIThread.RunJobs();
                    Assert.False(submit.IsEnabled);
                    Assert.True(mismatch.IsVisible);
                    confirmation.Text = password.Text;
                    Dispatcher.UIThread.RunJobs();
                    Assert.True(submit.IsEnabled);
                    var reveal = RequiredControl<CheckBox>(dialog, "ShowPasswordCheckBox");
                    reveal.IsChecked = true;
                    Assert.Equal('\0', password.PasswordChar);
                    Assert.Equal('\0', confirmation.PasswordChar);
                    reveal.IsChecked = false;
                    Assert.Equal('*', password.PasswordChar);
                    Assert.Equal('*', confirmation.PasswordChar);
                    var button = cancel ? RequiredControl<Button>(dialog, "CancelButton") : submit;
                    button.RaiseEvent(new global::Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                    Assert.Equal(cancel ? null : "Copper!River8Moon", await result);
                    Assert.Equal(string.Empty, password.Text);
                    Assert.Equal(string.Empty, confirmation.Text);
                }
                finally
                {
                    dialog.Close();
                    owner.Close();
                }
            });
        }

        [Theory]
        [InlineData("HeadlessLocker")]
        [InlineData("Locker with spaces")]
        [InlineData("café_Δοκιμή_測試")]
        [InlineData("Symbols !#$%&'()+,-;=@[]^_`{}~")]
        [InlineData("Emoji 🔒📁")]
        [InlineData("Combining Cafe\u0301")]
        public async Task NewLockerDialog_EnablesCreateOnlyForValidInput(string name)
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

                    nameBox.Text = name;
                    locationBox.Text = Path.Join(Path.GetDirectoryName(CreateSafeLockerPath()), name);
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

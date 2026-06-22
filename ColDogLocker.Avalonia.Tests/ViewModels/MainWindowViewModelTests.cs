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

using System.Collections.ObjectModel;
using ColDogStudios.ColDogLocker.Avalonia.Models;
using ColDogStudios.ColDogLocker.Avalonia.ViewModels;
using Material.Icons;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests.ViewModels
{
    public class MainWindowViewModelTests
    {
        [Theory]
        [InlineData("alpha", "Alpha")]
        [InlineData("archive", "Beta")]
        [InlineData("unlocked", "Alpha")]
        public void SearchText_FiltersByNameLocationAndStatus(string searchText, string expectedName)
        {
            var viewModel = CreateViewModel();
            viewModel.Lockers = CreateLockers();

            viewModel.SearchText = searchText;

            var locker = Assert.Single(viewModel.FilteredLockers);
            Assert.Equal(expectedName, locker.Name);
        }

        [Theory]
        [InlineData("Name", "Alpha")]
        [InlineData("Status", "Alpha")]
        [InlineData("Modified", "Beta")]
        [InlineData("Size", "Beta")]
        [InlineData("Location", "Beta")]
        public void SortColumn_SortsAscendingBySelectedColumn(string sortColumn, string expectedFirstName)
        {
            var viewModel = CreateViewModel();
            viewModel.Lockers = CreateLockers();

            viewModel.SortColumn = sortColumn == "Name" ? "Size" : sortColumn;
            if (sortColumn == "Name")
            {
                viewModel.SortColumn = "Name";
            }

            Assert.Equal(expectedFirstName, viewModel.FilteredLockers[0].Name);
        }

        [Fact]
        public void SortAscending_WhenDisabled_ReversesSortOrder()
        {
            var viewModel = CreateViewModel();
            viewModel.Lockers = CreateLockers();
            viewModel.SortColumn = "Size";

            viewModel.SortAscending = false;

            Assert.Equal(["Alpha", "Beta"], viewModel.FilteredLockers.Select(locker => locker.Name));
        }

        [Fact]
        public void FilteringOutSelectedLocker_ClearsSelection()
        {
            var viewModel = CreateViewModel();
            viewModel.Lockers = CreateLockers();
            viewModel.SortColumn = "Size";
            viewModel.SelectedLocker = viewModel.Lockers.Single(locker => locker.Name == "Beta");

            viewModel.SearchText = "Alpha";

            Assert.Null(viewModel.SelectedLocker);
            Assert.False(viewModel.HasSelection);
        }

        [Fact]
        public void SelectingLocker_UpdatesCommandAvailability()
        {
            var viewModel = CreateViewModel();
            var unlocked = CreateLockers().Single(locker => !locker.IsLocked);
            var locked = CreateLockers().Single(locker => locker.IsLocked);

            Assert.False(viewModel.LockSelectedCommand.CanExecute(null));
            Assert.False(viewModel.UnlockSelectedCommand.CanExecute(null));

            viewModel.SelectedLocker = unlocked;

            Assert.True(viewModel.LockSelectedCommand.CanExecute(null));
            Assert.False(viewModel.UnlockSelectedCommand.CanExecute(null));
            Assert.True(viewModel.RemoveSelectedCommand.CanExecute(null));

            viewModel.SelectedLocker = locked;

            Assert.False(viewModel.LockSelectedCommand.CanExecute(null));
            Assert.True(viewModel.UnlockSelectedCommand.CanExecute(null));
            Assert.False(viewModel.RemoveSelectedCommand.CanExecute(null));
        }

        [Fact]
        public void ToggleViewCommand_UpdatesViewStateAndIcon()
        {
            var viewModel = CreateViewModel();
            Assert.True(viewModel.IsGridView);
            Assert.False(viewModel.IsListView);
            Assert.Equal(MaterialIconKind.ViewList, viewModel.ToggleViewIconKind);

            viewModel.ToggleViewCommand.Execute(null);

            Assert.False(viewModel.IsGridView);
            Assert.True(viewModel.IsListView);
            Assert.Equal(MaterialIconKind.ViewGrid, viewModel.ToggleViewIconKind);
        }

        [Fact]
        public async Task OpenLocationCommand_UsesSelectedLockerPath()
        {
            var viewModel = TestViewModelFactory.Create(out _, out var platform, out _, out _);
            viewModel.SelectedLocker = CreateLockers()[0];

            await viewModel.OpenLocationCommand.ExecuteAsync(null);

            Assert.Equal(viewModel.SelectedLocker.Location, platform.LastSelectedPath);
        }

        [Fact]
        public async Task OpenLocationCommand_WhenPlatformFails_ShowsError()
        {
            var viewModel = TestViewModelFactory.Create(out var dialogs, out var platform, out _, out _);
            viewModel.SelectedLocker = CreateLockers()[0];
            platform.OpenFolderAndSelectException = new IOException("No file manager");

            await viewModel.OpenLocationCommand.ExecuteAsync(null);

            var error = Assert.Single(dialogs.Errors);
            Assert.Equal("Open Location Error", error.Title);
            Assert.IsType<IOException>(error.Exception);
        }

        [Fact]
        public async Task OpenDocumentationCommand_UsesPublicDocumentationUrl()
        {
            var viewModel = TestViewModelFactory.Create(out _, out var platform, out _, out _);

            await viewModel.OpenDocumentationCommand.ExecuteAsync(null);

            Assert.Equal("https://github.com/ColDog-Studios/ColDog-Locker/tree/main/docs", platform.LastOpenedUrl);
        }

        [Fact]
        public async Task CreateLockerCommand_WhenDialogIsCancelled_DoesNotCreateLocker()
        {
            var viewModel = TestViewModelFactory.Create(out var dialogs, out _, out _, out _);

            await viewModel.CreateLockerCommand.ExecuteAsync(null);

            Assert.Equal(1, dialogs.NewLockerPromptCount);
            Assert.Empty(dialogs.Messages);
            Assert.Empty(viewModel.Lockers);
        }

        [Fact]
        public async Task CheckForUpdatesCommand_RunsWorkflowAndShowsResult()
        {
            var viewModel = TestViewModelFactory.Create(out _, out _, out var updates, out var updateDialogs);

            await viewModel.CheckForUpdatesCommand.ExecuteAsync(null);

            Assert.Equal(1, updates.CheckCount);
            var message = Assert.Single(updateDialogs.Messages);
            Assert.Equal("No Updates Available", message.Title);
        }

        private static MainWindowViewModel CreateViewModel()
        {
            return TestViewModelFactory.Create(out _, out _, out _, out _);
        }

        internal static ObservableCollection<LockerItemViewModel> CreateLockers()
        {
            return
            [
                new LockerItemViewModel
                {
                    Guid = System.Guid.NewGuid().ToString(),
                    Name = "Alpha",
                    Location = Path.Combine(Path.DirectorySeparatorChar.ToString(), "vault", "alpha"),
                    IsLocked = false,
                    LastModified = new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc),
                    Size = 200
                },
                new LockerItemViewModel
                {
                    Guid = System.Guid.NewGuid().ToString(),
                    Name = "Beta",
                    Location = Path.Combine(Path.DirectorySeparatorChar.ToString(), "archive", "beta"),
                    IsLocked = true,
                    LastModified = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    Size = 100
                }
            ];
        }
    }
}

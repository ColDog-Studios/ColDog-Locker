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
using Avalonia.Headless.XUnit;
using ColDogStudios.ColDogLocker.Avalonia.Tests.ViewModels;
using ColDogStudios.ColDogLocker.Avalonia.ViewModels;
using ColDogStudios.ColDogLocker.Avalonia.Views;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests.Views
{
    public class MainWindowHeadlessTests
    {
        [AvaloniaFact]
        public void Window_LoadsRealXamlAndBindsLockerCollection()
        {
            var viewModel = CreatePopulatedViewModel();
            var window = new MainWindow(viewModel);

            try
            {
                var gridList = RequiredControl<ListBox>(window, "GridLockerList");
                Assert.Same(viewModel, window.DataContext);
                Assert.Equal(2, gridList.ItemCount);
                Assert.True(gridList.IsVisible);
                Assert.False(RequiredControl<Grid>(window, "ListViewPanel").IsVisible);
            }
            finally
            {
                window.Close();
            }
        }

        [AvaloniaFact]
        public void TypingInSearchBox_FiltersVisibleLockerItems()
        {
            var viewModel = CreatePopulatedViewModel();
            var window = new MainWindow(viewModel);

            try
            {
                var searchBox = RequiredControl<TextBox>(window, "SearchBox");
                searchBox.Text = "Beta";

                Assert.Equal("Beta", viewModel.SearchText);
                Assert.Equal("Beta", Assert.Single(viewModel.FilteredLockers).Name);
                Assert.Equal(1, RequiredControl<ListBox>(window, "GridLockerList").ItemCount);
            }
            finally
            {
                window.Close();
            }
        }

        [AvaloniaFact]
        public void SelectingLocker_UpdatesBoundToolbarButtons()
        {
            var viewModel = CreatePopulatedViewModel();
            var window = new MainWindow(viewModel);

            try
            {
                var gridList = RequiredControl<ListBox>(window, "GridLockerList");
                var unlocked = viewModel.FilteredLockers.Single(locker => !locker.IsLocked);
                var locked = viewModel.FilteredLockers.Single(locker => locker.IsLocked);

                gridList.SelectedItem = unlocked;

                Assert.Same(unlocked, viewModel.SelectedLocker);
                Assert.True(RequiredControl<Button>(window, "LockButton").IsEffectivelyEnabled);
                Assert.False(RequiredControl<Button>(window, "UnlockButton").IsEffectivelyEnabled);
                Assert.True(RequiredControl<Button>(window, "RemoveButton").IsEffectivelyEnabled);

                gridList.SelectedItem = locked;

                Assert.Same(locked, viewModel.SelectedLocker);
                Assert.False(RequiredControl<Button>(window, "LockButton").IsEffectivelyEnabled);
                Assert.True(RequiredControl<Button>(window, "UnlockButton").IsEffectivelyEnabled);
                Assert.False(RequiredControl<Button>(window, "RemoveButton").IsEffectivelyEnabled);
            }
            finally
            {
                window.Close();
            }
        }

        [AvaloniaFact]
        public void ToggleViewButtonCommand_SwitchesBoundViews()
        {
            var viewModel = CreatePopulatedViewModel();
            var window = new MainWindow(viewModel);

            try
            {
                var toggleButton = RequiredControl<Button>(window, "ToggleViewButton");
                Assert.NotNull(toggleButton.Command);

                toggleButton.Command.Execute(toggleButton.CommandParameter);

                Assert.False(viewModel.IsGridView);
                Assert.False(RequiredControl<ListBox>(window, "GridLockerList").IsVisible);
                Assert.True(RequiredControl<Grid>(window, "ListViewPanel").IsVisible);
            }
            finally
            {
                window.Close();
            }
        }

        [AvaloniaFact]
        public void DeveloperMenu_TracksDeveloperModeBinding()
        {
            var viewModel = CreatePopulatedViewModel();
            var window = new MainWindow(viewModel);

            try
            {
                var developerMenu = RequiredControl<MenuItem>(window, "DeveloperMenu");
                Assert.False(developerMenu.IsVisible);

                viewModel.IsDeveloperMode = true;

                Assert.True(developerMenu.IsVisible);
            }
            finally
            {
                window.Close();
            }
        }

        private static MainWindowViewModel CreatePopulatedViewModel()
        {
            var viewModel = TestViewModelFactory.Create(out _, out _, out _, out _);
            viewModel.Lockers = MainWindowViewModelTests.CreateLockers();
            viewModel.SortColumn = "Size";
            viewModel.SortColumn = "Name";
            return viewModel;
        }

        private static T RequiredControl<T>(Control root, string name) where T : Control
        {
            return root.FindControl<T>(name) ?? throw new InvalidOperationException($"Control '{name}' was not found.");
        }
    }
}

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

using Avalonia.Automation;
using Avalonia.Controls;
using ColDogStudios.ColDogLocker.Avalonia.Tests.ViewModels;
using ColDogStudios.ColDogLocker.Avalonia.ViewModels;
using ColDogStudios.ColDogLocker.Avalonia.Views;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests.Views
{
    public class MainWindowHeadlessTests
    {
        [Fact]
        public async Task IconToolbarAndDynamicStatus_ExposeAccessibleAutomationMetadata()
        {
            await HeadlessTestSession.RunAsync(() =>
            {
                var window = new MainWindow(TestViewModelFactory.Create(out _, out _, out _, out _));
                window.Show();
                try
                {
                    var expectedNames = new Dictionary<string, string>
                    {
                        ["NewLockerButton"] = "New locker",
                        ["LockButton"] = "Lock selected locker",
                        ["UnlockButton"] = "Unlock selected locker",
                        ["RemoveButton"] = "Remove selected locker",
                        ["OpenLocationButton"] = "Open selected locker location",
                        ["PropertiesButton"] = "Show selected locker properties",
                        ["ToggleViewButton"] = "Toggle grid or list view",
                        ["RefreshButton"] = "Refresh locker list"
                    };

                    foreach (var (controlName, automationName) in expectedNames)
                    {
                        Assert.Equal(automationName, AutomationProperties.GetName(RequiredControl<Button>(window, controlName)));
                    }

                    var menuNames = RequiredControl<Menu>(window, "MainMenu").Items
                        .Cast<MenuItem>()
                        .Select(AutomationProperties.GetName)
                        .ToList();
                    Assert.Equal(["File", "Locker", "View", "Tools", "Developer", "Help"], menuNames);

                    Assert.Equal(
                        AutomationLiveSetting.Polite,
                        AutomationProperties.GetLiveSetting(RequiredControl<TextBlock>(window, "StatusMessageText")));
                }
                finally
                {
                    window.Close();
                }

                return Task.CompletedTask;
            });
        }

        [Fact]
        public async Task RefreshProgressAndCancellation_AreBoundToVisibleControls()
        {
            await HeadlessTestSession.RunAsync(async () =>
            {
                IProgress<string>? progress = null;
                var viewModel = TestViewModelFactory.Create(out _, out _, out _, out _, async (token, reporter, _) =>
                {
                    progress = reporter;
                    await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    return [];
                });
                var window = new MainWindow(viewModel);
                window.Show();
                var button = RequiredControl<Button>(window, "CancelRefreshButton");
                Assert.False(button.IsVisible);
                var refresh = viewModel.RefreshCommand.ExecuteAsync(null);
                try
                {
                    Assert.True(button.IsVisible);
                    Assert.True(button.IsEffectivelyEnabled);
                    progress!.Report("Scanning locker 1 of 2: Vault");
                    global::Avalonia.Threading.Dispatcher.UIThread.RunJobs();
                    Assert.Equal("Scanning locker 1 of 2: Vault", viewModel.StatusMessage);
                    button.Command!.Execute(button.CommandParameter);
                    await refresh;
                    progress.Report("Obsolete progress");
                    global::Avalonia.Threading.Dispatcher.UIThread.RunJobs();
                    Assert.Contains("cancelled", viewModel.StatusMessage);
                    Assert.False(button.IsVisible);
                }
                finally
                {
                    viewModel.CancelRefreshCommand.Execute(null);
                    await refresh;
                    window.Close();
                }
            });
        }

        [Fact]
        public async Task LockerOperationProgressAndCancellation_AreBoundToVisibleControls()
        {
            await HeadlessTestSession.RunAsync(() =>
            {
                var viewModel = TestViewModelFactory.Create(out _, out _, out _, out _);
                var window = new MainWindow(viewModel);
                window.Show();
                try
                {
                    var progress = RequiredControl<ProgressBar>(window, "LockerOperationProgressBar");
                    var cancel = RequiredControl<Button>(window, "CancelLockerOperationButton");
                    Assert.False(progress.IsVisible);
                    Assert.False(cancel.IsVisible);

                    viewModel.IsLockerOperationRunning = true;
                    viewModel.LockerOperationPercent = 42;
                    viewModel.CanCancelLockerOperation = true;
                    global::Avalonia.Threading.Dispatcher.UIThread.RunJobs();

                    Assert.True(progress.IsVisible);
                    Assert.False(progress.IsIndeterminate);
                    Assert.Equal(42, progress.Value);
                    Assert.True(cancel.IsVisible);
                    Assert.True(cancel.IsEffectivelyEnabled);

                    viewModel.LockerOperationPercent = null;
                    viewModel.CanCancelLockerOperation = false;
                    global::Avalonia.Threading.Dispatcher.UIThread.RunJobs();

                    Assert.True(progress.IsIndeterminate);
                    Assert.False(cancel.IsEffectivelyEnabled);
                }
                finally
                {
                    window.Close();
                }

                return Task.CompletedTask;
            });
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task ClosingDuringWork_WaitsForCompletionOrHandledFailure(bool fail)
        {
            await HeadlessTestSession.RunAsync(async () =>
            {
                var viewModel = TestViewModelFactory.Create(out var dialogs, out var platform, out _, out _);
                viewModel.SelectedLocker = MainWindowViewModelTests.CreateLockers()[0];
                var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                platform.OpenFolderAndSelectCompletion = completion.Task;
                var window = new MainWindow(viewModel);
                var closed = false;
                window.Closed += (_, _) => closed = true;
                window.Show();
                var operation = viewModel.OpenLocationCommand.ExecuteAsync(null);
                try
                {
                    Assert.True(viewModel.IsBusy);
                    window.Close();
                    Assert.False(closed);
                    Assert.True(window.IsVisible);
                    Assert.Contains("Wait", viewModel.StatusMessage);
                    if (fail)
                    {
                        completion.SetException(new IOException("Injected operation failure"));
                    }
                    else
                    {
                        completion.SetResult();
                    }

                    await operation;
                    Assert.False(viewModel.IsBusy);
                    Assert.Equal(fail ? 1 : 0, dialogs.Errors.Count);
                    window.Close();
                    Assert.True(closed);
                }
                finally
                {
                    completion.TrySetResult();
                    await operation;
                    window.Close();
                }
            });
        }

        [Fact]
        public async Task ClosingWithOverlappingWork_WaitsForBothOperations()
        {
            await HeadlessTestSession.RunAsync(async () =>
            {
                var viewModel = TestViewModelFactory.Create(out _, out var platform, out _, out _);
                viewModel.SelectedLocker = MainWindowViewModelTests.CreateLockers()[0];
                var first = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var second = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var window = new MainWindow(viewModel);
                window.Show();
                platform.OpenFolderAndSelectCompletion = first.Task;
                var firstOperation = viewModel.OpenLocationCommand.ExecuteAsync(null);
                platform.OpenFolderAndSelectCompletion = second.Task;
                var secondOperation = viewModel.OpenLocationCommand.ExecuteAsync(null);
                try
                {
                    first.SetResult();
                    await firstOperation;
                    Assert.True(viewModel.IsBusy);
                    window.Close();
                    Assert.True(window.IsVisible);
                    second.SetResult();
                    await secondOperation;
                    Assert.False(viewModel.IsBusy);
                    window.Close();
                    Assert.False(window.IsVisible);
                }
                finally
                {
                    first.TrySetResult();
                    second.TrySetResult();
                    await Task.WhenAll(firstOperation, secondOperation);
                    window.Close();
                }
            });
        }

        [Fact]
        public async Task Window_LoadsRealXamlAndBindsLockerCollection()
        {
            await HeadlessTestSession.RunAsync(() =>
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
            });
        }

        [Fact]
        public async Task TypingInSearchBox_FiltersVisibleLockerItems()
        {
            await HeadlessTestSession.RunAsync(() =>
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
            });
        }

        [Fact]
        public async Task SelectingLocker_UpdatesBoundToolbarButtons()
        {
            await HeadlessTestSession.RunAsync(() =>
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
            });
        }

        [Fact]
        public async Task ToggleViewButtonCommand_SwitchesBoundViews()
        {
            await HeadlessTestSession.RunAsync(() =>
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
            });
        }

        [Fact]
        public async Task DeveloperMenu_TracksDeveloperModeBinding()
        {
            await HeadlessTestSession.RunAsync(() =>
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
            });
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

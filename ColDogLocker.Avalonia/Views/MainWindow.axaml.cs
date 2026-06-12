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
using Avalonia.Input;
using Avalonia.Interactivity;
using ColDogStudios.ColDogLocker.Avalonia.Models;
using ColDogStudios.ColDogLocker.Avalonia.ViewModels;

namespace ColDogStudios.ColDogLocker.Avalonia.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        public MainWindow(MainWindowViewModel viewModel)
            : this()
        {
            DataContext = viewModel;
        }

        public async Task InitializeAsync(Func<Task> appInitialization)
        {
            ArgumentNullException.ThrowIfNull(appInitialization);

            if (DataContext is not MainWindowViewModel viewModel)
            {
                return;
            }

            await viewModel.InitializeAsync(appInitialization);
        }

        private void Exit_Click(object? sender, RoutedEventArgs e)
        {
            Close();
        }

        private void LockerItem_PointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (sender is Control { DataContext: LockerItemViewModel locker } &&
                DataContext is MainWindowViewModel viewModel &&
                e.GetCurrentPoint(this).Properties.IsRightButtonPressed)
            {
                viewModel.SelectedLocker = locker;
            }
        }

        private void ContextLock_Click(object? sender, RoutedEventArgs e)
        {
            ExecuteSelectedCommand(sender, commandSelector: vm => vm.LockSelectedCommand);
        }

        private void ContextUnlock_Click(object? sender, RoutedEventArgs e)
        {
            ExecuteSelectedCommand(sender, commandSelector: vm => vm.UnlockSelectedCommand);
        }

        private void ContextOpenLocation_Click(object? sender, RoutedEventArgs e)
        {
            ExecuteSelectedCommand(sender, commandSelector: vm => vm.OpenLocationCommand);
        }

        private void ContextProperties_Click(object? sender, RoutedEventArgs e)
        {
            ExecuteSelectedCommand(sender, commandSelector: vm => vm.ShowPropertiesCommand);
        }

        private void ContextRemove_Click(object? sender, RoutedEventArgs e)
        {
            ExecuteSelectedCommand(sender, commandSelector: vm => vm.RemoveSelectedCommand);
        }

        private void ExecuteSelectedCommand(
            object? sender,
            Func<MainWindowViewModel, System.Windows.Input.ICommand> commandSelector)
        {
            if (DataContext is not MainWindowViewModel viewModel)
            {
                return;
            }

            if (sender is Control { DataContext: LockerItemViewModel locker })
            {
                viewModel.SelectedLocker = locker;
            }

            var command = commandSelector(viewModel);
            if (command.CanExecute(null))
            {
                command.Execute(null);
            }
        }
    }
}

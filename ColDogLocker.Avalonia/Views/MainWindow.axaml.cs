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
            Opened += async (_, _) => await viewModel.InitializeAsync();
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

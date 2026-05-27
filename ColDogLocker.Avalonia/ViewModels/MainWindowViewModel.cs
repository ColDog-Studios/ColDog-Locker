using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ColDogStudios.ColDogLocker.Avalonia.ViewModels
{
    /*
    public partial class MainWindowViewModel : ObservableObject
    {

    }
    */
    public partial class MainWindowViewModel : ViewModelBase
    {
        public string Greeting { get; } = "Welcome to ColDog Locker!\nThis GUI is currently under construction.";
    }
}

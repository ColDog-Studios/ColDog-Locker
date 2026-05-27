using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using ColDogStudios.ColDogLocker.Avalonia.ViewModels;
using ColDogStudios.ColDogLocker.Avalonia.Views;

namespace ColDogStudios.ColDogLocker.Avalonia
{
    public class App : Application
    {
        public override void Initialize()
        {
            // Initialize ColDog Locker (database, settings, logging)
            //await Initialization.InitializeAsync();

            AvaloniaXamlLoader.Load(this);
        }

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.MainWindow = new MainWindow { DataContext = new MainWindowViewModel() };
            }

            base.OnFrameworkInitializationCompleted();
        }
    }
}

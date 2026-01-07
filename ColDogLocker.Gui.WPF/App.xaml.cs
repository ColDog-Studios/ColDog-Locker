using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;

namespace ColDogStudios.ColDogLocker.Gui.WPF;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : System.Windows.Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Configure dependency injection
        var services = new ServiceCollection();
        ServiceLocator.ConfigureServices(services);
        var serviceProvider = services.BuildServiceProvider();
        ServiceLocator.Initialize(serviceProvider);

        // Load theme
        var themeService = ServiceLocator.Instance.ThemeService;
        await themeService.LoadThemeAsync();
    }
}

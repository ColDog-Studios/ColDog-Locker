using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using ColDogStudios.ColDogLocker.Gui.WPF.Services;
using ColDogStudios.ColDogLocker.Application.Services;

namespace ColDogStudios.ColDogLocker.Gui.WPF;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : System.Windows.Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Initialize ColDog Locker infrastructure (database, settings, logging)
        await Initialization.InitializeAsync();

        // Configure dependency injection
        var services = new ServiceCollection();
        ServiceLocator.ConfigureServices(services);
        var serviceProvider = services.BuildServiceProvider();
        ServiceLocator.Initialize(serviceProvider);

        // Load theme
        var themeService = ServiceLocator.Instance.ThemeService;
        await themeService.LoadThemeAsync();

        // Check for updates on startup if enabled
        if (ColDogStudios.ColDogLocker.Gui.WPF.Properties.Settings.Default.CheckUpdatesOnStartup)
        {
            // Run update check in background without blocking startup
            _ = Task.Run(async () =>
            {
                try
                {
                    await UpdateManager.CheckForUpdatesAsync(hideUpToDateMessage: true);
                }
                catch
                {
                    // Silently ignore update check failures on startup
                }
            });
        }
    }
}

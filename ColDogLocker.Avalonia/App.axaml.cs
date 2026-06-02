using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Avalonia.ViewModels;
using ColDogStudios.ColDogLocker.Avalonia.Views;
using ColDogStudios.ColDogLocker.Services.Startup;
using ColDogStudios.ColDogLocker.Services.Updates;
using Microsoft.Extensions.DependencyInjection;

namespace ColDogStudios.ColDogLocker.Avalonia
{
    public class App : Application
    {
        private ServiceProvider? _serviceProvider;

        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        public override async void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                await Initialization.InitializeAsync();
                _serviceProvider = ConfigureServices();
                _serviceProvider.GetRequiredService<IAppThemeService>().ApplySavedTheme();
                desktop.MainWindow = _serviceProvider.GetRequiredService<MainWindow>();
                desktop.Exit += (_, _) => _serviceProvider.Dispose();
            }

            base.OnFrameworkInitializationCompleted();
        }

        private static ServiceProvider ConfigureServices()
        {
            var services = new ServiceCollection();
            services.AddSingleton<IUpdateService>(_ => GitHubUpdateService.CreateDefault());
            services.AddSingleton<IUpdateWorkflowMessageFormatter, DefaultUpdateWorkflowMessageFormatter>();
            services.AddSingleton<IUpdateDialogHost, AvaloniaUpdateDialogHost>();
            services.AddSingleton<UpdateWorkflow>();
            services.AddSingleton<IPlatformService, DesktopPlatformService>();
            services.AddSingleton<IAppThemeService, AvaloniaThemeService>();
            services.AddSingleton<IUserDialogService, AvaloniaUserDialogService>();
            services.AddSingleton<MainWindowViewModel>();
            services.AddSingleton<MainWindow>();
            return services.BuildServiceProvider();
        }
    }
}

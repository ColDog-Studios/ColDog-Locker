using System;
using ColDogStudios.ColDogLocker.Gui.WPF.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Services
{
    /// <summary>
    /// Service locator for dependency injection
    /// </summary>
    public class ServiceLocator
    {
        private static ServiceLocator? _instance;
        private readonly IServiceProvider _serviceProvider;

        public static ServiceLocator Instance => _instance ?? throw new InvalidOperationException("ServiceLocator not initialized");

        private ServiceLocator(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public static void Initialize(IServiceProvider serviceProvider)
        {
            _instance = new ServiceLocator(serviceProvider);
        }

        public static void ConfigureServices(IServiceCollection services)
        {
            // Register services
            services.AddSingleton<IThemeService, ThemeService>();

            // Register ViewModels
            services.AddTransient<MainViewModel>();

            // TODO: Add more services as needed
            // services.AddSingleton<ILockerService, LockerService>();
        }

        public T GetService<T>() where T : class
        {
            return _serviceProvider.GetRequiredService<T>();
        }

        public MainViewModel MainViewModel => GetService<MainViewModel>();
        public IThemeService ThemeService => GetService<IThemeService>();
    }
}

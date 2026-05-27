using ColDogStudios.ColDogLocker.Gui.WPF.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Services
{
    /// <summary>
    ///     Service locator for dependency injection
    /// </summary>
    public class ServiceLocator
    {
        private readonly IServiceProvider _serviceProvider;

        private ServiceLocator(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public static ServiceLocator Instance { get => field ?? throw new InvalidOperationException("ServiceLocator not initialized"); private set; }

        public MainViewModel MainViewModel => GetService<MainViewModel>();
        public IThemeService ThemeService => GetService<IThemeService>();

        public static void Initialize(IServiceProvider serviceProvider)
        {
            Instance = new ServiceLocator(serviceProvider);
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
    }
}

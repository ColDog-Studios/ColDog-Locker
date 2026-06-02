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

using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace ColDogStudios.ColDogLocker.Desktop
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Handle unhandled exceptions
            DispatcherUnhandledException += (sender, args) =>
            {
                MessageBox.Show($"Unhandled exception: {args.Exception.Message}\n\nStack trace:\n{args.Exception.StackTrace}", 
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                args.Handled = true;
                Shutdown(1);
            };

            AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
            {
                var ex = (Exception)args.ExceptionObject;
                MessageBox.Show($"Unhandled domain exception: {ex.Message}\n\nStack trace:\n{ex.StackTrace}", 
                    "Critical Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
            };

            try
            {
                base.OnStartup(e);

                // Show simple test window first to verify WPF works
                var testWindow = new TestWindow();
                testWindow.Show();

                MessageBox.Show("Test window shown. If you can see this message, WPF basic functionality is working.", 
                    "Debug", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting application: {ex.Message}\n\nStack trace:\n{ex.StackTrace}", 
                    "Startup Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            base.OnExit(e);
        }
    }
}

using System;
using System.Windows;

namespace ColDogStudios.ColDogLocker.Desktop
{
    internal class Program
    {
        [STAThread]
        public static void Main()
        {
            try
            {
                Console.WriteLine("Starting WPF application...");
                
                var app = new Application();
                
                Console.WriteLine("Creating MainWindow...");
                var window = new MainWindow();
                
                Console.WriteLine("Showing window and running app...");
                app.Run(window);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                Console.ReadKey();
            }
        }
    }
}

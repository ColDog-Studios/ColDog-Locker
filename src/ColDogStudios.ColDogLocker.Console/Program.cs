using ColDogStudios.ColDogLocker.Core;

namespace ColDogStudios.ColDogLocker.Console
{
    class Program
    {
        static async Task Main()
        {
            // Initialize the application
            await Initialization.InitializeAsync();

            // For now, just show a message that console mode is available
            System.Console.WriteLine("ColDog Locker Console Interface");
            System.Console.WriteLine("The GUI version is now the primary interface.");
            System.Console.WriteLine("Console functionality is maintained for backward compatibility.");
            System.Console.WriteLine("Press any key to exit...");
            System.Console.ReadKey();
        }
    }
}

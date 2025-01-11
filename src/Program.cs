using ColDogStudios.ColDogLocker.Core;
using ColDogStudios.ColDogLocker.Menu;

namespace ColDogStudios.ColDogLocker
{
    class Program
    {
        static async Task Main()
        {
            // Initialize the application
            await Initialization.InitializeAsync();

            // Show the main menu
            await MainMenu.MenuOptions();
        }
    }
}

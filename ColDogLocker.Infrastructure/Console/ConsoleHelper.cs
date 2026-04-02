using System.Text;

namespace ColDogStudios.ColDogLocker.Infrastructure.Console
{
    /// <summary>
    /// Provides console-related utility methods for secure password input and other console operations.
    /// </summary>
    public static class ConsoleHelper
    {
        /// <summary>
        /// Reads a password from the console with masked input (asterisks).
        /// Supports backspace for correction.
        /// </summary>
        /// <returns>The password entered by the user.</returns>
        public static string ReadPassword()
        {
            var password = new StringBuilder();
            ConsoleKeyInfo key;

            do
            {
                key = System.Console.ReadKey(intercept: true);

                if (key.Key is not (ConsoleKey.Backspace or ConsoleKey.Enter))
                {
                    password.Append(key.KeyChar);
                    System.Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Remove(password.Length - 1, 1);
                    System.Console.Write("\b \b");
                }
            } while (key.Key != ConsoleKey.Enter);

            System.Console.WriteLine();
            return password.ToString();
        }
    }
}

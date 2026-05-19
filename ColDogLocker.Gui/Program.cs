using System.Diagnostics;
using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Infrastructure.Logging;
namespace ColDogStudios.ColDogLocker.Gui
{
    /// <summary>
    /// Abstraction for launching different GUI implementations.
    /// </summary>
    public interface IGuiLauncher
    {
        /// <summary>
        /// Launches the GUI application with the given arguments.
        /// </summary>
        /// <param name="args">Command line arguments to pass to the GUI.</param>
        /// <returns>The exit code of the GUI application.</returns>
        int Launch(string[] args);
    }

    /// <summary>
    /// WPF GUI launcher for Windows platforms.
    /// </summary>
    public class WpfGuiLauncher : IGuiLauncher
    {
        public int Launch(string[] args)
        {
            try
            {
                Logger.AddEntry("Launching Windows GUI", LogLevel.Debug);

                // Find the WPF GUI executable in the same directory or nearby
                var cliDirectory = AppContext.BaseDirectory;
                var guiExeName = "ColDogLocker.exe";

                // Check common locations relative to the current executable
                var possiblePaths = new[]
                {
                    Path.Combine(cliDirectory, guiExeName),
                    Path.Combine(cliDirectory, "..", "ColDogLocker.Gui.WPF", "bin", "Debug", "net10.0-windows", guiExeName),
                    Path.Combine(cliDirectory, "..", "ColDogLocker.Gui.WPF", "bin", "Release", "net10.0-windows", guiExeName)
                };

                string? guiPath = null;
                foreach (var path in possiblePaths)
                {
                    var normalizedPath = Path.GetFullPath(path);
                    if (File.Exists(normalizedPath))
                    {
                        guiPath = normalizedPath;
                        Logger.AddEntry($"Found GUI executable at: {guiPath}", LogLevel.Debug);
                        break;
                    }
                }

                if (guiPath == null)
                {
                    Logger.AddEntry($"Could not find {guiExeName} in expected locations", LogLevel.Error);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Error.WriteLine($"Error: Could not find {guiExeName}");
                    Console.ResetColor();
                    return 1;
                }

                // Launch the GUI application as a separate process
                var startInfo = new ProcessStartInfo
                {
                    FileName = guiPath,
                    UseShellExecute = true
                };

                var process = Process.Start(startInfo);
                if (process == null)
                {
                    Logger.AddEntry($"Failed to start GUI process for {guiExeName}", LogLevel.Error);
                    return 1;
                }

                Logger.AddEntry($"Launched GUI process with ID: {process.Id}", LogLevel.Debug);
                Console.WriteLine($"Launching GUI: {guiExeName}");
                process.WaitForExit();
                return process.ExitCode;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"Error launching GUI: {ex.Message}");
                Console.ResetColor();
                return 1;
            }
        }
    }

    /// <summary>
    /// Factory for creating GUI launcher instances based on platform.
    /// </summary>
    public static class GuiLauncher
    {
        /// <summary>
        /// Creates a GUI launcher appropriate for the current platform.
        /// </summary>
        /// <returns>An IGuiLauncher instance for the current platform.</returns>
        /// <exception cref="PlatformNotSupportedException">Thrown when the current platform is not supported.</exception>
        public static IGuiLauncher CreateLauncher()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new WpfGuiLauncher();
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // TODO: Implement AvaloniaGuiLauncher for Linux
                throw new PlatformNotSupportedException("GUI launcher not yet available on Linux. Use 'cdlocker tui' for TUI.");
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                // TODO: Implement appropriate GUI launcher for macOS
                throw new PlatformNotSupportedException("GUI launcher not yet available on macOS. Use 'cdlocker tui' for TUI.");
            }

            throw new PlatformNotSupportedException("Unknown platform");
        }
    }
}

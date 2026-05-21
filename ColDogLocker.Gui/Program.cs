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
                Logger.Log(LogLevel.Debug, "Launching Windows GUI");

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
                        Logger.Log(LogLevel.Debug, $"Found GUI executable at: {guiPath}");
                        break;
                    }
                }

                if (guiPath == null)
                {
                    Logger.Log(LogLevel.Error, $"Could not find {guiExeName} in expected locations");
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
                    Logger.Log(LogLevel.Error, $"Failed to start GUI process for {guiExeName}");
                    return 1;
                }

                Logger.Log(LogLevel.Debug, $"Launched GUI process with ID: {process.Id}");
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

    public class AvaloniaGuiLauncher : IGuiLauncher
    {
        public int Launch(string[] args)
        {            
            try
            {
                Logger.Log(LogLevel.Debug, "Launching Avalonia GUI");
                
                // Find the Avalonia GUI executable in the same directory or nearby
                var cliDirectory = AppContext.BaseDirectory;
                var guiExeName = "ColDogLocker.Avalonia.exe";

                // Check common locations relative to the current executable
                var possiblePaths = new[]
                {
                    Path.Combine(cliDirectory, guiExeName),
                    Path.Combine(cliDirectory, "..", "ColDogLocker.Gui.Avalonia", "bin", "Debug", "net10.0", guiExeName),
                    Path.Combine(cliDirectory, "..", "ColDogLocker.Gui.Avalonia", "bin", "Release", "net10.0", guiExeName)
                };

                string? guiPath = null;
                foreach (var path in possiblePaths)
                {
                    var normalizedPath = Path.GetFullPath(path);
                    if (File.Exists(normalizedPath))
                    {
                        guiPath = normalizedPath;
                        Logger.Log(LogLevel.Debug, $"Found GUI executable at: {guiPath}");
                        break;
                    }
                }

                if (guiPath == null)
                {
                    Logger.Log(LogLevel.Error, $"Could not find {guiExeName} in expected locations");
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
                    Logger.Log(LogLevel.Error, $"Failed to start GUI process for {guiExeName}");
                    return 1;
                }

                Logger.Log(LogLevel.Debug, $"Launched GUI process with ID: {process.Id}");
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
                //throw new PlatformNotSupportedException("GUI launcher not yet available on Linux. Use 'cdlocker tui' for TUI.");
                return new AvaloniaGuiLauncher();
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                // TODO: Implement appropriate GUI launcher for macOS -- will likely be Avalonia as well once we have it working on Linux
                throw new PlatformNotSupportedException("GUI launcher not yet available on macOS. Use 'cdlocker tui' for TUI.");
                // return new AvaloniaGuiLauncher();
            }

            throw new PlatformNotSupportedException("Unknown platform");
        }
    }
}

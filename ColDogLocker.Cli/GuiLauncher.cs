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

using System.Diagnostics;
using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Cli
{
    internal static class GuiLauncher
    {
        public static int Launch(string[] args)
        {
            try
            {
                if (OperatingSystem.IsMacOS())
                {
                    const string message = "GUI launcher not yet available on macOS. Use 'cdlocker tui' for TUI.";
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Error.WriteLine(message);
                    Console.ResetColor();
                    Logger.Log(LogLevel.Warning, message);
                    return 1;
                }

                Logger.Log(LogLevel.Debug, "Launching Avalonia GUI");

                var guiPath = FindAvaloniaGuiExecutable();
                if (guiPath == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Error.WriteLine("Error: Could not find the Avalonia GUI executable.");
                    Console.ResetColor();
                    Logger.Log(LogLevel.Error, "Could not find the Avalonia GUI executable.");
                    return 1;
                }

                var startInfo = new ProcessStartInfo
                {
                    FileName = guiPath,
                    UseShellExecute = true
                };

                if (args.Length > 0)
                {
                    foreach (var arg in args)
                    {
                        startInfo.ArgumentList.Add(arg);
                    }
                }

                var process = Process.Start(startInfo);
                if (process == null)
                {
                    Logger.Log(LogLevel.Error, $"Failed to start GUI process for {guiPath}");
                    return 1;
                }

                Logger.Log(LogLevel.Debug, $"Launched Avalonia GUI process with ID: {process.Id}");
                Console.WriteLine($"Launching GUI: {Path.GetFileName(guiPath)}");
                process.WaitForExit();
                return process.ExitCode;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"Error launching GUI: {ex.Message}");
                Console.ResetColor();
                Logger.Log(LogLevel.Error, "Error launching Avalonia GUI", ex);
                return 1;
            }
        }

        private static string? FindAvaloniaGuiExecutable()
        {
            foreach (var path in GetCandidatePaths())
            {
                var normalizedPath = Path.GetFullPath(path);
                if (File.Exists(normalizedPath))
                {
                    Logger.Log(LogLevel.Debug, $"Found Avalonia GUI executable at: {normalizedPath}");
                    return normalizedPath;
                }
            }

            return null;
        }

        private static IEnumerable<string> GetCandidatePaths()
        {
            var cliDirectory = Path.GetFullPath(AppContext.BaseDirectory);
            var executableNames = GetExecutableNames();

            foreach (var executableName in executableNames)
            {
                yield return Path.Combine(cliDirectory, executableName);
            }

            var sourceRoot = FindSourceRoot(cliDirectory);
            if (sourceRoot == null)
            {
                yield break;
            }

            foreach (var ancestor in GetAncestorDirectories(cliDirectory))
            {
                if (!IsWithinSourceRoot(ancestor, sourceRoot))
                {
                    continue;
                }

                foreach (var executableName in executableNames)
                {
                    yield return Path.Combine(ancestor, "bin", "Debug", executableName);
                    yield return Path.Combine(ancestor, "bin", "Release", executableName);
                    yield return Path.Combine(ancestor, "bin", "net10.0", executableName);
                    yield return Path.Combine(ancestor, "bin", "Debug", "net10.0", executableName);
                    yield return Path.Combine(ancestor, "bin", "Release", "net10.0", executableName);
                    yield return Path.Combine(ancestor, "ColDogLocker.Avalonia", "bin", "Debug", "net10.0", executableName);
                    yield return Path.Combine(ancestor, "ColDogLocker.Avalonia", "bin", "Release", "net10.0", executableName);
                }
            }
        }

        private static string? FindSourceRoot(string startDirectory)
        {
            foreach (var ancestor in GetAncestorDirectories(startDirectory))
            {
                if ((File.Exists(Path.Combine(ancestor, "ColDogLocker.sln")) ||
                     File.Exists(Path.Combine(ancestor, "ColDogLocker.slnx"))) &&
                    Directory.Exists(Path.Combine(ancestor, "ColDogLocker.Avalonia")) &&
                    Directory.Exists(Path.Combine(ancestor, "ColDogLocker.Cli")))
                {
                    return Path.GetFullPath(ancestor);
                }
            }

            return null;
        }

        private static bool IsWithinSourceRoot(string path, string sourceRoot)
        {
            var relativePath = Path.GetRelativePath(sourceRoot, Path.GetFullPath(path));
            return relativePath == "." ||
                   (!relativePath.StartsWith("..", StringComparison.Ordinal) &&
                    !Path.IsPathRooted(relativePath));
        }

        private static IEnumerable<string> GetExecutableNames()
        {
            if (OperatingSystem.IsWindows())
            {
                yield return "ColDogLocker.exe";
                yield break;
            }

            yield return "ColDogLocker";
        }

        private static IEnumerable<string> GetAncestorDirectories(string startDirectory)
        {
            var directory = new DirectoryInfo(startDirectory);
            for (var depth = 0; directory != null && depth < 6; depth++)
            {
                yield return directory.FullName;
                directory = directory.Parent;
            }
        }
    }
}

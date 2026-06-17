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

using ColDogStudios.ColDogLocker.Services.Logging;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Cli.Commands
{
    public static class UpdateCommands
    {
        public static int Update(string[] args)
        {
            var download = args.Any(arg => arg.Equals("--download", StringComparison.OrdinalIgnoreCase));

            try
            {
                var result = UpdateService.CheckForUpdatesAsync().GetAwaiter().GetResult();
                PrintUpdateResult(result);

                if (!result.UpdateAvailable)
                {
                    return 0;
                }

                if (!result.CanDownload)
                {
                    return 2;
                }

                if (!download)
                {
                    Console.WriteLine();
                    Console.WriteLine("Run `cdlocker update --download` to download and verify the installer.");
                    return 0;
                }

                var downloadResult = UpdateService.DownloadUpdateAsync(result).GetAwaiter().GetResult();
                Console.WriteLine();
                Console.WriteLine($"Downloaded: {downloadResult}");
                Console.WriteLine("Run the installer to complete the update.");
                return 0;
            }
            catch (UpdateException ex)
            {
                Console.Error.WriteLine($"Update failed: {ex.Message}");
                Logger.Log(LogLevel.Error, $"CLI update command failed: {ex.FailureKind}", ex);
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Update failed: {ex.Message}");
                Logger.Log(LogLevel.Error, "CLI update command failed unexpectedly.", ex);
                return 1;
            }
        }

        private static void PrintUpdateResult(UpdateCheckResult result)
        {
            Console.WriteLine($"Current Version: {result.CurrentVersion}");
            Console.WriteLine($"Latest Version: {result.LatestVersion}");
            Console.WriteLine($"Platform: {result.PlatformName}");

            if (!result.UpdateAvailable)
            {
                Console.WriteLine();
                Console.WriteLine(result.UserMessage ?? "ColDog Locker is up to date.");
                return;
            }

            Console.WriteLine();
            Console.WriteLine(result.UserMessage ?? "A newer version is available.");

            if (!string.IsNullOrWhiteSpace(result.ReleaseUrl))
            {
                Console.WriteLine($"Release: {result.ReleaseUrl}");
            }

            if (!result.CanDownload && !string.IsNullOrWhiteSpace(result.ManualUpdateInstructions))
            {
                Console.WriteLine();
                Console.WriteLine(result.ManualUpdateInstructions);
            }

            if (!string.IsNullOrWhiteSpace(result.ReleaseNotesMarkdown))
            {
                Console.WriteLine();
                Console.WriteLine("Release Notes:");
                Console.WriteLine(result.ReleaseNotesMarkdown.Trim());
            }
        }
    }
}

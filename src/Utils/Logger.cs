using ColDogStudios.ColDogLocker.Core;
using System.Runtime.CompilerServices;

namespace ColDogStudios.ColDogLocker.Utils
{
    public enum LogLevel
    {
        Info,
        Debug,
        Success,
        Warning,
        Error
    }

    public static class Logger
    {
        private static readonly string _logDirectory = Path.Combine(Variables.localConfig, "logs");
        private static readonly int _logRetentionDays = 120;
        private static readonly HashSet<LogLevel> _enabledLogLevels =
        [
            LogLevel.Info,
            LogLevel.Debug,
            LogLevel.Success,
            LogLevel.Warning,
            LogLevel.Error
        ];

        public static void AddEntry(string message, LogLevel level, [CallerFilePath] string filePath = "", [CallerLineNumber] int lineNumber = 0)
        {
            // Check if the log level is enabled
            if (!IsLogLevelEnabled(level))
            {
                return;
            }

            // Ensure the log directory exists
            if (!Directory.Exists(_logDirectory))
            {
                Directory.CreateDirectory(_logDirectory);
            }

            // Create the log entry with timestamp and level
            string logEntry = $"[{DateTime.Now}] [{level}] {message}";

            // If in debug mode, include the file name and line number in the log entry
            if (SettingsManager.Settings.DebugMode)
            {
                string fileName = Path.GetFileName(filePath);
                logEntry = $"[{DateTime.Now}] [{level}] {fileName}:{lineNumber} {message}";
            }

            // Append the log entry to the master log file
            File.AppendAllText(Path.Combine(_logDirectory, "cdl.log"), logEntry + Environment.NewLine);

            // Append the log entry to the category-specific log file
            string categoryLogFilePath = GetCategoryLogFilePath(level);
            File.AppendAllText(categoryLogFilePath, logEntry + Environment.NewLine);
        }

        // Get the log file path based on the log level
        private static string GetCategoryLogFilePath(LogLevel level)
        {
            return Path.Combine(_logDirectory, $"{level.ToString().ToLower()}.log");
        }

        // Check if the specified log level is enabled
        private static bool IsLogLevelEnabled(LogLevel level)
        {
            return _enabledLogLevels.Contains(level);
        }

        // Trim log entries older than the specified number of days
        public static void TrimLog()
        {
            // Verify the log files exist
            if (Directory.GetFiles(_logDirectory, "*.log").Length == 0)
            {
                return;
            }

            int totalTrimmed = 0;

            // Iterate through all log files in the log directory
            foreach (var logFile in Directory.GetFiles(_logDirectory, "*.log"))
            {
                // Read all lines from the log file
                var lines = File.ReadAllLines(logFile);
                int originalCount = lines.Length;

                // Filter out log entries older than the specified number of days
                var trimmedLines = lines.Where(line =>
                {
                    // Ensure the line is long enough to contain a date
                    if (line.Length < 21)
                    {
                        return false;
                    }

                    // Extract the date part from the log entry
                    var datePart = line.Substring(1, 19);

                    // Parse the date and check if it is within the retention period
                    if (DateTime.TryParse(datePart, out DateTime logDate))
                    {
                        return logDate >= DateTime.Now.AddDays(-_logRetentionDays);
                    }
                    return false;
                }).ToArray();

                // Write the filtered log entries back to the log file
                File.WriteAllLines(logFile, trimmedLines);

                int removedCount = originalCount - trimmedLines.Length;
                totalTrimmed += removedCount;
            }

            // Only log if we actually trimmed something, and do it after all files are processed
            if (totalTrimmed > 0)
            {
                string message = $"Trimmed {totalTrimmed} log entries older than {_logRetentionDays} days";
                string logEntry = $"[{DateTime.Now}] [Info] {message}";
                
                // Write directly to avoid recursion
                File.AppendAllText(Path.Combine(_logDirectory, "cdl.log"), logEntry + Environment.NewLine);
                File.AppendAllText(Path.Combine(_logDirectory, "info.log"), logEntry + Environment.NewLine);
            }
        }
    }
}
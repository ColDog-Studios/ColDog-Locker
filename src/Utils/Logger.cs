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
            DateTime cutoffDate = DateTime.Now.AddDays(-_logRetentionDays);

            // Iterate through all log files in the log directory
            foreach (var logFile in Directory.GetFiles(_logDirectory, "*.log"))
            {
                try
                {
                    // Read all lines from the log file
                    var lines = File.ReadAllLines(logFile);
                    int originalCount = lines.Length;

                    // Filter out log entries older than the specified number of days
                    var trimmedLines = lines.Where(line => IsLineWithinRetention(line, cutoffDate)).ToArray();

                    // Only write back if there were changes
                    if (trimmedLines.Length != originalCount)
                    {
                        File.WriteAllLines(logFile, trimmedLines);
                        int removedCount = originalCount - trimmedLines.Length;
                        totalTrimmed += removedCount;
                    }
                }
                catch (Exception ex)
                {
                    // Log error directly to avoid recursion, but continue with other files
                    string errorEntry = $"[{DateTime.Now}] [Error] Failed to trim log file {logFile}: {ex.Message}";
                    try
                    {
                        File.AppendAllText(Path.Combine(_logDirectory, "cdl.log"), errorEntry + Environment.NewLine);
                    }
                    catch
                    {
                        // If we can't even write to the main log, just continue
                    }
                }
            }

            // Only log if we actually trimmed something, and do it after all files are processed
            if (totalTrimmed > 0)
            {
                string message = $"Trimmed {totalTrimmed} log entries older than {_logRetentionDays} days";
                string logEntry = $"[{DateTime.Now}] [Info] {message}";
                
                // Write directly to avoid recursion
                try
                {
                    File.AppendAllText(Path.Combine(_logDirectory, "cdl.log"), logEntry + Environment.NewLine);
                    File.AppendAllText(Path.Combine(_logDirectory, "info.log"), logEntry + Environment.NewLine);
                }
                catch
                {
                    // If we can't log the trimming result, that's okay
                }
            }
        }

        // Helper method to check if a log line is within the retention period
        private static bool IsLineWithinRetention(string line, DateTime cutoffDate)
        {
            // If line is empty or too short, keep it (might be important)
            if (string.IsNullOrWhiteSpace(line) || line.Length < 10)
            {
                return true;
            }

            // Look for the pattern [timestamp] at the beginning
            if (!line.StartsWith("["))
            {
                return true; // Keep lines that don't follow expected format
            }

            // Find the closing bracket for the timestamp
            int closingBracketIndex = line.IndexOf(']');
            if (closingBracketIndex <= 1)
            {
                return true; // Keep malformed lines
            }

            // Extract the timestamp part (without the brackets)
            string timestampPart = line.Substring(1, closingBracketIndex - 1);

            // Try to parse the timestamp
            if (DateTime.TryParse(timestampPart, out DateTime logDate))
            {
                return logDate >= cutoffDate;
            }

            // If we can't parse the date, keep the line to be safe
            return true;
        }
    }
}
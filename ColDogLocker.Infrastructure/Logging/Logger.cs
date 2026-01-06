using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using ColDogStudios.ColDogLocker.Core.Constants;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Infrastructure.Logging
{
    public enum LogLevel
    {
        Debug,
        Info,
        Success,
        Warning,
        Error
    }

    public class LogEntry
    {
        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonProperty("level")]
        public string Level { get; set; } = string.Empty;

        [JsonProperty("message")]
        public string Message { get; set; } = string.Empty;

        [JsonProperty("source_file")]
        public string? SourceFile { get; set; }

        [JsonProperty("line_number")]
        public int? LineNumber { get; set; }

        [JsonProperty("session_id")]
        public string SessionId { get; set; } = string.Empty;
    }

    public static class Logger
    {
        private static readonly string _logDirectory = Path.Combine(Variables.localConfig, "logs");
        private static readonly string _sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        private static readonly string _logFilePath = Path.Combine(_logDirectory, $"session_{_sessionId}.json");
        private static readonly object _lockObject = new object();

        // Dynamic property that reads from settings
        // Note: This creates a circular dependency that will need to be resolved
        // TODO: Inject settings via configuration interface
        private static int LogRetentionDays => 30; // Default value, will be configurable

        private static readonly HashSet<LogLevel> _enabledLogLevels =
        [
            LogLevel.Info,
            LogLevel.Debug,
            LogLevel.Success,
            LogLevel.Warning,
            LogLevel.Error
        ];

        // Flag to check if debug mode is enabled
        private static bool _debugMode = false;

        // Method to set debug mode from external configuration
        public static void SetDebugMode(bool enabled)
        {
            _debugMode = enabled;
        }

        // Method to set log retention days
        public static void SetLogRetentionDays(int days)
        {
            // This will be used instead of the hardcoded default
        }

        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for log entries")]
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

            // Create the log entry object
            var logEntry = new LogEntry
            {
                Timestamp = DateTime.Now,
                Level = level.ToString(),
                Message = message,
                SessionId = _sessionId
            };

            // If in debug mode, include the file name and line number
            if (_debugMode)
            {
                logEntry.SourceFile = Path.GetFileName(filePath);
                logEntry.LineNumber = lineNumber;
            }

            // Convert to JSON and append to log file (thread-safe)
            lock (_lockObject)
            {
                try
                {
                    // NDJSON format - each line is a separate JSON object
                    var jsonLine = JsonConvert.SerializeObject(logEntry, Formatting.None);
                    File.AppendAllText(_logFilePath, jsonLine + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    // If we can't log, try to write to a fallback file
                    try
                    {
                        var fallbackPath = Path.Combine(_logDirectory, $"fallback_{_sessionId}.txt");
                        var fallbackEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message} (Logging Error: {ex.Message})";
                        File.AppendAllText(fallbackPath, fallbackEntry + Environment.NewLine);
                    }
                    catch
                    {
                        // If even fallback fails, we can't do much
                    }
                }
            }
        }

        // Get the log file path based on the log level
        private static string GetCategoryLogFilePath(LogLevel level)
        {
            return _logFilePath; // Single file for all levels
        }

        // Check if the specified log level is enabled
        private static bool IsLogLevelEnabled(LogLevel level)
        {
            return _enabledLogLevels.Contains(level);
        }

        // Trim log files older than the specified number of days
        public static void TrimLog()
        {
            TrimOldLogFiles();
        }

        // Remove log files older than the retention period
        private static void TrimOldLogFiles()
        {
            try
            {
                if (!Directory.Exists(_logDirectory))
                {
                    return;
                }

                var cutoffDate = DateTime.Now.AddDays(-LogRetentionDays);
                var allLogFiles = Directory.GetFiles(_logDirectory, "session_*.json")
                    .Concat(Directory.GetFiles(_logDirectory, "fallback_*.txt"))
                    .ToArray();

                var totalDeleted = 0;

                foreach (var logFile in allLogFiles)
                {
                    try
                    {
                        var fileInfo = new FileInfo(logFile);

                        // Delete files older than retention period
                        if (fileInfo.CreationTime < cutoffDate)
                        {
                            File.Delete(logFile);
                            totalDeleted++;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log error for specific file but continue with others
                        LogDirectly($"Failed to delete old log file {logFile}: {ex.Message}", "Warning");
                    }
                }

                // Log the cleanup result if files were deleted
                if (totalDeleted > 0)
                {
                    LogDirectly($"Deleted {totalDeleted} log files older than {LogRetentionDays} days", "Info");
                }
            }
            catch (Exception ex)
            {
                LogDirectly($"Error during log cleanup: {ex.Message}", "Error");
            }
        }

        // Direct logging method to avoid recursion during maintenance operations
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for log entries")]
        private static void LogDirectly(string message, string level)
        {
            try
            {
                var logEntry = new LogEntry
                {
                    Timestamp = DateTime.Now,
                    Level = level,
                    Message = message,
                    SessionId = _sessionId
                };

                lock (_lockObject)
                {
                    var jsonLine = JsonConvert.SerializeObject(logEntry, Formatting.None);
                    File.AppendAllText(_logFilePath, jsonLine + Environment.NewLine);
                }
            }
            catch
            {
                // If direct logging fails, there's not much we can do
            }
        }

        // Helper method to get session information
        public static string GetCurrentSessionId()
        {
            return _sessionId;
        }

        // Helper method to get current session log file path
        public static string GetCurrentLogFilePath()
        {
            return _logFilePath;
        }
    }
}

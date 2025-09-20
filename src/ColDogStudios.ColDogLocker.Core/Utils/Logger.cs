using ColDogStudios.ColDogLocker.Core;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Core.Utils
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
        private static readonly string _logDirectory = Path.Combine(Variables.LocalConfig, "logs");
        private static readonly string _sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        private static readonly string _logFilePath = Path.Combine(_logDirectory, $"session_{_sessionId}.json");
        private static readonly object _lockObject = new object();
        
        // Static log retention days (30 days default)
        private static int LogRetentionDays => 30;
        
        private static readonly HashSet<LogLevel> _enabledLogLevels =
        [
            LogLevel.Info,
            LogLevel.Debug,
            LogLevel.Success,
            LogLevel.Warning,
            LogLevel.Error
        ];

        // Event for GUI log monitoring
        public static event EventHandler<LogEntry>? LogEntryAdded;

        public static void AddEntry(string message, LogLevel level, [CallerFilePath] string filePath = "", [CallerLineNumber] int lineNumber = 0)
        {
            if (!IsLogLevelEnabled(level))
            {
                return;
            }

            if (!Directory.Exists(_logDirectory))
            {
                Directory.CreateDirectory(_logDirectory);
            }

            var logEntry = new LogEntry
            {
                Timestamp = DateTime.Now,
                Level = level.ToString(),
                Message = message,
                SessionId = _sessionId,
                SourceFile = Path.GetFileName(filePath),
                LineNumber = lineNumber
            };

            lock (_lockObject)
            {
                try
                {
                    string jsonLine = JsonConvert.SerializeObject(logEntry, Formatting.None);
                    File.AppendAllText(_logFilePath, jsonLine + Environment.NewLine);

                    // Notify GUI subscribers
                    LogEntryAdded?.Invoke(null, logEntry);
                }
                catch (Exception ex)
                {
                    try
                    {
                        string fallbackPath = Path.Combine(_logDirectory, $"fallback_{_sessionId}.txt");
                        string fallbackEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message} (Logging Error: {ex.Message})";
                        File.AppendAllText(fallbackPath, fallbackEntry + Environment.NewLine);
                    }
                    catch
                    {
                        // If even fallback fails, we can't do much
                    }
                }
            }
        }

        private static bool IsLogLevelEnabled(LogLevel level)
        {
            return _enabledLogLevels.Contains(level);
        }

        public static void TrimLog()
        {
            TrimOldLogFiles();
        }

        private static void TrimOldLogFiles()
        {
            try
            {
                if (!Directory.Exists(_logDirectory))
                    return;

                DateTime cutoffDate = DateTime.Now.AddDays(-LogRetentionDays);
                var allLogFiles = Directory.GetFiles(_logDirectory, "session_*.json")
                    .Concat(Directory.GetFiles(_logDirectory, "fallback_*.txt"))
                    .ToArray();
                
                int totalDeleted = 0;

                foreach (var logFile in allLogFiles)
                {
                    try
                    {
                        var fileInfo = new FileInfo(logFile);
                        
                        if (fileInfo.CreationTime < cutoffDate)
                        {
                            File.Delete(logFile);
                            totalDeleted++;
                        }
                    }
                    catch (Exception ex)
                    {
                        LogDirectly($"Failed to delete old log file {logFile}: {ex.Message}", "Warning");
                    }
                }

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
                    string jsonLine = JsonConvert.SerializeObject(logEntry, Formatting.None);
                    File.AppendAllText(_logFilePath, jsonLine + Environment.NewLine);
                }
            }
            catch
            {
                // If direct logging fails, there's not much we can do
            }
        }

        public static string GetCurrentSessionId()
        {
            return _sessionId;
        }

        public static string GetCurrentLogFilePath()
        {
            return _logFilePath;
        }

        // Get recent log entries for GUI display
        public static List<LogEntry> GetRecentEntries(int count = 100)
        {
            var entries = new List<LogEntry>();
            
            try
            {
                if (File.Exists(_logFilePath))
                {
                    var lines = File.ReadAllLines(_logFilePath);
                    foreach (var line in lines.TakeLast(count))
                    {
                        try
                        {
                            var entry = JsonConvert.DeserializeObject<LogEntry>(line);
                            if (entry != null)
                                entries.Add(entry);
                        }
                        catch
                        {
                            // Skip malformed lines
                        }
                    }
                }
            }
            catch
            {
                // Return empty list if file reading fails
            }

            return entries;
        }
    }
}

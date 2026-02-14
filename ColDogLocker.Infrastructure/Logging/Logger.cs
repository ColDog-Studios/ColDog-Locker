using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using ColDogStudios.ColDogLocker.Core.Constants;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Infrastructure.Logging
{
    public enum LogLevel
    {
        Debug = 0,
        Info = 1,
        Success = 2,
        Warning = 3,
        Error = 4,
        Fatal = 5
    }

    public class LogEntry
    {
        [JsonProperty("timestamp")]
        public string? Timestamp { get; set; }

        [JsonProperty("level")]
        public string Level { get; set; } = string.Empty;

        [JsonProperty("message")]
        public string Message { get; set; } = string.Empty;

        [JsonProperty("source_file")]
        public string? SourceFile { get; set; }

        [JsonProperty("line_number")]
        public int? LineNumber { get; set; }

        [JsonProperty("thread_id")]
        public int? ThreadId { get; set; }

        [JsonProperty("session_id")]
        public string SessionId { get; set; } = string.Empty;

        [JsonProperty("app_version")]
        public string AppVersion { get; set; } = string.Empty;

        [JsonProperty("environment")]
        public string Environment { get; set; } = string.Empty;
    }

    public static class Logger
    {
        private static readonly string _logDirectory = Path.Combine(Variables.localConfig, "logs");
        private static readonly string _sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        private static readonly string _logFilePath = Path.Combine(_logDirectory, $"cdl.log");
        private static readonly Lock _lockObject = new();

        private static LogLevel _minLogLevel = LogLevel.Info;
        private static string _logFormat = "json";
        private static int _maxFileSizeMB = 10;
        private static int _maxRetainedFiles = 9;
        private static bool _enableFileLogging = true;
        private static bool _enableCompression = false;
        private static bool _includeTimestamps = true;
        private static bool _includeThreadId = false;
        private static string _dateTimeFormat = "UTC";
        private static bool _asyncLogging = false;
        private static bool _devMode = false;

        // Custom fields - automatically populated
        private static readonly string _appVersion = GetAppVersion();
        private static readonly string _environment = GetEnvironmentInfo();

        // Async logging support
        private static readonly Queue<LogEntry> _logQueue = new();
        private static Thread? _logWorkerThread = null;
        private static bool _workerRunning = false;

        static Logger()
        {
            LoadConfigFromSettings();
            if (_asyncLogging)
            {
                StartLogWorker();
            }
        }

        public static void ReloadConfig()
        {
            LoadConfigFromSettings();
            if (_asyncLogging && !_workerRunning)
            {
                StartLogWorker();
            }
        }

        private static void LoadConfigFromSettings()
        {
            var s = ColDogStudios.ColDogLocker.Infrastructure.Configuration.SettingsManager.Settings;
            Enum.TryParse(s.LogLevel, true, out _minLogLevel);
            _logFormat = s.LogFormat ?? "json";
            _maxFileSizeMB = s.MaxFileSizeMB > 0 ? s.MaxFileSizeMB : 10;
            _maxRetainedFiles = s.MaxRetainedFiles > 0 ? s.MaxRetainedFiles : 9;
            _enableFileLogging = s.EnableFileLogging;
            _enableCompression = s.EnableCompression;
            _includeTimestamps = s.IncludeTimestamps;
            _includeThreadId = s.IncludeThreadId;
            _dateTimeFormat = s.DateTimeFormat ?? "UTC";
            _asyncLogging = s.AsyncLogging;
            _devMode = s.DevMode;
        }

        private static void StartLogWorker()
        {
            if (_workerRunning)
            {
                return;
            }

            _workerRunning = true;
            _logWorkerThread = new Thread(LogWorkerLoop) { IsBackground = true };
            _logWorkerThread.Start();
        }

        private static void LogWorkerLoop()
        {
            while (_workerRunning)
            {
                LogEntry? entry = null;
                lock (_logQueue)
                {
                    if (_logQueue.Count > 0)
                    {
                        entry = _logQueue.Dequeue();
                    }
                }

                if (entry != null)
                {
                    WriteLogEntry(entry);
                }
                else
                {
                    Thread.Sleep(50); // Tune as needed
                }
            }
        }

        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for log entries")]
        public static void AddEntry(string message, LogLevel level, [CallerFilePath] string filePath = "", [CallerLineNumber] int lineNumber = 0)
        {
            if (level < _minLogLevel)
            {
                return;
            }

            if (!_enableFileLogging)
            {
                return;
            }

            var logEntry = new LogEntry
            {
                Level = level.ToString(),
                Message = message,
                SessionId = _sessionId,
                AppVersion = _appVersion,
                Environment = _environment
            };
            if (_includeTimestamps)
            {
                var now = _dateTimeFormat.Equals("LOCAL", StringComparison.InvariantCultureIgnoreCase) ? DateTime.Now : DateTime.UtcNow;
                logEntry.Timestamp = now.ToString("o");
            }

            if (_includeThreadId)
            {
                logEntry.ThreadId = Environment.CurrentManagedThreadId;
            }

            if (_devMode)
            {
                logEntry.SourceFile = Path.GetFileName(filePath);
                logEntry.LineNumber = lineNumber;
            }

            if (_asyncLogging)
            {
                lock (_logQueue)
                {
                    _logQueue.Enqueue(logEntry);
                }
            }
            else
            {
                WriteLogEntry(logEntry);
            }
        }

        private static void WriteLogEntry(LogEntry logEntry)
        {
            try
            {
                // Ensure the log directory exists
                if (!Directory.Exists(_logDirectory))
                {
                    Directory.CreateDirectory(_logDirectory);
                }

                RotateLogFileIfNeeded();

                var line = _logFormat.Equals("json", StringComparison.InvariantCultureIgnoreCase)
                    ? JsonConvert.SerializeObject(logEntry, Formatting.None)
                    : FormatPlainText(logEntry);

                lock (_lockObject)
                {
                    File.AppendAllText(_logFilePath, line + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                // Fallback: try to write to a fallback file
                try
                {
                    var fallbackPath = Path.Combine(_logDirectory, $"fallback_{_sessionId}.txt");
                    File.AppendAllText(fallbackPath, $"[{DateTime.UtcNow:o}] {logEntry.Level}: {logEntry.Message} (Logger error: {ex.Message})\n");
                }
                catch { }
            }
        }

        private static string FormatPlainText(LogEntry entry)
        {
            var parts = new List<string>();
            if (_includeTimestamps && entry.Timestamp != null)
            {
                parts.Add($"[{entry.Timestamp}]");
            }

            parts.Add(entry.Level);
            if (_includeThreadId && entry.ThreadId.HasValue)
            {
                parts.Add($"[Thread:{entry.ThreadId}]");
            }

            if (!string.IsNullOrEmpty(entry.SourceFile))
            {
                parts.Add($"[{entry.SourceFile}:{entry.LineNumber}]");
            }

            parts.Add(entry.Message);
            parts.Add($"(Session:{entry.SessionId})");
            parts.Add($"(Version:{entry.AppVersion})");
            parts.Add($"(Env:{entry.Environment})");
            return string.Join(" ", parts);
        }

        private static void RotateLogFileIfNeeded()
        {
            if (!File.Exists(_logFilePath))
            {
                return;
            }

            var fileInfo = new FileInfo(_logFilePath);
            if (fileInfo.Length < _maxFileSizeMB * 1024 * 1024)
            {
                return;
            }

            // Rotate: rename current log file
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var rotatedName = Path.Combine(_logDirectory, $"app_{timestamp}.log");
            File.Move(_logFilePath, rotatedName);

            // Optionally compress
            if (_enableCompression)
            {
                try
                {
                    CompressFile(rotatedName);
                }
                catch { }
            }

            // Delete old logs if exceeding max retained
            var logFiles = Directory.GetFiles(_logDirectory, "app_*.log*")
                .OrderByDescending(f => File.GetCreationTimeUtc(f)).ToList();
            for (var i = _maxRetainedFiles; i < logFiles.Count; i++)
            {
                try
                {
                    File.Delete(logFiles[i]);
                }
                catch { }
            }
        }

        private static void CompressFile(string filePath)
        {
            var compressedPath = filePath + ".gz";
            using (var originalFileStream = File.OpenRead(filePath))
            using (var compressedFileStream = File.Create(compressedPath))
            using (var compressionStream = new System.IO.Compression.GZipStream(compressedFileStream, System.IO.Compression.CompressionLevel.Optimal))
            {
                originalFileStream.CopyTo(compressionStream);
            }

            File.Delete(filePath);
        }

        // Direct logging method to avoid recursion during maintenance operations
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for log entries")]
        private static void LogDirectly(string message, string level)
        {
            try
            {
                var logEntry = new LogEntry
                {
                    Level = level,
                    Message = message,
                    SessionId = _sessionId,
                    AppVersion = _appVersion,
                    Environment = _environment
                };
                if (_includeTimestamps)
                {
                    var now = _dateTimeFormat.Equals("LOCAL", StringComparison.InvariantCultureIgnoreCase) ? DateTime.Now : DateTime.UtcNow;
                    logEntry.Timestamp = now.ToString("o");
                }

                if (_includeThreadId)
                {
                    logEntry.ThreadId = Environment.CurrentManagedThreadId;
                }

                lock (_lockObject)
                {
                    var line = _logFormat.Equals("json", StringComparison.InvariantCultureIgnoreCase)
                        ? JsonConvert.SerializeObject(logEntry, Formatting.None)
                        : FormatPlainText(logEntry);
                    File.AppendAllText(_logFilePath, line + Environment.NewLine);
                }
            }
            catch { }
        }

        // Helper method to get session information
        public static string GetCurrentSessionId() => _sessionId;
        public static string GetCurrentLogFilePath() => _logFilePath;

        // Methods to get app information
        private static string GetAppVersion()
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            return version?.ToString() ?? "0.0.0.0";
        }

        private static string GetEnvironmentInfo()
        {
            var os = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
            var arch = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture;
            return $"{os} ({arch})";
        }

        // Methods to update logger config at runtime
        public static void SetDevMode(bool enabled) { _devMode = enabled; }
        public static void SetLogLevel(LogLevel level) { _minLogLevel = level; }
        public static void SetLogFormat(string format) { _logFormat = format; }
        public static void SetMaxFileSizeMB(int mb) { _maxFileSizeMB = mb; }
        public static void SetMaxRetainedFiles(int count) { _maxRetainedFiles = count; }
        public static void SetEnableFileLogging(bool enabled) { _enableFileLogging = enabled; }
        public static void SetEnableCompression(bool enabled) { _enableCompression = enabled; }
        public static void SetIncludeTimestamps(bool enabled) { _includeTimestamps = enabled; }
        public static void SetIncludeThreadId(bool enabled) { _includeThreadId = enabled; }
        public static void SetDateTimeFormat(string format) { _dateTimeFormat = format; }
        public static void SetAsyncLogging(bool enabled)
        {
            _asyncLogging = enabled;
            if (_asyncLogging && !_workerRunning)
            {
                StartLogWorker();
            }
        }
    }
}

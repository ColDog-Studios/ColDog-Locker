using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Core.Configuration;
using ColDogStudios.ColDogLocker.Core.Constants;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Core.Logging
{
    /// <summary>
    ///     Defines the severity level of a log entry.
    /// </summary>
    public enum LogLevel
    {
        Debug = 0, // Verbose diagnostic info for development; suppressed in production
        Info = 1, // General application flow and successful operations (lock, unlock, create, etc.)
        Warning = 2, // Something unexpected but recoverable; worth investigating
        Error = 3, // A failure occurred that affected an operation but did not crash the app
        Fatal = 4 // A critical failure that requires the application to stop or cannot recover
    }

    /// <summary>
    ///     Represents a single structured log entry. Used for both JSON serialization
    ///     and plain text formatting. All fields are optional depending on config.
    /// </summary>
    public class LogEntry
    {
        [JsonProperty("timestamp")] public string? Timestamp { get; set; }

        [JsonProperty("level")] public string Level { get; set; } = string.Empty;

        [JsonProperty("message")] public string Message { get; set; } = string.Empty;

        [JsonProperty("caller")] public CallerInfo? Caller { get; set; }

        [JsonProperty("exception")] public ExceptionInfo? Exception { get; set; }

        [JsonProperty("thread_id")] public int? ThreadId { get; set; }

        [JsonProperty("session_id")] public string SessionId { get; set; } = string.Empty;

        [JsonProperty("app_version")] public string AppVersion { get; set; } = string.Empty;

        [JsonProperty("environment")] public string Environment { get; set; } = string.Empty;
    }

    /// <summary>
    ///     Structured caller information captured automatically by the compiler.
    ///     Only populated when DevMode is enabled.
    /// </summary>
    public class CallerInfo
    {
        [JsonProperty("method")] public string Method { get; set; } = string.Empty;

        [JsonProperty("file")] public string File { get; set; } = string.Empty;

        [JsonProperty("line")] public int Line { get; set; }
    }

    /// <summary>
    ///     Structured exception information captured from a caught Exception object.
    ///     Separates type, message, and stack trace for clean SIEM ingestion.
    /// </summary>
    public class ExceptionInfo
    {
        [JsonProperty("type")] public string Type { get; set; } = string.Empty;

        [JsonProperty("message")] public string Message { get; set; } = string.Empty;

        [JsonProperty("stack_trace")] public string? StackTrace { get; set; }
    }

    /// <summary>
    ///     Static logger for ColDog Locker. Writes structured log entries to disk in either JSON (NDJSON) or plain text format.
    ///     Supports async buffered writing, log rotation, optional compression, and runtime configuration reloading.
    ///
    ///     USAGE:
    ///
    ///     Basic info entry:
    ///         Logger.Log(LogLevel.Info, "Locker unlocked successfully.");
    ///
    ///     With a caught exception:
    ///         try
    ///         {
    ///             File.ReadAllText("config.json");
    ///         }
    ///          catch (Exception ex)
    ///         {
    ///             Logger.Log(LogLevel.Error, "Failed to read config file.", ex);
    ///         }
    ///
    ///     The caller's method name, file, and line number are captured automatically by the compiler via [Caller...]
    ///     attributes — you never need to pass them. Caller info only appears in the log when DevMode is enabled in settings.
    /// </summary>
    public static class Logger
    {
        private static readonly string _logDirectory = Path.Combine(Variables.LocalConfig, "logs");
        private static readonly string _sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        private static readonly string _logFilePath = Path.Combine(_logDirectory, "cdl.log");
        private static readonly Lock _lockObject = new();

        private static LogLevel _minLogLevel = LogLevel.Info;
        private static string _logFormat = "json";
        private static int _maxFileSizeMb = 10;
        private static int _maxRetainedFiles = 9;
        private static bool _enableFileLogging = true;
        private static bool _enableCompression;
        private static bool _includeTimestamps = true;
        private static bool _includeThreadId;
        private static string _dateTimeFormat = "UTC";
        private static bool _asyncLogging;
        private static bool _devMode;

        private static readonly string _appVersion = AppInfo.SemanticVersion;
        private static readonly string _environment = GetEnvironmentInfo();

        // Async logging support
        private static readonly Queue<LogEntry> _logQueue = new();
        private static Thread? _logWorkerThread;
        private static bool _workerRunning;

        static Logger()
        {
            if (_asyncLogging)
            {
                StartLogWorker();
            }
        }

        /// <summary>
        ///     Reloads logger configuration from the current settings. Call this after
        ///     the user changes any logging-related settings at runtime.
        /// </summary>
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
            var s = SettingsManager.Settings;
            //Enum.TryParse(s.LogLevel, true, out _minLogLevel);
            if (!Enum.TryParse(s.LogLevel, true, out LogLevel parsedLevel))
            {
                // Fallback if the setting is missing or invalid
                parsedLevel = LogLevel.Info;
                LogDirectly($"Invalid log level in settings: '{s.LogLevel}'. Defaulting to 'Info'.", "WARNING");
            }

            _minLogLevel = parsedLevel;
            _logFormat = s.LogFormat;
            _maxFileSizeMb = s.MaxFileSizeMb > 0 ? s.MaxFileSizeMb : 10;
            _maxRetainedFiles = s.MaxRetainedFiles > 0 ? s.MaxRetainedFiles : 9;
            _enableFileLogging = s.EnableFileLogging;
            _enableCompression = s.EnableCompression;
            _includeTimestamps = s.IncludeTimestamps;
            _includeThreadId = s.IncludeThreadId;
            _dateTimeFormat = s.DateTimeFormat;
            _asyncLogging = s.AsyncLogging;
            _devMode = s.DevMode;

            Log(LogLevel.Debug, $"Logger initialized. Level={_minLogLevel}, Format={_logFormat}, MaxSizeMB={_maxFileSizeMb}, " +
                                $"MaxRetained={_maxRetainedFiles}, FileLogging={_enableFileLogging}, Compression={_enableCompression}, " +
                                $"Timestamps={_includeTimestamps}, ThreadId={_includeThreadId}, DateTimeFormat={_dateTimeFormat}, " +
                                $"Async={_asyncLogging}, DevMode={_devMode}");
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
                    Thread.Sleep(50);
                }
            }
        }

        /// <summary>
        ///     Writes a log entry with the specified level and message.
        ///     Caller information (method, file, line) is captured automatically by the
        ///     compiler when DevMode is enabled — do not pass these manually.
        /// </summary>
        /// <param name="level">The severity level of this entry.</param>
        /// <param name="message">A human-readable description of the event.</param>
        /// <param name="exception">Optional. The caught exception to capture type, message, and stack trace.</param>
        /// <param name="memberName">Autopopulated by the compiler. Do not pass manually.</param>
        /// <param name="filePath">Autopopulated by the compiler. Do not pass manually.</param>
        /// <param name="lineNumber">Autopopulated by the compiler. Do not pass manually.</param>
        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "JSON serialization needed for log entries")]
        public static void Log(
            LogLevel level,
            string message,
            Exception? exception = null,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0)
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
                Level = level.ToString().ToUpperInvariant(),
                Message = message,
                SessionId = _sessionId,
                AppVersion = _appVersion,
                Environment = _environment
            };

            if (_includeTimestamps)
            {
                var now = _dateTimeFormat.Equals("LOCAL", StringComparison.InvariantCultureIgnoreCase)
                    ? DateTime.Now
                    : DateTime.UtcNow;
                logEntry.Timestamp = now.ToString("o");
            }

            if (_includeThreadId)
            {
                logEntry.ThreadId = Environment.CurrentManagedThreadId;
            }

            if (_devMode)
            {
                logEntry.Caller = new CallerInfo { Method = memberName, File = Path.GetFileName(filePath), Line = lineNumber };
            }

            if (exception != null)
            {
                logEntry.Exception = new ExceptionInfo
                {
                    Type = exception.GetType().FullName ?? exception.GetType().Name, Message = exception.Message, StackTrace = exception.StackTrace
                };
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
                if (!Directory.Exists(_logDirectory))
                {
                    Directory.CreateDirectory(_logDirectory);
                }

                RotateLogFileIfNeeded();

                var line = _logFormat.Equals("json", StringComparison.InvariantCultureIgnoreCase)
                    ? JsonConvert.SerializeObject(logEntry, Formatting.None)
                    // Plain text: write session marker on first entry of a new session
                    : FormatPlainText(logEntry);

                lock (_lockObject)
                {
                    // Write session start marker in plain text mode
                    if (!_logFormat.Equals("json", StringComparison.InvariantCultureIgnoreCase)
                        && !File.Exists(_logFilePath))
                    {
                        var separator = new string('=', 60);
                        var header = $"{separator}{Environment.NewLine}"
                                     + $"  SESSION START  {_sessionId}  v{_appVersion}{Environment.NewLine}"
                                     + $"{separator}{Environment.NewLine}";
                        File.AppendAllText(_logFilePath, header);
                    }

                    File.AppendAllText(_logFilePath, line + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                var fallbackPath = Path.Combine(_logDirectory, $"fallback_{_sessionId}.txt");
                File.AppendAllText(fallbackPath,
                    $"[{DateTime.UtcNow:o}] {logEntry.Level}: {logEntry.Message} (Logger error: {ex.Message}){Environment.NewLine}");
            }
        }

        private static string FormatPlainText(LogEntry entry)
        {
            var parts = new List<string>();

            if (_includeTimestamps && entry.Timestamp != null)
            {
                parts.Add($"[{entry.Timestamp}]");
            }

            parts.Add($"[{entry.Level}]");

            if (_includeThreadId && entry.ThreadId.HasValue)
            {
                parts.Add($"[Thread:{entry.ThreadId}]");
            }

            if (entry.Caller != null)
            {
                parts.Add($"[{entry.Caller.File} | {entry.Caller.Method}() | Line {entry.Caller.Line}]");
            }

            parts.Add(entry.Message);

            if (entry.Exception != null)
            {
                parts.Add($"| Exception: {entry.Exception.Type}: {entry.Exception.Message}");
                if (!string.IsNullOrWhiteSpace(entry.Exception.StackTrace))
                {
                    parts.Add($"{Environment.NewLine}{entry.Exception.StackTrace}");
                }
            }

            return string.Join(" ", parts);
        }

        private static void RotateLogFileIfNeeded()
        {
            if (!File.Exists(_logFilePath))
            {
                return;
            }

            var fileInfo = new FileInfo(_logFilePath);
            if (fileInfo.Length < _maxFileSizeMb * 1024L * 1024L)
            {
                return;
            }

            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var rotatedName = Path.Combine(_logDirectory, $"cdl_{timestamp}.log");
            File.Move(_logFilePath, rotatedName);

            if (_enableCompression)
            {
                CompressFile(rotatedName);
            }

            // Delete oldest files beyond the retained limit
            var pattern = _enableCompression ? "cdl_*.log.gz" : "cdl_*.log";
            var logFiles = Directory.GetFiles(_logDirectory, pattern)
                .OrderByDescending(File.GetCreationTimeUtc)
                .ToList();

            for (var i = _maxRetainedFiles; i < logFiles.Count; i++)
            {
                File.Delete(logFiles[i]);
            }
        }

        private static void CompressFile(string filePath)
        {
            var compressedPath = filePath + ".gz";
            using var originalStream = File.OpenRead(filePath);
            using var compressedStream = File.Create(compressedPath);
            using var gzip = new GZipStream(
                compressedStream, CompressionLevel.Optimal);
            originalStream.CopyTo(gzip);
            // Dispose order: gzip must flush before we delete
            gzip.Dispose();
            File.Delete(filePath);
        }

        // Direct write used internally to avoid re-entering the public Log() method
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
                    var now = _dateTimeFormat.Equals("LOCAL", StringComparison.InvariantCultureIgnoreCase)
                        ? DateTime.Now
                        : DateTime.UtcNow;
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
            catch
            {
                Console.WriteLine("An exception occurred while processing log entries.");
            }
        }

        private static string GetEnvironmentInfo()
        {
            var os = RuntimeInformation.OSDescription;
            var arch = RuntimeInformation.ProcessArchitecture;
            return $"{os} ({arch})";
        }

        // -------------------------------------------------------------------------
        // Public helpers
        // -------------------------------------------------------------------------

        /// <summary>Returns the session ID for the current application run.</summary>
        public static string GetCurrentSessionId()
        {
            return _sessionId;
        }

        /// <summary>Returns the full path to the active log file.</summary>
        public static string GetCurrentLogFilePath()
        {
            return _logFilePath;
        }

        // -------------------------------------------------------------------------
        // Runtime config setters — use ReloadConfig() when possible
        // -------------------------------------------------------------------------

        public static void SetDevMode(bool enabled) { _devMode = enabled; }
        public static void SetLogLevel(LogLevel level) { _minLogLevel = level; }
        public static void SetLogFormat(string format) { _logFormat = format; }
        public static void SetMaxFileSizeMb(int mb) { _maxFileSizeMb = mb; }
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

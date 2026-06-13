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

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ColDogStudios.ColDogLocker.Services.Configuration;
using ColDogStudios.ColDogLocker.Core.Environment;
using Newtonsoft.Json;

namespace ColDogStudios.ColDogLocker.Services.Logging
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
    ///     Supports async buffered writing, log rotation, and runtime configuration reloading.
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
        private static readonly string _logDirectory = Path.GetFullPath(Path.Join(Path.GetFullPath(AppPaths.LocalConfig), "logs"));
        private static readonly string _sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        private static readonly string _logFilePath = Path.Combine(_logDirectory, "cdl.log");
        private static readonly Lock _lockObject = new();

        private static LogLevel _minLogLevel = LogLevel.Info;
        private static string _logFormat = "json";
        private static int _maxFileSizeMb = 10;
        private const int MaxRetainedLogFiles = 4;
        private static bool _enableFileLogging = true;
        private static bool _devMode;

        private static readonly string _appVersion = AppInfo.SemanticVersion;
        private static readonly string _environment = GetEnvironmentInfo();

        // Async logging support
        private static readonly Queue<LogEntry> _logQueue = new();
        private static readonly AutoResetEvent _logQueued = new(false);
        private static readonly Lock _workerStateLock = new();
        private static Thread? _logWorkerThread;
        private static bool _workerRunning;

        static Logger()
        {
            AppDomain.CurrentDomain.ProcessExit += (_, _) => StopLogWorker();
            StartLogWorker();
        }

        /// <summary>
        ///     Reloads logger configuration from the current settings. Call this after
        ///     the user changes any logging-related settings at runtime.
        /// </summary>
        public static void ReloadConfig()
        {
            LoadConfigFromSettings();
            if (!_workerRunning)
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
            _enableFileLogging = s.EnableFileLogging;
            _devMode = s.DevMode;

            Log(LogLevel.Debug, $"Logger initialized. Level={_minLogLevel}, Format={_logFormat}, MaxSizeMB={_maxFileSizeMb}, " +
                                $"MaxRetained={MaxRetainedLogFiles}, FileLogging={_enableFileLogging}, TimestampFormat=UtcIso8601, " +
                                $"Async=True, DevMode={_devMode}");
        }

        private static void StartLogWorker()
        {
            lock (_workerStateLock)
            {
                if (_workerRunning)
                {
                    return;
                }

                _workerRunning = true;
                _logWorkerThread = new Thread(LogWorkerLoop) { IsBackground = true };
                _logWorkerThread.Start();
            }
        }

        private static void LogWorkerLoop()
        {
            while (true)
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
                else if (!_workerRunning)
                {
                    break;
                }
                else
                {
                    _logQueued.WaitOne(50);
                }
            }
        }

        private static void StopLogWorker()
        {
            Thread? workerThread;
            lock (_workerStateLock)
            {
                if (!_workerRunning)
                {
                    return;
                }

                _workerRunning = false;
                workerThread = _logWorkerThread;
                _logQueued.Set();
            }

            if (workerThread != null && workerThread != Thread.CurrentThread)
            {
                workerThread.Join(TimeSpan.FromSeconds(2));
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
                Timestamp = DateTime.UtcNow.ToString("o"),
                SessionId = _sessionId,
                AppVersion = _appVersion,
                Environment = _environment
            };

            if (_devMode)
            {
                logEntry.Caller = new CallerInfo { Method = memberName, File = Path.GetFileName(filePath), Line = lineNumber };
                logEntry.ThreadId = Environment.CurrentManagedThreadId;
            }

            if (exception != null)
            {
                logEntry.Exception = new ExceptionInfo
                {
                    Type = exception.GetType().FullName ?? exception.GetType().Name, Message = exception.Message, StackTrace = exception.StackTrace
                };
            }

            lock (_logQueue)
            {
                _logQueue.Enqueue(logEntry);
            }

            _logQueued.Set();
        }

        private static void WriteLogEntry(LogEntry logEntry)
        {
            try
            {
                EnsureLogDirectory();

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
                TryWriteFallbackLog(logEntry, ex);
            }
        }

        private static void EnsureLogDirectory()
        {
            Directory.CreateDirectory(_logDirectory);
        }

        private static void TryWriteFallbackLog(LogEntry logEntry, Exception loggerException)
        {
            try
            {
                EnsureLogDirectory();
                var fallbackFileName = Path.GetFileName($"fallback_{_sessionId}.txt");
                var fallbackPath = Path.Combine(_logDirectory, fallbackFileName);
                File.AppendAllText(fallbackPath,
                    $"[{DateTime.UtcNow:o}] {logEntry.Level}: {logEntry.Message} (Logger error: {loggerException.Message}){Environment.NewLine}");
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"An exception occurred while writing fallback log entries: {ex}");
            }
        }

        private static string FormatPlainText(LogEntry entry)
        {
            var parts = new List<string>();

            if (entry.Timestamp != null)
            {
                parts.Add($"[{entry.Timestamp}]");
            }

            parts.Add($"[{entry.Level}]");

            if (entry.ThreadId.HasValue)
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

            // Delete oldest files beyond the retained limit
            var logFiles = Directory.GetFiles(_logDirectory, "cdl_*.log")
                .OrderByDescending(File.GetCreationTimeUtc)
                .ToList();

            for (var i = MaxRetainedLogFiles; i < logFiles.Count; i++)
            {
                File.Delete(logFiles[i]);
            }
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
                    Timestamp = DateTime.UtcNow.ToString("o"),
                    SessionId = _sessionId,
                    AppVersion = _appVersion,
                    Environment = _environment
                };

                if (_devMode)
                {
                    logEntry.ThreadId = Environment.CurrentManagedThreadId;
                }

                lock (_lockObject)
                {
                    EnsureLogDirectory();
                    var line = _logFormat.Equals("json", StringComparison.InvariantCultureIgnoreCase)
                        ? JsonConvert.SerializeObject(logEntry, Formatting.None)
                        : FormatPlainText(logEntry);
                    File.AppendAllText(_logFilePath, line + Environment.NewLine);
                }
            }
            catch (JsonException ex)
            {
                System.Console.WriteLine($"An exception occurred while processing log entries: {ex}");
            }
            catch (IOException ex)
            {
                System.Console.WriteLine($"An exception occurred while processing log entries: {ex}");
            }
            catch (UnauthorizedAccessException ex)
            {
                System.Console.WriteLine($"An exception occurred while processing log entries: {ex}");
            }
            catch (NotSupportedException ex)
            {
                System.Console.WriteLine($"An exception occurred while processing log entries: {ex}");
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
        public static void SetEnableFileLogging(bool enabled) { _enableFileLogging = enabled; }

        public static void Flush()
        {
            var deadline = DateTime.UtcNow.AddSeconds(2);
            while (DateTime.UtcNow < deadline)
            {
                lock (_logQueue)
                {
                    if (_logQueue.Count == 0)
                    {
                        return;
                    }
                }

                _logQueued.Set();
                Thread.Sleep(20);
            }
        }
    }
}
